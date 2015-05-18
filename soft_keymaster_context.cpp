/*
 * Copyright 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "soft_keymaster_context.h"

#include <time.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/logger.h>

#include "aes_key.h"
#include "auth_encrypted_key_blob.h"
#include "ec_key.h"
#include "hmac_key.h"
#include "ocb_utils.h"
#include "openssl_err.h"
#include "rsa_key.h"

namespace keymaster {

namespace {
static uint8_t master_key_bytes[AES_BLOCK_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
const int NONCE_LENGTH = 12;
const int TAG_LENGTH = 16;
const KeymasterKeyBlob MASTER_KEY(master_key_bytes, array_length(master_key_bytes));
}  // anonymous namespace

class SoftKeymasterKeyRegistrations {
  public:
    SoftKeymasterKeyRegistrations(const KeymasterContext* context)
        : rsa_(context), ec_(context), hmac_(context), aes_(context) {}

    KeyFactoryRegistry::Registration<RsaKeyFactory> rsa_;
    KeyFactoryRegistry::Registration<EcdsaKeyFactory> ec_;
    KeyFactoryRegistry::Registration<HmacKeyFactory> hmac_;
    KeyFactoryRegistry::Registration<AesKeyFactory> aes_;
};

SoftKeymasterContext::SoftKeymasterContext()
    : registrations_(new SoftKeymasterKeyRegistrations(this)) {
}

static keymaster_error_t TranslateAuthorizationSetError(AuthorizationSet::Error err) {
    switch (err) {
    case AuthorizationSet::OK:
        return KM_ERROR_OK;
    case AuthorizationSet::ALLOCATION_FAILURE:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    case AuthorizationSet::MALFORMED_DATA:
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t BuildHiddenAuthorizations(const AuthorizationSet& input_set,
                                                   AuthorizationSet* hidden) {
    keymaster_blob_t entry;
    if (input_set.GetTagValue(TAG_APPLICATION_ID, &entry))
        hidden->push_back(TAG_APPLICATION_ID, entry.data, entry.data_length);
    if (input_set.GetTagValue(TAG_APPLICATION_DATA, &entry))
        hidden->push_back(TAG_APPLICATION_DATA, entry.data, entry.data_length);

    keymaster_key_param_t root_of_trust;
    root_of_trust.tag = KM_TAG_ROOT_OF_TRUST;
    root_of_trust.blob.data = reinterpret_cast<const uint8_t*>("SW");
    root_of_trust.blob.data_length = 2;
    hidden->push_back(root_of_trust);

    return TranslateAuthorizationSetError(hidden->is_valid());
}

static keymaster_error_t SetAuthorizations(const AuthorizationSet& key_description,
                                           keymaster_key_origin_t origin,
                                           AuthorizationSet* hw_enforced,
                                           AuthorizationSet* sw_enforced) {
    hw_enforced->Clear();
    sw_enforced->Clear();
    for (size_t i = 0; i < key_description.size(); ++i) {
        switch (key_description[i].tag) {
        // These cannot be specified by the client.
        case KM_TAG_ROOT_OF_TRUST:
        case KM_TAG_ORIGIN:
            LOG_E("Root of trust and origin tags may not be specified", 0);
            return KM_ERROR_INVALID_TAG;

        // These don't work.
        case KM_TAG_ROLLBACK_RESISTANT:
            LOG_E("KM_TAG_ROLLBACK_RESISTANT not supported", 0);
            return KM_ERROR_UNSUPPORTED_TAG;

        // These are hidden.
        case KM_TAG_APPLICATION_ID:
        case KM_TAG_APPLICATION_DATA:
            break;

        // Everything else we just copy into sw_enforced.
        default:
            sw_enforced->push_back(key_description[i]);
            break;
        }
    }

    sw_enforced->push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));
    sw_enforced->push_back(TAG_ORIGIN, origin);
    return TranslateAuthorizationSetError(sw_enforced->is_valid());
}

keymaster_error_t SoftKeymasterContext::CreateKeyBlob(const AuthorizationSet& key_description,
                                                      const keymaster_key_origin_t origin,
                                                      const KeymasterKeyBlob& key_material,
                                                      KeymasterKeyBlob* blob,
                                                      AuthorizationSet* hw_enforced,
                                                      AuthorizationSet* sw_enforced) const {

    keymaster_error_t error;

    error = SetAuthorizations(key_description, origin, hw_enforced, sw_enforced);
    if (error != KM_ERROR_OK)
        return error;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(key_description, &hidden);
    if (error != KM_ERROR_OK)
        return error;

    Buffer nonce, tag;
    if (!nonce.reserve(OCB_NONCE_LENGTH) || !tag.reserve(OCB_TAG_LENGTH))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    GenerateRandom(nonce.peek_write(), OCB_NONCE_LENGTH);
    nonce.advance_write(OCB_NONCE_LENGTH);

    KeymasterKeyBlob encrypted_key;
    error = OcbEncryptKey(*hw_enforced, *sw_enforced, hidden, MASTER_KEY, key_material, nonce,
                          &encrypted_key, &tag);
    if (error != KM_ERROR_OK)
        return error;

    return SerializeAuthEncryptedBlob(encrypted_key, *hw_enforced, *sw_enforced, nonce, tag, blob);
}

keymaster_error_t SoftKeymasterContext::ParseKeyBlob(const KeymasterKeyBlob& blob,
                                                     const AuthorizationSet& additional_params,
                                                     KeymasterKeyBlob* key_material,
                                                     AuthorizationSet* hw_enforced,
                                                     AuthorizationSet* sw_enforced) const {
    Buffer nonce, tag;
    KeymasterKeyBlob encrypted_key_material;
    keymaster_error_t error = DeserializeAuthEncryptedBlob(blob, &encrypted_key_material,
                                                           hw_enforced, sw_enforced, &nonce, &tag);
    if (error != KM_ERROR_OK)
        return error;

    AuthorizationSet hidden;
    error = BuildHiddenAuthorizations(additional_params, &hidden);
    if (error != KM_ERROR_OK)
        return error;

    if (nonce.available_read() != OCB_NONCE_LENGTH || tag.available_read() != OCB_TAG_LENGTH)
        return KM_ERROR_INVALID_KEY_BLOB;

    return OcbDecryptKey(*hw_enforced, *sw_enforced, hidden, MASTER_KEY, encrypted_key_material,
                         nonce, tag, key_material);
}

keymaster_error_t SoftKeymasterContext::AddRngEntropy(const uint8_t* buf, size_t length) const {
    RAND_add(buf, length, 0 /* Don't assume any entropy is added to the pool. */);
    return KM_ERROR_OK;
}

keymaster_error_t SoftKeymasterContext::GenerateRandom(uint8_t* buf, size_t length) const {
    if (RAND_bytes(buf, length) != 1)
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

}  // namespace keymaster
