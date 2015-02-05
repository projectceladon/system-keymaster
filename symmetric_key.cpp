/*
 * Copyright 2014 The Android Open Source Project
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

#include "symmetric_key.h"

#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "aes_key.h"
#include "hmac_key.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

/* static */
SymmetricKey* SymmetricKey::GenerateKey(keymaster_algorithm_t algorithm,
                                        const AuthorizationSet& key_description,
                                        const Logger& logger, keymaster_error_t* error) {
    if (!error)
        return NULL;

    *error = KM_ERROR_OK;

    UniquePtr<SymmetricKey> key;
    switch (algorithm) {
    case KM_ALGORITHM_AES:
        key.reset(new AesKey(key_description, logger));
        break;
    case KM_ALGORITHM_HMAC:
        key.reset(new HmacKey(key_description, logger));
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return NULL;
    };

    uint32_t key_size_bits;
    if (!key_description.GetTagValue(TAG_KEY_SIZE, &key_size_bits) || key_size_bits % 8 != 0) {
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return NULL;
    }

    key->key_data_size_ = key_size_bits / 8;
    if (key->key_data_size_ > MAX_KEY_SIZE) {
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return NULL;
    }
    if (!RAND_bytes(key->key_data_, key->key_data_size_)) {
        logger.error("Error %ul generating %d bit AES key", ERR_get_error(), key_size_bits);
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    if (*error != KM_ERROR_OK)
        return NULL;
    return key.release();
}

/* static */
SymmetricKey* SymmetricKey::CreateKey(keymaster_algorithm_t algorithm,
                                      const UnencryptedKeyBlob& blob, const Logger& logger,
                                      keymaster_error_t* error) {
    switch (algorithm) {
    case KM_ALGORITHM_AES:
        return new AesKey(blob, logger, error);
    case KM_ALGORITHM_HMAC:
        return new HmacKey(blob, logger, error);
    default:
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return NULL;
    }
}

SymmetricKey::SymmetricKey(const UnencryptedKeyBlob& blob, const Logger& logger,
                           keymaster_error_t* error)
    : Key(blob, logger), key_data_size_(blob.unencrypted_key_material_length()) {
    if (error)
        *error = LoadKey(blob);
}

SymmetricKey::~SymmetricKey() {
    memset_s(key_data_, 0, MAX_KEY_SIZE);
}

keymaster_error_t SymmetricKey::LoadKey(const UnencryptedKeyBlob& blob) {
    assert(blob.unencrypted_key_material_length() == key_data_size_);
    memcpy(key_data_, blob.unencrypted_key_material(), key_data_size_);

    return KM_ERROR_OK;
}

keymaster_error_t SymmetricKey::key_material(UniquePtr<uint8_t[]>* key_material,
                                             size_t* size) const {
    *size = key_data_size_;
    key_material->reset(new uint8_t[*size]);
    if (!key_material->get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(key_material->get(), key_data_, *size);
    return KM_ERROR_OK;
}

}  // namespace keymaster
