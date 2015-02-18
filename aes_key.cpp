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

#include "aes_key.h"

#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "aes_operation.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

class AesKeyFactory : public SymmetricKeyFactory {
  public:
    keymaster_algorithm_t registry_key() const { return KM_ALGORITHM_AES; }

    virtual Key* LoadKey(const UnencryptedKeyBlob& blob, const Logger& logger,
                         keymaster_error_t* error) {
        return new AesKey(blob, logger, error);
    }

    virtual SymmetricKey* CreateKey(const AuthorizationSet& auths, const Logger& logger) {
        return new AesKey(auths, logger);
    }
};

static KeyFactoryRegistry::Registration<AesKeyFactory> registration;

Operation* AesKey::CreateOperation(keymaster_purpose_t purpose, keymaster_error_t* error) {
    keymaster_block_mode_t block_mode;
    if (!authorizations().GetTagValue(TAG_BLOCK_MODE, &block_mode)) {
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return NULL;
    }

    switch (block_mode) {
    case KM_MODE_OCB:
        return CreateOcbOperation(purpose, error);
    default:
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return NULL;
    }
}

Operation* AesKey::CreateOcbOperation(keymaster_purpose_t purpose, keymaster_error_t* error) {
    *error = KM_ERROR_OK;

    if (key_data_size() != 16 && key_data_size() != 24 && key_data_size() != 32)
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;

    uint32_t chunk_length;
    if (!authorizations().GetTagValue(TAG_CHUNK_LENGTH, &chunk_length))
        // TODO(swillden): Create and use a better return code.
        *error = KM_ERROR_INVALID_ARGUMENT;

    uint32_t tag_length;
    if (!authorizations().GetTagValue(TAG_MAC_LENGTH, &tag_length))
        // TODO(swillden): Create and use a better return code.
        *error = KM_ERROR_INVALID_ARGUMENT;

    keymaster_padding_t padding;
    if (authorizations().GetTagValue(TAG_PADDING, &padding) && padding != KM_PAD_NONE) {
        *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    if (*error != KM_ERROR_OK)
        return NULL;

    keymaster_blob_t additional_data = {0, 0};
    authorizations().GetTagValue(TAG_ASSOCIATED_DATA, &additional_data);

    UniquePtr<Operation> op;
    switch (purpose) {
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
        op.reset(new AesOcbOperation(purpose, logger_, key_data(), key_data_size(), chunk_length,
                                     tag_length, additional_data));
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_PURPOSE;
        return NULL;
    }

    if (!op.get())
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;

    return op.release();
}

}  // namespace keymaster
