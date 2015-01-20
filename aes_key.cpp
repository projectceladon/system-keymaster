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

#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "aes_key.h"
#include "aes_operation.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

AesKey* AesKey::GenerateKey(const AuthorizationSet& key_description, const Logger& logger,
                            keymaster_error_t* error) {
    if (!error)
        return NULL;

    AuthorizationSet authorizations(key_description);
    uint32_t key_size_bits;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size_bits) ||
        !size_is_supported(key_size_bits)) {
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return NULL;
    }

    keymaster_block_mode_t block_mode;
    if (!authorizations.GetTagValue(TAG_BLOCK_MODE, &block_mode) ||
        !block_mode_is_supported(block_mode)) {
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return NULL;
    }

    uint32_t chunk_length = 0;
    if (block_mode >= KM_MODE_FIRST_AUTHENTICATED && block_mode < KM_MODE_FIRST_MAC) {
        // Chunk length is required.
        if (!authorizations.GetTagValue(TAG_CHUNK_LENGTH, &chunk_length) ||
            !chunk_length_is_supported(chunk_length)) {
            // TODO(swillden): Add a better error code for this.
            *error = KM_ERROR_INVALID_INPUT_LENGTH;
            return NULL;
        }
    }

    // Padding is optional
    keymaster_padding_t padding;
    if (authorizations.GetTagValue(TAG_PADDING, &padding) && !padding_is_supported(padding)) {
        *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        return NULL;
    }

    // Verify purpose is compatible with block mode.
    if (!ModeAndPurposesAreCompatible(authorizations, block_mode, logger)) {
        *error = KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
        return NULL;
    }

    // All required tags seem to be present and valid.  Generate the key bits.
    size_t key_data_size = key_size_bits / 8;
    uint8_t key_data[MAX_KEY_SIZE];
    Eraser erase_key_data(key_data, MAX_KEY_SIZE);
    if (!RAND_bytes(key_data, key_data_size)) {
        logger.error("Error %ul generating %d bit AES key", ERR_get_error(), key_size_bits);
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    *error = KM_ERROR_OK;
    return new AesKey(key_data, key_data_size, authorizations, logger);
}

bool AesKey::ModeAndPurposesAreCompatible(const AuthorizationSet& authorizations,
                                          keymaster_block_mode_t block_mode, const Logger& logger) {
    keymaster_purpose_t purpose;
    for (size_t i = 0; authorizations.GetTagValue(TAG_PURPOSE, i, &purpose); ++i) {
        switch (purpose) {
        case KM_PURPOSE_SIGN:
        case KM_PURPOSE_VERIFY:
            if (block_mode < KM_MODE_FIRST_AUTHENTICATED) {
                logger.error("Only MACing or authenticated modes are supported for signing and "
                             "verification purposes.");
                return false;
            }
            break;

        case KM_PURPOSE_ENCRYPT:
        case KM_PURPOSE_DECRYPT:
            if (block_mode >= KM_MODE_FIRST_MAC) {
                logger.error("MACing modes not supported for encryption and decryption purposes.");
                return false;
            }
            break;
        }
    }
    return true;
}

AesKey::AesKey(const uint8_t(&key_data)[MAX_KEY_SIZE], size_t key_data_size,
               AuthorizationSet& auths, const Logger& logger)
    : Key(auths, logger), key_data_size_(key_data_size) {
    memcpy(key_data_, key_data, key_data_size);
}

AesKey::AesKey(const UnencryptedKeyBlob& blob, const Logger& logger, keymaster_error_t* error)
    : Key(blob, logger), key_data_size_(blob.unencrypted_key_material_length()) {
    if (error)
        *error = LoadKey(blob);
}

AesKey::~AesKey() {
    memset_s(key_data_, 0, MAX_KEY_SIZE);
}

keymaster_error_t AesKey::LoadKey(const UnencryptedKeyBlob& blob) {
    assert(blob.unencrypted_key_material_length() == key_data_size_);
    memcpy(key_data_, blob.unencrypted_key_material(), key_data_size_);

    return KM_ERROR_OK;
}

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

    uint32_t chunk_length;
    if (!authorizations().GetTagValue(TAG_CHUNK_LENGTH, &chunk_length))
        // TODO(swillden): Create and use a better return code.
        *error = KM_ERROR_INVALID_INPUT_LENGTH;

    uint32_t tag_length;
    if (!authorizations().GetTagValue(TAG_MAC_LENGTH, &tag_length))
        // TODO(swillden): Create and use a better return code.
        *error = KM_ERROR_INVALID_INPUT_LENGTH;

    if (*error != KM_ERROR_OK)
        return NULL;

    keymaster_blob_t additional_data = {0, 0};
    authorizations().GetTagValue(TAG_ADDITIONAL_DATA, &additional_data);

    Operation* op = NULL;
    switch (purpose) {
    case KM_PURPOSE_ENCRYPT:
        op = new AesOcbEncryptOperation(logger_, key_data_, key_data_size_, chunk_length,
                                        tag_length, additional_data);
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_PURPOSE;
        return NULL;
    }

    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;

    return op;
}

keymaster_error_t AesKey::key_material(UniquePtr<uint8_t[]>* key_material, size_t* size) const {
    *size = key_data_size_;
    key_material->reset(new uint8_t[*size]);
    if (!key_material->get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(key_material->get(), key_data_, *size);
    return KM_ERROR_OK;
}

}  // namespace keymaster
