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

#include <stdio.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include <keymaster/logger.h>

#include "aes_key.h"
#include "aes_operation.h"

namespace keymaster {

/**
 * Abstract base for AES OCB mode operation factories.  This class does all of the work to create
 * OCB mode operations.
 */
class AesOcbOperationFactory : public OperationFactory {
  public:
    virtual KeyType registry_key() const { return KeyType(KM_ALGORITHM_AES, purpose()); }

    virtual Operation* CreateOperation(const Key& key, keymaster_error_t* error);
    virtual const keymaster_block_mode_t* SupportedBlockModes(size_t* block_mode_count) const;

    virtual keymaster_purpose_t purpose() const = 0;
};

Operation* AesOcbOperationFactory::CreateOperation(const Key& key, keymaster_error_t* error) {
    *error = KM_ERROR_OK;

    keymaster_block_mode_t block_mode;
    if (!key.authorizations().GetTagValue(TAG_BLOCK_MODE, &block_mode) ||
        block_mode != KM_MODE_OCB) {
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return NULL;
    }

    uint32_t chunk_length;
    if (!key.authorizations().GetTagValue(TAG_CHUNK_LENGTH, &chunk_length) ||
        chunk_length > AeadModeOperation::MAX_CHUNK_LENGTH)
        // TODO(swillden): Create and use a better return code.
        *error = KM_ERROR_INVALID_ARGUMENT;

    uint32_t tag_length;
    if (!key.authorizations().GetTagValue(TAG_MAC_LENGTH, &tag_length) ||
        tag_length > AeadModeOperation::MAX_TAG_LENGTH)
        // TODO(swillden): Create and use a better return code.
        *error = KM_ERROR_INVALID_ARGUMENT;

    keymaster_padding_t padding;
    if (key.authorizations().GetTagValue(TAG_PADDING, &padding) && padding != KM_PAD_NONE)
        *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;

    const SymmetricKey* symmetric_key = static_cast<const SymmetricKey*>(&key);
    if (!symmetric_key) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    switch (symmetric_key->key_data_size()) {
    case 16:
    case 24:
    case 32:
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }

    if (*error != KM_ERROR_OK)
        return NULL;

    keymaster_blob_t additional_data = {0, 0};
    symmetric_key->authorizations().GetTagValue(TAG_ASSOCIATED_DATA, &additional_data);

    Operation* op =
        new AesOcbOperation(purpose(), symmetric_key->key_data(), symmetric_key->key_data_size(),
                            chunk_length, tag_length, additional_data);
    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

static const keymaster_block_mode_t supported_block_modes[] = {KM_MODE_OCB};

const keymaster_block_mode_t*
AesOcbOperationFactory::SupportedBlockModes(size_t* block_mode_count) const {
    *block_mode_count = array_length(supported_block_modes);
    return supported_block_modes;
}

/**
 * Concrete factory for AES OCB mode encryption operations.
 */
class AesOcbEncryptionOperationFactory : public AesOcbOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_ENCRYPT; }
};
static OperationFactoryRegistry::Registration<AesOcbEncryptionOperationFactory>
    encrypt_registration;

/**
 * Concrete factory for AES OCB mode decryption operations.
 */
class AesOcbDecryptionOperationFactory : public AesOcbOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_DECRYPT; }
};
static OperationFactoryRegistry::Registration<AesOcbDecryptionOperationFactory>
    decrypt_registration;

keymaster_error_t AesOcbOperation::Initialize(uint8_t* key, size_t key_size, size_t nonce_length,
                                              size_t tag_length) {
    if (tag_length > MAX_TAG_LENGTH || nonce_length > MAX_NONCE_LENGTH)
        return KM_ERROR_INVALID_KEY_BLOB;

    if (ae_init(ctx(), key, key_size, nonce_length, tag_length) != AE_SUCCESS) {
        memset_s(ctx(), 0, ae_ctx_sizeof());
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t AesOcbOperation::EncryptChunk(const uint8_t* nonce, size_t /* nonce_length */,
                                                size_t tag_length,
                                                const keymaster_blob_t additional_data,
                                                uint8_t* chunk, size_t chunk_size, Buffer* output) {
    if (!ctx())
        return KM_ERROR_UNKNOWN_ERROR;
    uint8_t __attribute__((aligned(16))) tag[MAX_TAG_LENGTH];

    // Encrypt chunk in place.
    int ae_err = ae_encrypt(ctx(), nonce, chunk, chunk_size, additional_data.data,
                            additional_data.data_length, chunk, tag, AE_FINALIZE);

    if (ae_err < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(ae_err == (int)buffered_data_length());

    output->write(chunk, buffered_data_length());
    output->write(tag, tag_length);

    return KM_ERROR_OK;
}

keymaster_error_t AesOcbOperation::DecryptChunk(const uint8_t* nonce, size_t /* nonce_length */,
                                                const uint8_t* tag, size_t /* tag_length */,
                                                const keymaster_blob_t additional_data,
                                                uint8_t* chunk, size_t chunk_size, Buffer* output) {
    if (!ctx())
        return KM_ERROR_UNKNOWN_ERROR;

    // Decrypt chunk in place
    int ae_err = ae_decrypt(ctx(), nonce, chunk, chunk_size, additional_data.data,
                            additional_data.data_length, chunk, tag, AE_FINALIZE);
    if (ae_err == AE_INVALID)
        return KM_ERROR_VERIFICATION_FAILED;
    else if (ae_err < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(ae_err == (int)buffered_data_length());
    output->write(chunk, chunk_size);

    return KM_ERROR_OK;
}

}  // namespace keymaster
