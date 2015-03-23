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
#include <openssl/err.h>
#include <openssl/rand.h>

#include <keymaster/logger.h>

#include "aes_key.h"
#include "aes_operation.h"
#include "openssl_err.h"

namespace keymaster {

/**
 * Abstract base for AES operation factories.  This class does all of the work to create
 * AES operations.
 */
class AesOperationFactory : public OperationFactory {
  public:
    virtual KeyType registry_key() const { return KeyType(KM_ALGORITHM_AES, purpose()); }

    virtual Operation* CreateOperation(const Key& key, keymaster_error_t* error);
    virtual const keymaster_block_mode_t* SupportedBlockModes(size_t* block_mode_count) const;
    virtual const keymaster_padding_t* SupportedPaddingModes(size_t* padding_count) const;

    virtual keymaster_purpose_t purpose() const = 0;

  private:
    virtual Operation* CreateOcbOperation(const SymmetricKey& key, bool caller_nonce,
                                          keymaster_error_t* error);
    virtual Operation* CreateEvpOperation(const SymmetricKey& key,
                                          keymaster_block_mode_t block_mode,
                                          keymaster_padding_t padding, bool caller_iv,
                                          keymaster_error_t* error);
};

Operation* AesOperationFactory::CreateOperation(const Key& key, keymaster_error_t* error) {
    *error = KM_ERROR_OK;
    const SymmetricKey* symmetric_key = static_cast<const SymmetricKey*>(&key);

    switch (symmetric_key->key_data_size()) {
    case 16:
    case 24:
    case 32:
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return NULL;
    }

    keymaster_block_mode_t block_mode;
    if (!key.authorizations().GetTagValue(TAG_BLOCK_MODE, &block_mode) || !supported(block_mode))
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;

    keymaster_padding_t padding = KM_PAD_NONE;
    key.authorizations().GetTagValue(TAG_PADDING, &padding);

    bool caller_nonce = key.authorizations().GetTagValue(TAG_CALLER_NONCE);

    if (*error != KM_ERROR_OK)
        return NULL;

    switch (block_mode) {
    case KM_MODE_OCB:
        if (padding != KM_PAD_NONE) {
            *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
            return NULL;
        }
        return CreateOcbOperation(*symmetric_key, caller_nonce, error);
    case KM_MODE_ECB:
    case KM_MODE_CBC:
        return CreateEvpOperation(*symmetric_key, block_mode, padding, caller_nonce, error);
    default:
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return NULL;
    }
}

Operation* AesOperationFactory::CreateOcbOperation(const SymmetricKey& key, bool caller_nonce,
                                                   keymaster_error_t* error) {
    *error = KM_ERROR_OK;

    uint32_t chunk_length;
    if (!key.authorizations().GetTagValue(TAG_CHUNK_LENGTH, &chunk_length) ||
        chunk_length > AeadModeOperation::MAX_CHUNK_LENGTH)
        *error = KM_ERROR_UNSUPPORTED_CHUNK_LENGTH;

    uint32_t tag_length;
    if (!key.authorizations().GetTagValue(TAG_MAC_LENGTH, &tag_length) ||
        tag_length > AeadModeOperation::MAX_TAG_LENGTH)
        *error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;

    keymaster_padding_t padding;
    if (key.authorizations().GetTagValue(TAG_PADDING, &padding) && padding != KM_PAD_NONE)
        *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;

    if (*error != KM_ERROR_OK)
        return NULL;

    Operation* op = new AesOcbOperation(purpose(), key.key_data(), key.key_data_size(),
                                        chunk_length, tag_length, caller_nonce);
    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

Operation* AesOperationFactory::CreateEvpOperation(const SymmetricKey& key,
                                                   keymaster_block_mode_t block_mode,
                                                   keymaster_padding_t padding, bool caller_iv,
                                                   keymaster_error_t* error) {
    Operation* op = NULL;
    switch (purpose()) {
    case KM_PURPOSE_ENCRYPT:
        op = new AesEvpEncryptOperation(block_mode, padding, caller_iv, key.key_data(),
                                        key.key_data_size());
        break;
    case KM_PURPOSE_DECRYPT:
        op = new AesEvpDecryptOperation(block_mode, padding, key.key_data(), key.key_data_size());
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_PURPOSE;
        return NULL;
    }

    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

static const keymaster_block_mode_t supported_block_modes[] = {KM_MODE_OCB, KM_MODE_ECB,
                                                               KM_MODE_CBC};

const keymaster_block_mode_t*
AesOperationFactory::SupportedBlockModes(size_t* block_mode_count) const {
    *block_mode_count = array_length(supported_block_modes);
    return supported_block_modes;
}

static const keymaster_padding_t supported_padding_modes[] = {KM_PAD_NONE, KM_PAD_PKCS7};
const keymaster_padding_t*
AesOperationFactory::SupportedPaddingModes(size_t* padding_mode_count) const {
    *padding_mode_count = array_length(supported_padding_modes);
    return supported_padding_modes;
}

/**
 * Concrete factory for AES encryption operations.
 */
class AesEncryptionOperationFactory : public AesOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_ENCRYPT; }
};
static OperationFactoryRegistry::Registration<AesEncryptionOperationFactory> encrypt_registration;

/**
 * Concrete factory for AES decryption operations.
 */
class AesDecryptionOperationFactory : public AesOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_DECRYPT; }
};
static OperationFactoryRegistry::Registration<AesDecryptionOperationFactory> decrypt_registration;

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

AesEvpOperation::AesEvpOperation(keymaster_purpose_t purpose, keymaster_block_mode_t block_mode,
                                 keymaster_padding_t padding, bool caller_iv, const uint8_t* key,
                                 size_t key_size)
    : Operation(purpose), key_size_(key_size), block_mode_(block_mode), padding_(padding),
      caller_iv_(caller_iv) {
    memcpy(key_, key, key_size_);
    EVP_CIPHER_CTX_init(&ctx_);
}

AesEvpOperation::~AesEvpOperation() {
    EVP_CIPHER_CTX_cleanup(&ctx_);
}

keymaster_error_t AesEvpOperation::InitializeCipher() {
    const EVP_CIPHER* cipher;
    switch (block_mode_) {
    case KM_MODE_ECB:
        switch (key_size_) {
        case 16:
            cipher = EVP_aes_128_ecb();
            break;
        case 24:
            cipher = EVP_aes_192_ecb();
            break;
        case 32:
            cipher = EVP_aes_256_ecb();
            break;
        default:
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }
        break;
    case KM_MODE_CBC:
        switch (key_size_) {
        case 16:
            cipher = EVP_aes_128_cbc();
            break;
        case 24:
            cipher = EVP_aes_192_cbc();
            break;
        case 32:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            return KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }
        break;
    default:
        return KM_ERROR_UNSUPPORTED_BLOCK_MODE;
    }

    int init_result =
        EVP_CipherInit_ex(&ctx_, cipher, NULL /* engine */, key_, iv_.get(), evp_encrypt_mode());

    if (!init_result)
        return TranslateLastOpenSslError();

    switch (padding_) {
    case KM_PAD_NONE:
        EVP_CIPHER_CTX_set_padding(&ctx_, 0 /* disable padding */);
        break;
    case KM_PAD_PKCS7:
        // This is the default for OpenSSL EVP cipher operations.
        break;
    default:
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    return KM_ERROR_OK;
}

bool AesEvpOperation::need_iv() const {
    switch (block_mode_) {
    case KM_MODE_CBC:
        return true;
    case KM_MODE_ECB:
        return false;
    default:
        // Shouldn't get here.
        assert(false);
        return false;
    }
}

keymaster_error_t AesEvpOperation::Begin(const AuthorizationSet& input_params,
                                         AuthorizationSet* output_params) {
    if (!output_params)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    keymaster_error_t error = KM_ERROR_OK;
    if (need_iv()) {
        switch (purpose()) {
        case KM_PURPOSE_ENCRYPT:
            if (caller_iv_)
                error = GetIv(input_params);
            else {
                iv_.reset(new uint8_t[AES_BLOCK_SIZE]);
                if (!iv_.get())
                    return KM_ERROR_MEMORY_ALLOCATION_FAILED;
                if (!RAND_bytes(iv_.get(), AES_BLOCK_SIZE))
                    error = TranslateLastOpenSslError();
            }

            if (error == KM_ERROR_OK)
                output_params->push_back(TAG_NONCE, iv_.get(), AES_BLOCK_SIZE);
            break;

        case KM_PURPOSE_DECRYPT:
            error = GetIv(input_params);
            break;
        default:
            return KM_ERROR_UNSUPPORTED_PURPOSE;
        }
    }

    if (error == KM_ERROR_OK)
        error = InitializeCipher();

    return error;
}

keymaster_error_t AesEvpOperation::GetIv(const AuthorizationSet& input_params) {
    keymaster_blob_t iv_blob;
    if (!input_params.GetTagValue(TAG_NONCE, &iv_blob)) {
        LOG_E("No IV provided", 0);
        return KM_ERROR_INVALID_ARGUMENT;
    }
    if (iv_blob.data_length != AES_BLOCK_SIZE) {
        LOG_E("Expected %d-byte IV for AES operation, but got %d bytes", AES_BLOCK_SIZE,
              iv_blob.data_length);
        return KM_ERROR_INVALID_ARGUMENT;
    }
    iv_.reset(dup_array(iv_blob.data, iv_blob.data_length));
    if (!iv_.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return KM_ERROR_OK;
}

inline size_t min(size_t a, size_t b) {
    if (a < b)
        return a;
    return b;
}

keymaster_error_t AesEvpOperation::Update(const AuthorizationSet& /* additional_params */,
                                          const Buffer& input, Buffer* output,
                                          size_t* input_consumed) {
    output->reserve(input.available_read() + AES_BLOCK_SIZE);

    const uint8_t* input_pos = input.peek_read();
    const uint8_t* input_end = input_pos + input.available_read();

    int output_written = -1;
    if (!EVP_CipherUpdate(&ctx_, output->peek_write(), &output_written, input_pos,
                          input_end - input_pos))
        return TranslateLastOpenSslError();

    assert(output_written >= 0);
    assert(output_written <= (int)output->available_write());
    output->advance_write(output_written);
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t AesEvpOperation::Finish(const AuthorizationSet& /* additional_params */,
                                          const Buffer& /* signature */, Buffer* output) {
    output->reserve(AES_BLOCK_SIZE);

    int output_written = -1;
    if (!EVP_CipherFinal_ex(&ctx_, output->peek_write(), &output_written)) {
        LOG_E("Error encrypting final block: %s", ERR_error_string(ERR_peek_last_error(), NULL));
        return TranslateLastOpenSslError();
    }

    assert(output_written <= AES_BLOCK_SIZE);
    output->advance_write(output_written);
    return KM_ERROR_OK;
}

keymaster_error_t AesEvpOperation::Abort() {
    return KM_ERROR_OK;
}

}  // namespace keymaster
