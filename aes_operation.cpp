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

#include <UniquePtr.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <keymaster/logger.h>

#include "aes_key.h"
#include "aes_operation.h"
#include "openssl_err.h"

namespace keymaster {

Operation* AesOperationFactory::CreateOperation(const Key& key,
                                                const AuthorizationSet& begin_params,
                                                keymaster_error_t* error) {
    *error = KM_ERROR_OK;
    const SymmetricKey* symmetric_key = static_cast<const SymmetricKey*>(&key);

    switch (symmetric_key->key_data_size()) {
    case 16:
    case 24:
    case 32:
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return nullptr;
    }

    keymaster_block_mode_t block_mode;
    if (!begin_params.GetTagValue(TAG_BLOCK_MODE, &block_mode)) {
        LOG_E("%d block modes specified in begin params", begin_params.GetTagCount(TAG_BLOCK_MODE));
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return nullptr;
    } else if (!supported(block_mode)) {
        LOG_E("Block mode %d not supported", block_mode);
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return nullptr;
    } else if (!key.authorizations().Contains(TAG_BLOCK_MODE, block_mode)) {
        LOG_E("Block mode %d was specified, but not authorized by key", block_mode);
        *error = KM_ERROR_INCOMPATIBLE_BLOCK_MODE;
        return nullptr;
    }

    keymaster_padding_t padding;
    if (!begin_params.GetTagValue(TAG_PADDING, &padding)) {
        LOG_E("%d padding modes specified in begin params", begin_params.GetTagCount(TAG_PADDING));
        *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        return nullptr;
    } else if (!supported(padding)) {
        LOG_E("Padding mode %d not supported", padding);
        *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        return nullptr;
    } else if (!key.authorizations().Contains(TAG_PADDING, padding)) {
        LOG_E("Padding mode %d was specified, but not authorized by key", padding);
        *error = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
        return nullptr;
    }

    bool caller_nonce = key.authorizations().GetTagValue(TAG_CALLER_NONCE);

    if (*error != KM_ERROR_OK)
        return nullptr;

    switch (block_mode) {
    case KM_MODE_ECB:
    case KM_MODE_CBC:
        return CreateEvpOperation(*symmetric_key, block_mode, padding, caller_nonce, error);
    case KM_MODE_CTR:
        if (padding != KM_PAD_NONE) {
            *error = KM_ERROR_INCOMPATIBLE_PADDING_MODE;
            return nullptr;
        }
        return CreateEvpOperation(*symmetric_key, block_mode, padding, caller_nonce, error);
    default:
        *error = KM_ERROR_UNSUPPORTED_BLOCK_MODE;
        return nullptr;
    }
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

static const keymaster_block_mode_t supported_block_modes[] = {KM_MODE_ECB, KM_MODE_CBC,
                                                               KM_MODE_CTR};

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
    case KM_MODE_CTR:
        switch (key_size_) {
        case 16:
            cipher = EVP_aes_128_ctr();
            break;
        case 24:
            cipher = EVP_aes_192_ctr();
            break;
        case 32:
            cipher = EVP_aes_256_ctr();
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
    case KM_MODE_CTR:
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
            if (input_params.find(TAG_NONCE) == -1)
                error = GenerateIv();
            else if (caller_iv_)
                error = GetIv(input_params);
            else
                error = KM_ERROR_CALLER_NONCE_PROHIBITED;

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
        return KM_ERROR_INVALID_NONCE;
    }
    iv_.reset(dup_array(iv_blob.data, iv_blob.data_length));
    if (!iv_.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return KM_ERROR_OK;
}

keymaster_error_t AesEvpOperation::GenerateIv() {
    iv_.reset(new uint8_t[AES_BLOCK_SIZE]);
    if (!iv_.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    if (RAND_bytes(iv_.get(), AES_BLOCK_SIZE) != 1)
        return TranslateLastOpenSslError();
    return KM_ERROR_OK;
}

inline size_t min(size_t a, size_t b) {
    if (a < b)
        return a;
    return b;
}

keymaster_error_t AesEvpOperation::Update(const AuthorizationSet& /* additional_params */,
                                          const Buffer& input,
                                          AuthorizationSet* /* output_params */, Buffer* output,
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
                                          const Buffer& /* signature */,
                                          AuthorizationSet* /* output_params */, Buffer* output) {
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
