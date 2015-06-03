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

#ifndef SYSTEM_KEYMASTER_AES_OPERATION_H_
#define SYSTEM_KEYMASTER_AES_OPERATION_H_

#include <openssl/evp.h>

#include "aead_mode_operation.h"
#include "ocb_utils.h"
#include "operation.h"

namespace keymaster {

static const size_t MAX_EVP_KEY_SIZE = 32;

class AesEvpOperation : public Operation {
  public:
    AesEvpOperation(keymaster_purpose_t purpose, keymaster_block_mode_t block_mode,
                    keymaster_padding_t padding, bool caller_iv, const uint8_t* key,
                    size_t key_size);
    ~AesEvpOperation();

    virtual keymaster_error_t Begin(const AuthorizationSet& input_params,
                                    AuthorizationSet* output_params);
    virtual keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                                     AuthorizationSet* output_params, Buffer* output,
                                     size_t* input_consumed);
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, AuthorizationSet* output_params,
                                     Buffer* output);
    virtual keymaster_error_t Abort();

    virtual int evp_encrypt_mode() = 0;

  private:
    keymaster_error_t InitializeCipher();
    keymaster_error_t GetIv(const AuthorizationSet& input_params);
    keymaster_error_t GenerateIv();
    bool need_iv() const;

    EVP_CIPHER_CTX ctx_;
    const size_t key_size_;
    const keymaster_block_mode_t block_mode_;
    const keymaster_padding_t padding_;
    const bool caller_iv_;
    UniquePtr<uint8_t[]> iv_;
    uint8_t key_[MAX_EVP_KEY_SIZE];
};

class AesEvpEncryptOperation : public AesEvpOperation {
  public:
    AesEvpEncryptOperation(keymaster_block_mode_t block_mode, keymaster_padding_t padding,
                           bool caller_iv, const uint8_t* key, size_t key_size)
        : AesEvpOperation(KM_PURPOSE_ENCRYPT, block_mode, padding, caller_iv, key, key_size) {}
    int evp_encrypt_mode() { return 1; }
};

class AesEvpDecryptOperation : public AesEvpOperation {
  public:
    AesEvpDecryptOperation(keymaster_block_mode_t block_mode, keymaster_padding_t padding,
                           const uint8_t* key, size_t key_size)
        : AesEvpOperation(KM_PURPOSE_DECRYPT, block_mode, padding,
                          false /* caller_iv -- don't care */, key, key_size) {}

    int evp_encrypt_mode() { return 0; }
};

/**
 * Abstract base for AES operation factories.  This class does all of the work to create
 * AES operations.
 */
class AesOperationFactory : public OperationFactory {
  public:
    virtual KeyType registry_key() const { return KeyType(KM_ALGORITHM_AES, purpose()); }

    virtual Operation* CreateOperation(const Key& key, const AuthorizationSet& begin_params,
                                       keymaster_error_t* error);
    virtual const keymaster_block_mode_t* SupportedBlockModes(size_t* block_mode_count) const;
    virtual const keymaster_padding_t* SupportedPaddingModes(size_t* padding_count) const;

    virtual keymaster_purpose_t purpose() const = 0;

  private:
    virtual Operation* CreateEvpOperation(const SymmetricKey& key,
                                          keymaster_block_mode_t block_mode,
                                          keymaster_padding_t padding, bool caller_iv,
                                          keymaster_error_t* error);
};

/**
 * Concrete factory for AES encryption operations.
 */
class AesEncryptionOperationFactory : public AesOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_ENCRYPT; }
};

/**
 * Concrete factory for AES decryption operations.
 */
class AesDecryptionOperationFactory : public AesOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_DECRYPT; }
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_AES_OPERATION_H_
