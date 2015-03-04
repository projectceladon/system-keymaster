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

#ifndef SYSTEM_KEYMASTER_RSA_OPERATION_H_
#define SYSTEM_KEYMASTER_RSA_OPERATION_H_

#include <UniquePtr.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <keymaster/key_blob.h>

#include "operation.h"

namespace keymaster {

/**
 * Base class for all RSA operations.
 *
 * This class provides RSA key management, plus buffering of data for non-digesting modes.
 */
class RsaOperation : public Operation {
  public:
    RsaOperation(keymaster_purpose_t purpose, keymaster_padding_t padding, RSA* key)
        : Operation(purpose), rsa_key_(key), padding_(padding) {}
    ~RsaOperation();

    virtual keymaster_error_t Begin(const AuthorizationSet& /* input_params */,
                                    AuthorizationSet* /* output_params */) {
        return KM_ERROR_OK;
    }
    virtual keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                                     Buffer* output, size_t* input_consumed);
    virtual keymaster_error_t Abort() { return KM_ERROR_OK; }

  protected:
    keymaster_error_t StoreData(const Buffer& input, size_t* input_consumed);

    RSA* rsa_key_;
    keymaster_padding_t padding_;
    Buffer data_;
};

/**
 * Base class for all RSA operations.
 *
 * This class adds digesting support, for digesting modes.  For non-digesting modes, it falls back
 * on the RsaOperation input buffering.
 */
class RsaDigestingOperation : public RsaOperation {
  public:
    RsaDigestingOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                          keymaster_padding_t padding, RSA* key);
    ~RsaDigestingOperation();

    virtual keymaster_error_t Begin(const AuthorizationSet& input_params,
                                    AuthorizationSet* output_params);
    virtual keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                                     Buffer* output, size_t* input_consumed);

  protected:
    uint8_t* FinishDigest(unsigned* digest_size);

    const keymaster_digest_t digest_;
    const EVP_MD* digest_algorithm_;
    EVP_MD_CTX digest_ctx_;
};

/**
 * RSA private key signing operation.
 */
class RsaSignOperation : public RsaDigestingOperation {
  public:
    RsaSignOperation(keymaster_digest_t digest, keymaster_padding_t padding, RSA* key)
        : RsaDigestingOperation(KM_PURPOSE_SIGN, digest, padding, key) {}
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);

  private:
    int SignUndigested(Buffer* output);
    int SignDigested(Buffer* output);
};

/**
 * RSA public key verification operation.
 */
class RsaVerifyOperation : public RsaDigestingOperation {
  public:
    RsaVerifyOperation(keymaster_digest_t digest, keymaster_padding_t padding, RSA* key)
        : RsaDigestingOperation(KM_PURPOSE_VERIFY, digest, padding, key) {}
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);

  private:
    keymaster_error_t VerifyUndigested(uint8_t* decrypted_data);
    keymaster_error_t VerifyDigested(uint8_t* decrypted_data);
};

/**
 * RSA public key encryption operation.
 */
class RsaEncryptOperation : public RsaOperation {
  public:
    RsaEncryptOperation(keymaster_padding_t padding, RSA* key)
        : RsaOperation(KM_PURPOSE_ENCRYPT, padding, key) {}
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);
};

/**
 * RSA private key decryption operation.
 */
class RsaDecryptOperation : public RsaOperation {
  public:
    RsaDecryptOperation(keymaster_padding_t padding, RSA* key)
        : RsaOperation(KM_PURPOSE_DECRYPT, padding, key) {}
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_RSA_OPERATION_H_
