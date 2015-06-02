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

    keymaster_error_t Begin(const AuthorizationSet& /* input_params */,
                            AuthorizationSet* /* output_params */) override {
        return KM_ERROR_OK;
    }
    keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                             Buffer* output, size_t* input_consumed) override;
    keymaster_error_t Abort() override { return KM_ERROR_OK; }

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

    keymaster_error_t Begin(const AuthorizationSet& input_params,
                            AuthorizationSet* output_params) override;
    keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                             Buffer* output, size_t* input_consumed) override;

  protected:
    bool require_digest() const { return padding_ == KM_PAD_RSA_PSS; }
    keymaster_error_t InitDigest();
    keymaster_error_t UpdateDigest(const Buffer& input, size_t* input_consumed);
    keymaster_error_t FinishDigest(unsigned* digest_size);

    const keymaster_digest_t digest_;
    const EVP_MD* digest_algorithm_;
    EVP_MD_CTX digest_ctx_;
    uint8_t digest_buf_[EVP_MAX_MD_SIZE];
};

/**
 * RSA private key signing operation.
 */
class RsaSignOperation : public RsaDigestingOperation {
  public:
    RsaSignOperation(keymaster_digest_t digest, keymaster_padding_t padding, RSA* key)
        : RsaDigestingOperation(KM_PURPOSE_SIGN, digest, padding, key) {}
    keymaster_error_t Finish(const AuthorizationSet& additional_params, const Buffer& signature,
                             Buffer* output) override;

  private:
    keymaster_error_t SignUndigested(Buffer* output);
    keymaster_error_t SignDigested(Buffer* output);
    keymaster_error_t PrivateEncrypt(uint8_t* to_encrypt, size_t len, int openssl_padding,
                                     Buffer* output);
    keymaster_error_t PssPadDigest(UniquePtr<uint8_t[]>* padded_digest);
};

/**
 * RSA public key verification operation.
 */
class RsaVerifyOperation : public RsaDigestingOperation {
  public:
    RsaVerifyOperation(keymaster_digest_t digest, keymaster_padding_t padding, RSA* key)
        : RsaDigestingOperation(KM_PURPOSE_VERIFY, digest, padding, key) {}
    keymaster_error_t Finish(const AuthorizationSet& additional_params, const Buffer& signature,
                             Buffer* output) override;

  private:
    keymaster_error_t VerifyUndigested(const Buffer& signature);
    keymaster_error_t VerifyDigested(const Buffer& signature);
    keymaster_error_t DecryptAndMatch(const Buffer& signature, const uint8_t* to_match, size_t len);
};

/**
 * RSA public key encryption operation.
 */
class RsaEncryptOperation : public RsaOperation {
  public:
    RsaEncryptOperation(keymaster_padding_t padding, RSA* key)
        : RsaOperation(KM_PURPOSE_ENCRYPT, padding, key) {}
    keymaster_error_t Finish(const AuthorizationSet& additional_params, const Buffer& signature,
                             Buffer* output) override;
};

/**
 * RSA private key decryption operation.
 */
class RsaDecryptOperation : public RsaOperation {
  public:
    RsaDecryptOperation(keymaster_padding_t padding, RSA* key)
        : RsaOperation(KM_PURPOSE_DECRYPT, padding, key) {}
    keymaster_error_t Finish(const AuthorizationSet& additional_params, const Buffer& signature,
                             Buffer* output) override;
};

/**
 * Abstract base for all RSA operation factories.  This class exists mainly to centralize some code
 * common to all RSA operation factories.
 */
class RsaOperationFactory : public OperationFactory {
  public:
    KeyType registry_key() const override { return KeyType(KM_ALGORITHM_RSA, purpose()); }
    virtual keymaster_purpose_t purpose() const = 0;

  protected:
    bool GetAndValidatePadding(const AuthorizationSet& begin_params, const Key& key,
                               keymaster_padding_t* padding, keymaster_error_t* error) const;
    bool GetAndValidateDigest(const AuthorizationSet& begin_params, const Key& key,
                              keymaster_digest_t* digest, keymaster_error_t* error) const;
    static RSA* GetRsaKey(const Key& key, keymaster_error_t* error);
};

/**
 * Abstract base for RSA operations that digest their input (signing and verification).  This class
 * does most of the work of creation of RSA digesting operations, delegating only the actual
 * operation instantiation.
 */
class RsaDigestingOperationFactory : public RsaOperationFactory {
  public:
    virtual Operation* CreateOperation(const Key& key, const AuthorizationSet& begin_params,
                                       keymaster_error_t* error);
    const keymaster_digest_t* SupportedDigests(size_t* digest_count) const override;
    const keymaster_padding_t* SupportedPaddingModes(size_t* padding_mode_count) const override;

  private:
    virtual Operation* InstantiateOperation(keymaster_digest_t digest, keymaster_padding_t padding,
                                            RSA* key) = 0;
};

/**
 * Abstract base for en/de-crypting RSA operation factories.  This class does most of the work of
 * creating such operations, delegating only the actual operation instantiation.
 */
class RsaCryptingOperationFactory : public RsaOperationFactory {
  public:
    virtual Operation* CreateOperation(const Key& key, const AuthorizationSet& begin_params,
                                       keymaster_error_t* error);
    const keymaster_padding_t* SupportedPaddingModes(size_t* padding_mode_count) const override;
    const keymaster_digest_t* SupportedDigests(size_t* digest_count) const override;

  private:
    virtual Operation* InstantiateOperation(keymaster_padding_t padding, RSA* key) = 0;
};

/**
 * Concrete factory for RSA signing operations.
 */
class RsaSigningOperationFactory : public RsaDigestingOperationFactory {
  public:
    keymaster_purpose_t purpose() const override { return KM_PURPOSE_SIGN; }
    Operation* InstantiateOperation(keymaster_digest_t digest, keymaster_padding_t padding,
                                    RSA* key) override {
        return new RsaSignOperation(digest, padding, key);
    }
};

/**
 * Concrete factory for RSA signing operations.
 */
class RsaVerificationOperationFactory : public RsaDigestingOperationFactory {
    keymaster_purpose_t purpose() const override { return KM_PURPOSE_VERIFY; }
    Operation* InstantiateOperation(keymaster_digest_t digest, keymaster_padding_t padding,
                                    RSA* key) override {
        return new RsaVerifyOperation(digest, padding, key);
    }
};

/**
 * Concrete factory for RSA signing operations.
 */
class RsaEncryptionOperationFactory : public RsaCryptingOperationFactory {
    keymaster_purpose_t purpose() const override { return KM_PURPOSE_ENCRYPT; }
    Operation* InstantiateOperation(keymaster_padding_t padding, RSA* key) override {
        return new RsaEncryptOperation(padding, key);
    }
};

/**
 * Concrete factory for RSA signing operations.
 */
class RsaDecryptionOperationFactory : public RsaCryptingOperationFactory {
    keymaster_purpose_t purpose() const override { return KM_PURPOSE_DECRYPT; }
    Operation* InstantiateOperation(keymaster_padding_t padding, RSA* key) override {
        return new RsaDecryptOperation(padding, key);
    }
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_RSA_OPERATION_H_
