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

#include "rsa_operation.h"

#include <limits.h>

#include <openssl/err.h>

#include <keymaster/logger.h>

#include "openssl_err.h"
#include "openssl_utils.h"
#include "rsa_key.h"

namespace keymaster {

static const int MIN_PSS_SALT_LEN = 8 /* salt len */ + 2 /* overhead */;

/**
 * Abstract base for all RSA operation factories.  This class exists mainly to centralize some code
 * common to all RSA operation factories.
 */
class RsaOperationFactory : public OperationFactory {
  public:
    KeyType registry_key() const override { return KeyType(KM_ALGORITHM_RSA, purpose()); }
    virtual keymaster_purpose_t purpose() const = 0;

  protected:
    bool GetAndValidatePadding(const Key& key, keymaster_padding_t* padding,
                               keymaster_error_t* error) const;
    bool GetAndValidateDigest(const AuthorizationSet& begin_params, const Key& key,
                              keymaster_digest_t* digest, keymaster_error_t* error) const;
    static RSA* GetRsaKey(const Key& key, keymaster_error_t* error);
};

bool RsaOperationFactory::GetAndValidatePadding(const Key& key, keymaster_padding_t* padding,
                                                keymaster_error_t* error) const {
    *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
    if (!key.authorizations().GetTagValue(TAG_PADDING, padding) &&
        !key.authorizations().GetTagValue(TAG_PADDING_OLD, padding))
        return false;

    if (!supported(*padding))
        return false;

    *error = KM_ERROR_OK;
    return true;
}

bool RsaOperationFactory::GetAndValidateDigest(const AuthorizationSet& begin_params, const Key& key,
                                               keymaster_digest_t* digest,
                                               keymaster_error_t* error) const {
    *error = KM_ERROR_UNSUPPORTED_DIGEST;
    if (!begin_params.GetTagValue(TAG_DIGEST, digest)) {
        LOG_E("%d digests specified in begin params", begin_params.GetTagCount(TAG_DIGEST));
        return false;
    } else if (!supported(*digest)) {
        LOG_E("Digest %d not supported", *digest);
        return false;
    } else if (!key.authorizations().Contains(TAG_DIGEST, *digest) &&
               !key.authorizations().Contains(TAG_DIGEST_OLD, *digest)) {
        LOG_E("Digest %d was specified, but not authorized by key", *digest);
        *error = KM_ERROR_INCOMPATIBLE_DIGEST;
        return false;
    }
    *error = KM_ERROR_OK;
    return true;
}

/* static */
RSA* RsaOperationFactory::GetRsaKey(const Key& key, keymaster_error_t* error) {
    const RsaKey* rsa_key = static_cast<const RsaKey*>(&key);
    assert(rsa_key);
    if (!rsa_key || !rsa_key->key()) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }
    RSA_up_ref(rsa_key->key());
    return rsa_key->key();
}

static const keymaster_digest_t supported_digests[] = {KM_DIGEST_NONE, KM_DIGEST_SHA_2_256};
static const keymaster_padding_t supported_sig_padding[] = {KM_PAD_NONE, KM_PAD_RSA_PKCS1_1_5_SIGN,
                                                            KM_PAD_RSA_PSS};

/**
 * Abstract base for RSA operations that digest their input (signing and verification).  This class
 * does most of the work of creation of RSA digesting operations, delegating only the actual
 * operation instantiation.
 */
class RsaDigestingOperationFactory : public RsaOperationFactory {
  public:
    virtual Operation* CreateOperation(const Key& key, const AuthorizationSet& begin_params,
                                       keymaster_error_t* error);

    virtual const keymaster_digest_t* SupportedDigests(size_t* digest_count) const {
        *digest_count = array_length(supported_digests);
        return supported_digests;
    }

    virtual const keymaster_padding_t* SupportedPaddingModes(size_t* padding_mode_count) const {
        *padding_mode_count = array_length(supported_sig_padding);
        return supported_sig_padding;
    }

  private:
    virtual Operation* InstantiateOperation(keymaster_digest_t digest, keymaster_padding_t padding,
                                            RSA* key) = 0;
};

Operation* RsaDigestingOperationFactory::CreateOperation(const Key& key,
                                                         const AuthorizationSet& begin_params,
                                                         keymaster_error_t* error) {
    keymaster_padding_t padding;
    keymaster_digest_t digest;
    RSA* rsa;
    if (!GetAndValidateDigest(begin_params, key, &digest, error) ||
        !GetAndValidatePadding(key, &padding, error) || !(rsa = GetRsaKey(key, error)))
        return NULL;

    Operation* op = InstantiateOperation(digest, padding, rsa);
    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

static const keymaster_padding_t supported_crypt_padding[] = {KM_PAD_RSA_OAEP,
                                                              KM_PAD_RSA_PKCS1_1_5_ENCRYPT};

/**
 * Abstract base for en/de-crypting RSA operation factories.  This class does most of the work of
 * creating such operations, delegating only the actual operation instantiation.
 */
class RsaCryptingOperationFactory : public RsaOperationFactory {
  public:
    virtual Operation* CreateOperation(const Key& key, const AuthorizationSet& begin_params,
                                       keymaster_error_t* error);

    virtual const keymaster_padding_t* SupportedPaddingModes(size_t* padding_mode_count) const {
        *padding_mode_count = array_length(supported_crypt_padding);
        return supported_crypt_padding;
    }

    virtual const keymaster_digest_t* SupportedDigests(size_t* digest_count) const {
        *digest_count = 0;
        return NULL;
    }

  private:
    virtual Operation* InstantiateOperation(keymaster_padding_t padding, RSA* key) = 0;
};

Operation* RsaCryptingOperationFactory::CreateOperation(const Key& key,
                                                        const AuthorizationSet& /* begin_params */,
                                                        keymaster_error_t* error) {
    keymaster_padding_t padding;
    RSA* rsa;
    if (!GetAndValidatePadding(key, &padding, error) || !(rsa = GetRsaKey(key, error)))
        return NULL;

    Operation* op = InstantiateOperation(padding, rsa);
    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

/**
 * Concrete factory for RSA signing operations.
 */
class RsaSigningOperationFactory : public RsaDigestingOperationFactory {
  public:
    virtual keymaster_purpose_t purpose() const { return KM_PURPOSE_SIGN; }
    virtual Operation* InstantiateOperation(keymaster_digest_t digest, keymaster_padding_t padding,
                                            RSA* key) {
        return new RsaSignOperation(digest, padding, key);
    }
};
static OperationFactoryRegistry::Registration<RsaSigningOperationFactory> sign_registration;

/**
 * Concrete factory for RSA signing operations.
 */
class RsaVerificationOperationFactory : public RsaDigestingOperationFactory {
    virtual keymaster_purpose_t purpose() const { return KM_PURPOSE_VERIFY; }
    virtual Operation* InstantiateOperation(keymaster_digest_t digest, keymaster_padding_t padding,
                                            RSA* key) {
        return new RsaVerifyOperation(digest, padding, key);
    }
};
static OperationFactoryRegistry::Registration<RsaVerificationOperationFactory> verify_registration;

/**
 * Concrete factory for RSA signing operations.
 */
class RsaEncryptionOperationFactory : public RsaCryptingOperationFactory {
    virtual keymaster_purpose_t purpose() const { return KM_PURPOSE_ENCRYPT; }
    virtual Operation* InstantiateOperation(keymaster_padding_t padding, RSA* key) {
        return new RsaEncryptOperation(padding, key);
    }
};
static OperationFactoryRegistry::Registration<RsaEncryptionOperationFactory> encrypt_registration;

/**
 * Concrete factory for RSA signing operations.
 */
class RsaDecryptionOperationFactory : public RsaCryptingOperationFactory {
    virtual keymaster_purpose_t purpose() const { return KM_PURPOSE_DECRYPT; }
    virtual Operation* InstantiateOperation(keymaster_padding_t padding, RSA* key) {
        return new RsaDecryptOperation(padding, key);
    }
};

static OperationFactoryRegistry::Registration<RsaDecryptionOperationFactory> decrypt_registration;

struct RSA_Delete {
    void operator()(RSA* p) const { RSA_free(p); }
};

RsaOperation::~RsaOperation() {
    if (rsa_key_ != NULL)
        RSA_free(rsa_key_);
}

keymaster_error_t RsaOperation::Update(const AuthorizationSet& /* additional_params */,
                                       const Buffer& input, Buffer* /* output */,
                                       size_t* input_consumed) {
    assert(input_consumed);
    switch (purpose()) {
    default:
        return KM_ERROR_UNIMPLEMENTED;
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
        return StoreData(input, input_consumed);
    }
}

keymaster_error_t RsaOperation::StoreData(const Buffer& input, size_t* input_consumed) {
    assert(input_consumed);
    if (!data_.reserve(data_.available_read() + input.available_read()) ||
        !data_.write(input.peek_read(), input.available_read()))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

RsaDigestingOperation::RsaDigestingOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                                             keymaster_padding_t padding, RSA* key)
    : RsaOperation(purpose, padding, key), digest_(digest), digest_algorithm_(NULL) {
    EVP_MD_CTX_init(&digest_ctx_);
}
RsaDigestingOperation::~RsaDigestingOperation() {
    EVP_MD_CTX_cleanup(&digest_ctx_);
    memset_s(digest_buf_, 0, sizeof(digest_buf_));
}

keymaster_error_t RsaDigestingOperation::Begin(const AuthorizationSet& /* input_params */,
                                               AuthorizationSet* /* output_params */) {
    if (require_digest() && digest_ == KM_DIGEST_NONE)
        return KM_ERROR_INCOMPATIBLE_DIGEST;
    return InitDigest();
}

keymaster_error_t RsaDigestingOperation::Update(const AuthorizationSet& additional_params,
                                                const Buffer& input, Buffer* output,
                                                size_t* input_consumed) {
    if (digest_ == KM_DIGEST_NONE)
        return RsaOperation::Update(additional_params, input, output, input_consumed);
    else
        return UpdateDigest(input, input_consumed);
}

keymaster_error_t RsaDigestingOperation::InitDigest() {
    switch (digest_) {
    case KM_DIGEST_NONE:
        return KM_ERROR_OK;
    case KM_DIGEST_SHA_2_256:
        digest_algorithm_ = EVP_sha256();
        break;
    default:
        return KM_ERROR_UNSUPPORTED_DIGEST;
    }

    if (!EVP_DigestInit_ex(&digest_ctx_, digest_algorithm_, NULL /* engine */)) {
        int err = ERR_get_error();
        LOG_E("Failed to initialize digest: %d %s", err, ERR_error_string(err, NULL));
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t RsaDigestingOperation::UpdateDigest(const Buffer& input, size_t* input_consumed) {
    if (!EVP_DigestUpdate(&digest_ctx_, input.peek_read(), input.available_read())) {
        int err = ERR_get_error();
        LOG_E("Failed to update digest: %d %s", err, ERR_error_string(err, NULL));
        return KM_ERROR_UNKNOWN_ERROR;
    }
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t RsaDigestingOperation::FinishDigest(unsigned* digest_size) {
    assert(digest_algorithm_ != NULL);
    if (!EVP_DigestFinal_ex(&digest_ctx_, digest_buf_, digest_size)) {
        int err = ERR_get_error();
        LOG_E("Failed to finalize digest: %d %s", err, ERR_error_string(err, NULL));
        return KM_ERROR_UNKNOWN_ERROR;
    }
    assert(*digest_size == static_cast<unsigned>(EVP_MD_size(digest_algorithm_)));
    return KM_ERROR_OK;
}

keymaster_error_t RsaSignOperation::Finish(const AuthorizationSet& /* additional_params */,
                                           const Buffer& /* signature */, Buffer* output) {
    assert(output);
    output->Reinitialize(RSA_size(rsa_key_));
    if (digest_ == KM_DIGEST_NONE)
        return SignUndigested(output);
    else
        return SignDigested(output);
}

keymaster_error_t RsaSignOperation::SignUndigested(Buffer* output) {
    int bytes_encrypted;
    switch (padding_) {
    case KM_PAD_NONE:
        bytes_encrypted = RSA_private_encrypt(data_.available_read(), data_.peek_read(),
                                              output->peek_write(), rsa_key_, RSA_NO_PADDING);
        break;
    case KM_PAD_RSA_PKCS1_1_5_SIGN:
        bytes_encrypted = RSA_private_encrypt(data_.available_read(), data_.peek_read(),
                                              output->peek_write(), rsa_key_, RSA_PKCS1_PADDING);
        break;
    default:
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    if (bytes_encrypted <= 0)
        return KM_ERROR_UNKNOWN_ERROR;
    output->advance_write(bytes_encrypted);
    return KM_ERROR_OK;
}

keymaster_error_t RsaSignOperation::SignDigested(Buffer* output) {
    unsigned digest_size = 0;
    keymaster_error_t error = FinishDigest(&digest_size);
    if (error != KM_ERROR_OK)
        return error;

    UniquePtr<uint8_t[]> padded_digest;
    switch (padding_) {
    case KM_PAD_NONE:
        return PrivateEncrypt(digest_buf_, digest_size, RSA_NO_PADDING, output);
    case KM_PAD_RSA_PKCS1_1_5_SIGN:
        return PrivateEncrypt(digest_buf_, digest_size, RSA_PKCS1_PADDING, output);
    case KM_PAD_RSA_PSS:
        // OpenSSL doesn't verify that the key is large enough for the digest size.  This can cause
        // a segfault in some cases, and in others can result in a unsafely-small salt.
        if ((unsigned)RSA_size(rsa_key_) < MIN_PSS_SALT_LEN + digest_size)
            // TODO(swillden): Add a better return code for this.
            return KM_ERROR_INCOMPATIBLE_DIGEST;

        if ((error = PssPadDigest(&padded_digest)) != KM_ERROR_OK)
            return error;
        return PrivateEncrypt(padded_digest.get(), RSA_size(rsa_key_), RSA_NO_PADDING, output);
    default:
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }
}

keymaster_error_t RsaSignOperation::PssPadDigest(UniquePtr<uint8_t[]>* padded_digest) {
    padded_digest->reset(new uint8_t[RSA_size(rsa_key_)]);
    if (!padded_digest->get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa_key_, padded_digest->get(), digest_buf_,
                                        digest_algorithm_, NULL,
                                        -2 /* Indicates maximum salt length */)) {
        LOG_E("%s", "Failed to apply PSS padding");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t RsaSignOperation::PrivateEncrypt(uint8_t* to_encrypt, size_t len,
                                                   int openssl_padding, Buffer* output) {
    int bytes_encrypted =
        RSA_private_encrypt(len, to_encrypt, output->peek_write(), rsa_key_, openssl_padding);
    if (bytes_encrypted <= 0)
        return KM_ERROR_UNKNOWN_ERROR;
    output->advance_write(bytes_encrypted);
    return KM_ERROR_OK;
}

keymaster_error_t RsaVerifyOperation::Finish(const AuthorizationSet& /* additional_params */,
                                             const Buffer& signature, Buffer* /* output */) {
    if (digest_ == KM_DIGEST_NONE)
        return VerifyUndigested(signature);
    else
        return VerifyDigested(signature);
}

keymaster_error_t RsaVerifyOperation::VerifyUndigested(const Buffer& signature) {
    return DecryptAndMatch(signature, data_.peek_read(), data_.available_read());
}

keymaster_error_t RsaVerifyOperation::VerifyDigested(const Buffer& signature) {
    unsigned digest_size = 0;
    keymaster_error_t error = FinishDigest(&digest_size);
    if (error != KM_ERROR_OK)
        return error;
    return DecryptAndMatch(signature, digest_buf_, digest_size);
}

keymaster_error_t RsaVerifyOperation::DecryptAndMatch(const Buffer& signature,
                                                      const uint8_t* to_match, size_t len) {
#ifdef OPENSSL_IS_BORINGSSL
    size_t key_len = RSA_size(rsa_key_);
#else
    size_t key_len = (size_t)RSA_size(rsa_key_);
#endif

    int openssl_padding;
    switch (padding_) {
    case KM_PAD_NONE:
        if (len != key_len)
            return KM_ERROR_INVALID_INPUT_LENGTH;
        if (len != signature.available_read())
            return KM_ERROR_VERIFICATION_FAILED;
        openssl_padding = RSA_NO_PADDING;
        break;
    case KM_PAD_RSA_PSS:  // Do a raw decrypt for PSS
        openssl_padding = RSA_NO_PADDING;
        break;
    case KM_PAD_RSA_PKCS1_1_5_SIGN:
        openssl_padding = RSA_PKCS1_PADDING;
        break;
    default:
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    UniquePtr<uint8_t[]> decrypted_data(new uint8_t[key_len]);
    int bytes_decrypted = RSA_public_decrypt(signature.available_read(), signature.peek_read(),
                                             decrypted_data.get(), rsa_key_, openssl_padding);
    if (bytes_decrypted < 0)
        return KM_ERROR_VERIFICATION_FAILED;

    if (padding_ == KM_PAD_RSA_PSS &&
        RSA_verify_PKCS1_PSS_mgf1(rsa_key_, to_match, digest_algorithm_, NULL, decrypted_data.get(),
                                  -2 /* salt length recovered from signature */))
        return KM_ERROR_OK;
    else if (padding_ != KM_PAD_RSA_PSS && memcmp_s(decrypted_data.get(), to_match, len) == 0)
        return KM_ERROR_OK;

    return KM_ERROR_VERIFICATION_FAILED;
}

const int OAEP_PADDING_OVERHEAD = 41;
const int PKCS1_PADDING_OVERHEAD = 11;

keymaster_error_t RsaEncryptOperation::Finish(const AuthorizationSet& /* additional_params */,
                                              const Buffer& /* signature */, Buffer* output) {
    assert(output);
    int openssl_padding;

#if defined(OPENSSL_IS_BORINGSSL)
    size_t key_len = RSA_size(rsa_key_);
#else
    size_t key_len = (size_t)RSA_size(rsa_key_);
#endif

    size_t message_size = data_.available_read();
    switch (padding_) {
    case KM_PAD_RSA_OAEP:
        openssl_padding = RSA_PKCS1_OAEP_PADDING;
        if (message_size + OAEP_PADDING_OVERHEAD >= key_len) {
            LOG_E("Cannot encrypt %d bytes with %d-byte key and OAEP padding",
                  data_.available_read(), key_len);
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        break;
    case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
        openssl_padding = RSA_PKCS1_PADDING;
        if (message_size + PKCS1_PADDING_OVERHEAD >= key_len) {
            LOG_E("Cannot encrypt %d bytes with %d-byte key and PKCS1 padding",
                  data_.available_read(), key_len);
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        break;
    default:
        LOG_E("Padding mode %d not supported", padding_);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    output->Reinitialize(RSA_size(rsa_key_));
    int bytes_encrypted = RSA_public_encrypt(data_.available_read(), data_.peek_read(),
                                             output->peek_write(), rsa_key_, openssl_padding);

    if (bytes_encrypted < 0) {
        LOG_E("Error %d encrypting data with RSA", ERR_get_error());
        return KM_ERROR_UNKNOWN_ERROR;
    }
    assert(bytes_encrypted == RSA_size(rsa_key_));
    output->advance_write(bytes_encrypted);

    return KM_ERROR_OK;
}

keymaster_error_t RsaDecryptOperation::Finish(const AuthorizationSet& /* additional_params */,
                                              const Buffer& /* signature */, Buffer* output) {
    assert(output);
    int openssl_padding;
    switch (padding_) {
    case KM_PAD_RSA_OAEP:
        openssl_padding = RSA_PKCS1_OAEP_PADDING;
        break;
    case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
        openssl_padding = RSA_PKCS1_PADDING;
        break;
    default:
        LOG_E("Padding mode %d not supported", padding_);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    output->Reinitialize(RSA_size(rsa_key_));
    int bytes_decrypted = RSA_private_decrypt(data_.available_read(), data_.peek_read(),
                                              output->peek_write(), rsa_key_, openssl_padding);

    if (bytes_decrypted < 0) {
        LOG_E("Error %d decrypting data with RSA", ERR_get_error());
        return KM_ERROR_UNKNOWN_ERROR;
    }
    output->advance_write(bytes_decrypted);

    return KM_ERROR_OK;
}

}  // namespace keymaster
