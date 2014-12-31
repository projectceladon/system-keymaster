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

/**
 * Abstract base for all RSA operation factories.  This class exists mainly to centralize some code
 * common to all RSA operation factories.
 */
class RsaOperationFactory : public OperationFactory {
  public:
    virtual KeyType registry_key() const { return KeyType(KM_ALGORITHM_RSA, purpose()); }
    virtual keymaster_purpose_t purpose() const = 0;

  protected:
    bool GetAndValidatePadding(const Key& key, keymaster_padding_t* padding,
                               keymaster_error_t* error) const;
    bool GetAndValidateDigest(const Key& key, keymaster_digest_t* digest,
                              keymaster_error_t* error) const;
    static RSA* GetRsaKey(const Key& key, keymaster_error_t* error);
};

bool RsaOperationFactory::GetAndValidatePadding(const Key& key, keymaster_padding_t* padding,
                                                keymaster_error_t* error) const {
    *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
    if (!key.authorizations().GetTagValue(TAG_PADDING, padding))
        return false;

    size_t padding_count;
    const keymaster_padding_t* supported_paddings = SupportedPaddingModes(&padding_count);
    for (size_t i = 0; i < padding_count; ++i) {
        if (*padding == supported_paddings[i]) {
            *error = KM_ERROR_OK;
            return true;
        }
    }
    return false;
}

bool RsaOperationFactory::GetAndValidateDigest(const Key& key, keymaster_digest_t* digest,
                                               keymaster_error_t* error) const {
    *error = KM_ERROR_UNSUPPORTED_DIGEST;
    if (!key.authorizations().GetTagValue(TAG_DIGEST, digest))
        return false;

    size_t digest_count;
    const keymaster_digest_t* supported_digests = SupportedDigests(&digest_count);
    for (size_t i = 0; i < digest_count; ++i) {
        if (*digest == supported_digests[i]) {
            *error = KM_ERROR_OK;
            return true;
        }
    }
    return false;
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

static const keymaster_digest_t supported_digests[] = {KM_DIGEST_NONE};
static const keymaster_padding_t supported_sig_padding[] = {KM_PAD_NONE};

/**
 * Abstract base for RSA operations that digest their input (signing and verification).  This class
 * does most of the work of creation of RSA digesting operations, delegating only the actual
 * operation instantiation.
 */
class RsaDigestingOperationFactory : public RsaOperationFactory {
  public:
    virtual Operation* CreateOperation(const Key& key, keymaster_error_t* error);

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

Operation* RsaDigestingOperationFactory::CreateOperation(const Key& key, keymaster_error_t* error) {
    keymaster_padding_t padding;
    keymaster_digest_t digest;
    RSA* rsa;
    if (!GetAndValidateDigest(key, &digest, error) ||
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
    virtual Operation* CreateOperation(const Key& key, keymaster_error_t* error);

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

Operation* RsaCryptingOperationFactory::CreateOperation(const Key& key, keymaster_error_t* error) {
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

keymaster_error_t RsaSignOperation::Finish(const AuthorizationSet& /* additional_params */,
                                           const Buffer& /* signature */, Buffer* output) {
    assert(output);
    output->Reinitialize(RSA_size(rsa_key_));
    int bytes_encrypted = RSA_private_encrypt(data_.available_read(), data_.peek_read(),
                                              output->peek_write(), rsa_key_, RSA_NO_PADDING);
    if (bytes_encrypted < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(bytes_encrypted == RSA_size(rsa_key_));
    output->advance_write(bytes_encrypted);
    return KM_ERROR_OK;
}

keymaster_error_t RsaVerifyOperation::Finish(const AuthorizationSet& /* additional_params */,
                                             const Buffer& signature, Buffer* /* output */) {
#if defined(OPENSSL_IS_BORINGSSL)
    size_t message_size = data_.available_read();
#else
    if (data_.available_read() > INT_MAX)
        return KM_ERROR_INVALID_INPUT_LENGTH;
    int message_size = (int)data_.available_read();
#endif

    if (message_size != RSA_size(rsa_key_))
        return KM_ERROR_INVALID_INPUT_LENGTH;

    if (data_.available_read() != signature.available_read())
        return KM_ERROR_VERIFICATION_FAILED;

    UniquePtr<uint8_t[]> decrypted_data(new uint8_t[RSA_size(rsa_key_)]);
    int bytes_decrypted = RSA_public_decrypt(signature.available_read(), signature.peek_read(),
                                             decrypted_data.get(), rsa_key_, RSA_NO_PADDING);
    if (bytes_decrypted < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(bytes_decrypted == RSA_size(rsa_key_));

    if (memcmp_s(decrypted_data.get(), data_.peek_read(), data_.available_read()) == 0)
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
    size_t message_size = data_.available_read();
#else
    if (data_.available_read() > INT_MAX)
        return KM_ERROR_INVALID_INPUT_LENGTH;
    int message_size = (int)data_.available_read();
#endif

    switch (padding_) {
    case KM_PAD_RSA_OAEP:
        openssl_padding = RSA_PKCS1_OAEP_PADDING;
        if (message_size >= RSA_size(rsa_key_) - OAEP_PADDING_OVERHEAD) {
            LOG_E("Cannot encrypt %d bytes with %d-byte key and OAEP padding",
                  data_.available_read(), RSA_size(rsa_key_));
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        break;
    case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
        openssl_padding = RSA_PKCS1_PADDING;
        if (message_size >= RSA_size(rsa_key_) - PKCS1_PADDING_OVERHEAD) {
            LOG_E("Cannot encrypt %d bytes with %d-byte key and PKCS1 padding",
                  data_.available_read(), RSA_size(rsa_key_));
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
