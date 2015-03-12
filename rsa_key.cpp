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

#include "rsa_key.h"

#include "openssl_err.h"
#include "openssl_utils.h"
#include "rsa_operation.h"
#include "unencrypted_key_blob.h"

#if defined(OPENSSL_IS_BORINGSSL)
typedef size_t openssl_size_t;
#else
typedef int openssl_size_t;
#endif

namespace keymaster {

const uint32_t RSA_DEFAULT_KEY_SIZE = 2048;
const uint64_t RSA_DEFAULT_EXPONENT = 65537;

class RsaKeyFactory : public AsymmetricKeyFactory {
  public:
    virtual keymaster_algorithm_t registry_key() const { return KM_ALGORITHM_RSA; }
    virtual Key* GenerateKey(const AuthorizationSet& key_description, keymaster_error_t* error);
    virtual Key* ImportKey(const AuthorizationSet& key_description,
                           keymaster_key_format_t key_format, const uint8_t* key_data,
                           size_t key_data_length, keymaster_error_t* error);
    virtual Key* LoadKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error) {
        return new RsaKey(blob, error);
    }
    virtual Key* RescopeKey(const UnencryptedKeyBlob& blob,
                            const AuthorizationSet& new_authorizations, keymaster_error_t* error);
};
static KeyFactoryRegistry::Registration<RsaKeyFactory> registration;

Key* RsaKeyFactory::GenerateKey(const AuthorizationSet& key_description, keymaster_error_t* error) {
    if (!error)
        return NULL;

    AuthorizationSet authorizations(key_description);

    uint64_t public_exponent = RSA_DEFAULT_EXPONENT;
    if (!authorizations.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent))
        authorizations.push_back(Authorization(TAG_RSA_PUBLIC_EXPONENT, public_exponent));

    uint32_t key_size = RSA_DEFAULT_KEY_SIZE;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size))
        authorizations.push_back(Authorization(TAG_KEY_SIZE, key_size));

    UniquePtr<BIGNUM, BIGNUM_Delete> exponent(BN_new());
    UniquePtr<RSA, RsaKey::RSA_Delete> rsa_key(RSA_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (rsa_key.get() == NULL || pkey.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    if (!BN_set_word(exponent.get(), public_exponent) ||
        !RSA_generate_key_ex(rsa_key.get(), key_size, exponent.get(), NULL /* callback */)) {
        *error = TranslateLastOpenSslError();
        return NULL;
    }

    RsaKey* new_key = new RsaKey(rsa_key.release(), authorizations);
    *error = new_key ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return new_key;
}

Key* RsaKeyFactory::ImportKey(const AuthorizationSet& key_description,
                              keymaster_key_format_t key_format, const uint8_t* key_data,
                              size_t key_data_length, keymaster_error_t* error) {
    if (!error)
        return NULL;

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(
        ExtractEvpKey(key_format, KM_ALGORITHM_RSA, key_data, key_data_length, error));
    if (*error != KM_ERROR_OK)
        return NULL;
    assert(pkey.get());

    UniquePtr<RSA, RsaKey::RSA_Delete> rsa_key(EVP_PKEY_get1_RSA(pkey.get()));
    if (!rsa_key.get()) {
        *error = TranslateLastOpenSslError();
        return NULL;
    }

    AuthorizationSet authorizations(key_description);

    uint64_t public_exponent;
    if (authorizations.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent)) {
        // public_exponent specified, make sure it matches the key
        UniquePtr<BIGNUM, BIGNUM_Delete> public_exponent_bn(BN_new());
        if (!BN_set_word(public_exponent_bn.get(), public_exponent))
            return NULL;
        if (BN_cmp(public_exponent_bn.get(), rsa_key->e) != 0) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
    } else {
        // public_exponent not specified, use the one from the key.
        public_exponent = BN_get_word(rsa_key->e);
        if (public_exponent == 0xffffffffL) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
        authorizations.push_back(TAG_RSA_PUBLIC_EXPONENT, public_exponent);
    }

    uint32_t key_size;
    if (authorizations.GetTagValue(TAG_KEY_SIZE, &key_size)) {
        // key_size specified, make sure it matches the key.
        if (RSA_size(rsa_key.get()) != (openssl_size_t)key_size) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
    } else {
        key_size = RSA_size(rsa_key.get()) * 8;
        authorizations.push_back(TAG_KEY_SIZE, key_size);
    }

    keymaster_algorithm_t algorithm;
    if (authorizations.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        if (algorithm != KM_ALGORITHM_RSA) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
    } else {
        authorizations.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    }

    // Don't bother with the other parameters.  If the necessary padding, digest, purpose, etc. are
    // missing, the error will be diagnosed when the key is used (when auth checking is
    // implemented).
    *error = KM_ERROR_OK;
    return new RsaKey(rsa_key.release(), authorizations);
}

Key* RsaKeyFactory::RescopeKey(const UnencryptedKeyBlob& blob,
                               const AuthorizationSet& new_authorizations,
                               keymaster_error_t* error) {
    if (!error)
        return NULL;

    RsaKey original_key(blob, error);
    if (*error != KM_ERROR_OK)
        return NULL;

    RsaKey* new_key = new RsaKey(original_key.rsa_key_.release(), new_authorizations);
    *error = new_key ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return new_key;
}

RsaKey::RsaKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error) : AsymmetricKey(blob) {
    if (error)
        *error = LoadKey(blob);
}

RSA* RsaKey::key() const {
    return rsa_key_.get();
}

bool RsaKey::EvpToInternal(const EVP_PKEY* pkey) {
    rsa_key_.reset(EVP_PKEY_get1_RSA(const_cast<EVP_PKEY*>(pkey)));
    return rsa_key_.get() != NULL;
}

bool RsaKey::InternalToEvp(EVP_PKEY* pkey) const {
    return EVP_PKEY_set1_RSA(pkey, rsa_key_.get()) == 1;
}

bool RsaKey::SupportedMode(keymaster_purpose_t purpose, keymaster_padding_t padding) {
    switch (purpose) {
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        return padding == KM_PAD_NONE || padding == KM_PAD_RSA_PSS ||
               padding == KM_PAD_RSA_PKCS1_1_5_SIGN;
        break;
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
        return padding == KM_PAD_RSA_OAEP || padding == KM_PAD_RSA_PKCS1_1_5_ENCRYPT;
        break;
    };
    return false;
}

bool RsaKey::SupportedMode(keymaster_purpose_t purpose, keymaster_digest_t digest) {
    switch (purpose) {
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        return digest == KM_DIGEST_NONE || digest == KM_DIGEST_SHA_2_256;
        break;
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
        /* Don't care */
        break;
    };
    return true;
}

}  // namespace keymaster
