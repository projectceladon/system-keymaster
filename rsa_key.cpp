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

#include <keymaster/keymaster_context.h>

#include "openssl_err.h"
#include "openssl_utils.h"

#if defined(OPENSSL_IS_BORINGSSL)
typedef size_t openssl_size_t;
#else
typedef int openssl_size_t;
#endif

namespace keymaster {

keymaster_error_t RsaKeyFactory::GenerateKey(const AuthorizationSet& key_description,
                                             KeymasterKeyBlob* key_blob,
                                             AuthorizationSet* hw_enforced,
                                             AuthorizationSet* sw_enforced) {
    if (!key_blob || !hw_enforced || !sw_enforced)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    AuthorizationSet authorizations(key_description);

    uint64_t public_exponent;
    if (!authorizations.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent)) {
        LOG_E("%s", "No public exponent specified for RSA key generation");
        return KM_ERROR_INVALID_ARGUMENT;
    }

    uint32_t key_size;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size)) {
        LOG_E("%s", "No key size specified for RSA key generation");
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }

    UniquePtr<BIGNUM, BIGNUM_Delete> exponent(BN_new());
    UniquePtr<RSA, RsaKey::RSA_Delete> rsa_key(RSA_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (exponent.get() == NULL || rsa_key.get() == NULL || pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!BN_set_word(exponent.get(), public_exponent) ||
        !RSA_generate_key_ex(rsa_key.get(), key_size, exponent.get(), NULL /* callback */))
        return TranslateLastOpenSslError();

    if (EVP_PKEY_set1_RSA(pkey.get(), rsa_key.get()) != 1)
        return TranslateLastOpenSslError();

    KeymasterKeyBlob key_material;
    keymaster_error_t error = EvpKeyToKeyMaterial(pkey.get(), &key_material);
    if (error != KM_ERROR_OK)
        return error;

    return context_->CreateKeyBlob(authorizations, KM_ORIGIN_GENERATED, key_material, key_blob,
                                   hw_enforced, sw_enforced);
}

keymaster_error_t RsaKeyFactory::ImportKey(const AuthorizationSet& key_description,
                                           keymaster_key_format_t input_key_material_format,
                                           const KeymasterKeyBlob& input_key_material,
                                           KeymasterKeyBlob* output_key_blob,
                                           AuthorizationSet* hw_enforced,
                                           AuthorizationSet* sw_enforced) {
    if (!output_key_blob || !hw_enforced || !sw_enforced)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey;
    keymaster_error_t error =
        KeyMaterialToEvpKey(input_key_material_format, input_key_material, &pkey);
    if (error != KM_ERROR_OK)
        return error;

    UniquePtr<RSA, RsaKey::RSA_Delete> rsa_key(EVP_PKEY_get1_RSA(pkey.get()));
    if (!rsa_key.get())
        return TranslateLastOpenSslError();

    AuthorizationSet authorizations(key_description);

    uint64_t public_exponent;
    if (authorizations.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent)) {
        // public_exponent specified, make sure it matches the key
        UniquePtr<BIGNUM, BIGNUM_Delete> public_exponent_bn(BN_new());
        if (!BN_set_word(public_exponent_bn.get(), public_exponent))
            return KM_ERROR_UNKNOWN_ERROR;
        if (BN_cmp(public_exponent_bn.get(), rsa_key->e) != 0)
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    } else {
        // public_exponent not specified, use the one from the key.
        public_exponent = BN_get_word(rsa_key->e);
        if (public_exponent == 0xffffffffL)
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
        authorizations.push_back(TAG_RSA_PUBLIC_EXPONENT, public_exponent);
    }

    uint32_t key_size;
    if (authorizations.GetTagValue(TAG_KEY_SIZE, &key_size)) {
        // key_size specified, make sure it matches the key.
        if (RSA_size(rsa_key.get()) * 8 != (openssl_size_t)key_size)
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    } else {
        key_size = RSA_size(rsa_key.get()) * 8;
        authorizations.push_back(TAG_KEY_SIZE, key_size);
    }

    keymaster_algorithm_t algorithm;
    if (authorizations.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        if (algorithm != KM_ALGORITHM_RSA)
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    } else {
        authorizations.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
    }

    return context_->CreateKeyBlob(authorizations, KM_ORIGIN_IMPORTED, input_key_material,
                                   output_key_blob, hw_enforced, sw_enforced);
}

keymaster_error_t RsaKeyFactory::CreateEmptyKey(const AuthorizationSet& hw_enforced,
                                                const AuthorizationSet& sw_enforced,
                                                UniquePtr<AsymmetricKey>* key) {
    keymaster_error_t error;
    key->reset(new RsaKey(hw_enforced, sw_enforced, &error));
    if (!key->get())
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return error;
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
