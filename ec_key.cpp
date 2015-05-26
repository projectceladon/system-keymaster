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

#include "ec_key.h"

#include <keymaster/keymaster_context.h>

#include "openssl_err.h"
#include "openssl_utils.h"

#if defined(OPENSSL_IS_BORINGSSL)
typedef size_t openssl_size_t;
#else
typedef int openssl_size_t;
#endif

namespace keymaster {

keymaster_error_t EcKeyFactory::GenerateKey(const AuthorizationSet& key_description,
                                            KeymasterKeyBlob* key_blob,
                                            AuthorizationSet* hw_enforced,
                                            AuthorizationSet* sw_enforced) {
    if (!key_blob || !hw_enforced || !sw_enforced)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    AuthorizationSet authorizations(key_description);

    uint32_t key_size;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size)) {
        LOG_E("%s", "No key size specified for EC key generation");
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }

    UniquePtr<EC_KEY, EcKey::EC_Delete> ec_key(EC_KEY_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (ec_key.get() == NULL || pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    UniquePtr<EC_GROUP, EC_GROUP_Delete> group(choose_group(key_size));
    if (group.get() == NULL) {
        LOG_E("Unable to get EC group for key of size %d", key_size);
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;
    }

#if !defined(OPENSSL_IS_BORINGSSL)
    EC_GROUP_set_point_conversion_form(group.get(), POINT_CONVERSION_UNCOMPRESSED);
    EC_GROUP_set_asn1_flag(group.get(), OPENSSL_EC_NAMED_CURVE);
#endif

    if (EC_KEY_set_group(ec_key.get(), group.get()) != 1 ||
        EC_KEY_generate_key(ec_key.get()) != 1 || EC_KEY_check_key(ec_key.get()) < 0) {
        return TranslateLastOpenSslError();
    }

    if (EVP_PKEY_set1_EC_KEY(pkey.get(), ec_key.get()) != 1)
        return TranslateLastOpenSslError();

    KeymasterKeyBlob key_material;
    keymaster_error_t error = EvpKeyToKeyMaterial(pkey.get(), &key_material);
    if (error != KM_ERROR_OK)
        return error;

    return context_->CreateKeyBlob(authorizations, KM_ORIGIN_GENERATED, key_material, key_blob,
                                   hw_enforced, sw_enforced);
}

keymaster_error_t EcKeyFactory::ImportKey(const AuthorizationSet& key_description,
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

    UniquePtr<EC_KEY, EcKey::EC_Delete> ec_key(EVP_PKEY_get1_EC_KEY(pkey.get()));
    if (!ec_key.get())
        return TranslateLastOpenSslError();

    AuthorizationSet authorizations(key_description);

    size_t extracted_key_size_bits;
    error = get_group_size(*EC_KEY_get0_group(ec_key.get()), &extracted_key_size_bits);
    if (error != KM_ERROR_OK)
        return error;

    uint32_t key_size_bits;
    if (authorizations.GetTagValue(TAG_KEY_SIZE, &key_size_bits)) {
        // key_size_bits specified, make sure it matches the key.
        if (key_size_bits != extracted_key_size_bits)
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    } else {
        // key_size_bits not specified, add it.
        authorizations.push_back(TAG_KEY_SIZE, extracted_key_size_bits);
    }

    keymaster_algorithm_t algorithm;
    if (authorizations.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        if (algorithm != registry_key())
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    } else {
        authorizations.push_back(TAG_ALGORITHM, registry_key());
    }

    return context_->CreateKeyBlob(authorizations, KM_ORIGIN_IMPORTED, input_key_material,
                                   output_key_blob, hw_enforced, sw_enforced);
}

/* static */
EC_GROUP* EcKeyFactory::choose_group(size_t key_size_bits) {
    switch (key_size_bits) {
    case 224:
        return EC_GROUP_new_by_curve_name(NID_secp224r1);
        break;
    case 256:
        return EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        break;
    case 384:
        return EC_GROUP_new_by_curve_name(NID_secp384r1);
        break;
    case 521:
        return EC_GROUP_new_by_curve_name(NID_secp521r1);
        break;
    default:
        return NULL;
        break;
    }
}
/* static */
keymaster_error_t EcKeyFactory::get_group_size(const EC_GROUP& group, size_t* key_size_bits) {
    switch (EC_GROUP_get_curve_name(&group)) {
    case NID_secp224r1:
        *key_size_bits = 224;
        break;
    case NID_X9_62_prime256v1:
        *key_size_bits = 256;
        break;
    case NID_secp384r1:
        *key_size_bits = 384;
        break;
    case NID_secp521r1:
        *key_size_bits = 521;
        break;
    default:
        return KM_ERROR_UNSUPPORTED_EC_FIELD;
    }
    return KM_ERROR_OK;
}

keymaster_error_t EcKeyFactory::CreateEmptyKey(const AuthorizationSet& hw_enforced,
                                               const AuthorizationSet& sw_enforced,
                                               UniquePtr<AsymmetricKey>* key) {
    keymaster_error_t error;
    key->reset(new EcKey(hw_enforced, sw_enforced, &error));
    if (!key->get())
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return error;
}

bool EcKey::EvpToInternal(const EVP_PKEY* pkey) {
    ec_key_.reset(EVP_PKEY_get1_EC_KEY(const_cast<EVP_PKEY*>(pkey)));
    return ec_key_.get() != NULL;
}

bool EcKey::InternalToEvp(EVP_PKEY* pkey) const {
    return EVP_PKEY_set1_EC_KEY(pkey, ec_key_.get()) == 1;
}

}  // namespace keymaster
