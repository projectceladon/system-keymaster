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

#include "ecdsa_key.h"
#include "ecdsa_operation.h"
#include "openssl_utils.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

const uint32_t ECDSA_DEFAULT_KEY_SIZE = 224;

/* static */
EcdsaKey* EcdsaKey::GenerateKey(const AuthorizationSet& key_description, const Logger& logger,
                                keymaster_error_t* error) {
    if (!error)
        return NULL;

    AuthorizationSet authorizations(key_description);

    uint32_t key_size = ECDSA_DEFAULT_KEY_SIZE;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size))
        authorizations.push_back(Authorization(TAG_KEY_SIZE, key_size));

    UniquePtr<EC_KEY, ECDSA_Delete> ecdsa_key(EC_KEY_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (ecdsa_key.get() == NULL || pkey.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    UniquePtr<EC_GROUP, EC_GROUP_Delete> group(choose_group(key_size));
    if (group.get() == NULL) {
        // Technically, could also have been a memory allocation problem.
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return NULL;
    }

    EC_GROUP_set_point_conversion_form(group.get(), POINT_CONVERSION_UNCOMPRESSED);
    EC_GROUP_set_asn1_flag(group.get(), OPENSSL_EC_NAMED_CURVE);

    if (EC_KEY_set_group(ecdsa_key.get(), group.get()) != 1 ||
        EC_KEY_generate_key(ecdsa_key.get()) != 1 || EC_KEY_check_key(ecdsa_key.get()) < 0) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    EcdsaKey* new_key = new EcdsaKey(ecdsa_key.release(), authorizations, logger);
    *error = new_key ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return new_key;
}

/* static */
EcdsaKey* EcdsaKey::ImportKey(const AuthorizationSet& key_description, EVP_PKEY* pkey,
                              const Logger& logger, keymaster_error_t* error) {
    if (!error)
        return NULL;
    *error = KM_ERROR_UNKNOWN_ERROR;

    UniquePtr<EC_KEY, ECDSA_Delete> ecdsa_key(EVP_PKEY_get1_EC_KEY(pkey));
    if (!ecdsa_key.get())
        return NULL;

    AuthorizationSet authorizations(key_description);

    size_t extracted_key_size_bits;
    *error = get_group_size(*EC_KEY_get0_group(ecdsa_key.get()), &extracted_key_size_bits);
    if (*error != KM_ERROR_OK)
        return NULL;

    uint32_t key_size_bits;
    if (authorizations.GetTagValue(TAG_KEY_SIZE, &key_size_bits)) {
        // key_size_bits specified, make sure it matches the key.
        if (key_size_bits != extracted_key_size_bits) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
    } else {
        // key_size_bits not specified, add it.
        authorizations.push_back(TAG_KEY_SIZE, extracted_key_size_bits);
    }

    keymaster_algorithm_t algorithm;
    if (authorizations.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        if (algorithm != KM_ALGORITHM_ECDSA) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
    } else {
        authorizations.push_back(TAG_ALGORITHM, KM_ALGORITHM_ECDSA);
    }

    // Don't bother with the other parameters.  If the necessary padding, digest, purpose, etc. are
    // missing, the error will be diagnosed when the key is used (when auth checking is
    // implemented).
    *error = KM_ERROR_OK;
    return new EcdsaKey(ecdsa_key.release(), authorizations, logger);
}

/* static */
EC_GROUP* EcdsaKey::choose_group(size_t key_size_bits) {
    switch (key_size_bits) {
    case 192:
        return EC_GROUP_new_by_curve_name(NID_X9_62_prime192v1);
        break;
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
keymaster_error_t EcdsaKey::get_group_size(const EC_GROUP& group, size_t* key_size_bits) {
    switch (EC_GROUP_get_curve_name(&group)) {
    case NID_X9_62_prime192v1:
        *key_size_bits = 192;
        break;
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

EcdsaKey::EcdsaKey(const UnencryptedKeyBlob& blob, const Logger& logger, keymaster_error_t* error)
    : AsymmetricKey(blob, logger) {
    if (error)
        *error = LoadKey(blob);
}

Operation* EcdsaKey::CreateOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                                     keymaster_padding_t padding, keymaster_error_t* error) {
    Operation* op;
    switch (purpose) {
    case KM_PURPOSE_SIGN:
        op = new EcdsaSignOperation(purpose, logger_, digest, padding, ecdsa_key_.release());
        break;
    case KM_PURPOSE_VERIFY:
        op = new EcdsaVerifyOperation(purpose, logger_, digest, padding, ecdsa_key_.release());
        break;
    default:
        *error = KM_ERROR_UNIMPLEMENTED;
        return NULL;
    }
    *error = op ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

bool EcdsaKey::EvpToInternal(const EVP_PKEY* pkey) {
    ecdsa_key_.reset(EVP_PKEY_get1_EC_KEY(const_cast<EVP_PKEY*>(pkey)));
    return ecdsa_key_.get() != NULL;
}

bool EcdsaKey::InternalToEvp(EVP_PKEY* pkey) const {
    return EVP_PKEY_set1_EC_KEY(pkey, ecdsa_key_.get()) == 1;
}

}  // namespace keymaster
