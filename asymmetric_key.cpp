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

#include "asymmetric_key.h"
#include "dsa_operation.h"
#include "ecdsa_operation.h"
#include "key_blob.h"
#include "keymaster_defs.h"
#include "openssl_utils.h"
#include "rsa_operation.h"

namespace keymaster {

const uint32_t RSA_DEFAULT_KEY_SIZE = 2048;
const uint64_t RSA_DEFAULT_EXPONENT = 65537;

const uint32_t DSA_DEFAULT_KEY_SIZE = 2048;

const uint32_t ECDSA_DEFAULT_KEY_SIZE = 192;

keymaster_error_t AsymmetricKey::LoadKey(const KeyBlob& blob) {
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> evp_key(EVP_PKEY_new());
    if (evp_key.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    EVP_PKEY* tmp_pkey = evp_key.get();
    const uint8_t* key_material = blob.key_material();
    if (d2i_PrivateKey(evp_key_type(), &tmp_pkey, &key_material, blob.key_material_length()) ==
        NULL) {
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    if (!EvpToInternal(evp_key.get()))
        return KM_ERROR_UNKNOWN_ERROR;

    return KM_ERROR_OK;
}

keymaster_error_t AsymmetricKey::key_material(UniquePtr<uint8_t[]>* material, size_t* size) const {
    if (material == NULL || size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!InternalToEvp(pkey.get()))
        return KM_ERROR_UNKNOWN_ERROR;

    *size = i2d_PrivateKey(pkey.get(), NULL /* key_data*/);
    if (*size <= 0)
        return KM_ERROR_UNKNOWN_ERROR;

    material->reset(new uint8_t[*size]);
    uint8_t* tmp = material->get();
    i2d_PrivateKey(pkey.get(), &tmp);

    return KM_ERROR_OK;
}

keymaster_error_t AsymmetricKey::formatted_key_material(UniquePtr<uint8_t[]>* material,
                                                        size_t* size) const {
    if (material == NULL || size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    return KM_ERROR_UNIMPLEMENTED;
}

Operation* AsymmetricKey::CreateOperation(keymaster_purpose_t purpose, keymaster_error_t* error) {
    keymaster_digest_t digest;
    if (!authorizations().GetTagValue(TAG_DIGEST, &digest) || digest != KM_DIGEST_NONE) {
        *error = KM_ERROR_UNSUPPORTED_DIGEST;
        return NULL;
    }

    keymaster_padding_t padding;
    if (!authorizations().GetTagValue(TAG_PADDING, &padding) || padding != KM_PAD_NONE) {
        *error = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        return NULL;
    }

    return CreateOperation(purpose, digest, padding, error);
}

/* static */
RsaKey* RsaKey::GenerateKey(const AuthorizationSet& key_description, keymaster_error_t* error) {
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
    UniquePtr<RSA, RSA_Delete> rsa_key(RSA_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (rsa_key.get() == NULL || pkey.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    if (!BN_set_word(exponent.get(), public_exponent) ||
        !RSA_generate_key_ex(rsa_key.get(), key_size, exponent.get(), NULL /* callback */)) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    RsaKey* new_key = new RsaKey(rsa_key.release(), authorizations);
    *error = new_key ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return new_key;
}

RsaKey::RsaKey(const KeyBlob& blob, keymaster_error_t* error) : AsymmetricKey(blob) {
    if (error)
        *error = LoadKey(blob);
}

Operation* RsaKey::CreateOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                                   keymaster_padding_t padding, keymaster_error_t* error) {
    Operation* op;
    switch (purpose) {
    case KM_PURPOSE_SIGN:
        op = new RsaSignOperation(purpose, digest, padding, rsa_key_.release());
        break;
    case KM_PURPOSE_VERIFY:
        op = new RsaVerifyOperation(purpose, digest, padding, rsa_key_.release());
        break;
    default:
        *error = KM_ERROR_UNIMPLEMENTED;
        return NULL;
    }
    *error = op ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

bool RsaKey::EvpToInternal(const EVP_PKEY* pkey) {
    rsa_key_.reset(EVP_PKEY_get1_RSA(const_cast<EVP_PKEY*>(pkey)));
    return rsa_key_.get() != NULL;
}

bool RsaKey::InternalToEvp(EVP_PKEY* pkey) const {
    return EVP_PKEY_set1_RSA(pkey, rsa_key_.get()) == 1;
}

template <keymaster_tag_t Tag>
static void GetDsaParamData(const AuthorizationSet& auths, TypedTag<KM_BIGNUM, Tag> tag,
                            keymaster_blob_t* blob) {
    if (!auths.GetTagValue(tag, blob))
        blob->data = NULL;
}

// Store the specified DSA param in auths
template <keymaster_tag_t Tag>
static void SetDsaParamData(AuthorizationSet* auths, TypedTag<KM_BIGNUM, Tag> tag, BIGNUM* number) {
    keymaster_blob_t blob;
    convert_bn_to_blob(number, &blob);
    auths->push_back(Authorization(tag, blob));
    delete[] blob.data;
}

DsaKey* DsaKey::GenerateKey(const AuthorizationSet& key_description, keymaster_error_t* error) {
    if (!error)
        return NULL;

    AuthorizationSet authorizations(key_description);

    keymaster_blob_t g_blob;
    GetDsaParamData(authorizations, TAG_DSA_GENERATOR, &g_blob);

    keymaster_blob_t p_blob;
    GetDsaParamData(authorizations, TAG_DSA_P, &p_blob);

    keymaster_blob_t q_blob;
    GetDsaParamData(authorizations, TAG_DSA_Q, &q_blob);

    uint32_t key_size = DSA_DEFAULT_KEY_SIZE;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size))
        authorizations.push_back(Authorization(TAG_KEY_SIZE, key_size));

    UniquePtr<uint8_t[]> key_data;
    size_t key_data_size;

    UniquePtr<DSA, DSA_Delete> dsa_key(DSA_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (dsa_key.get() == NULL || pkey.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    // If anything goes wrong in the next section, it's a param problem.
    *error = KM_ERROR_INVALID_DSA_PARAMS;

    if (g_blob.data == NULL && p_blob.data == NULL && q_blob.data == NULL) {
        // No params provided, generate them.
        if (!DSA_generate_parameters_ex(dsa_key.get(), key_size, NULL /* seed */, 0 /* seed_len */,
                                        NULL /* counter_ret */, NULL /* h_ret */,
                                        NULL /* callback */))
            // TODO(swillden): return a more precise error, depending on ERR_get_error();
            return NULL;

        SetDsaParamData(&authorizations, TAG_DSA_GENERATOR, dsa_key->g);
        SetDsaParamData(&authorizations, TAG_DSA_P, dsa_key->p);
        SetDsaParamData(&authorizations, TAG_DSA_Q, dsa_key->q);
    } else if (g_blob.data == NULL || p_blob.data == NULL || q_blob.data == NULL) {
        // Some params provided: that's an error.  Provide them all or provide none.
        return NULL;
    } else {
        // All params provided. Use them.
        dsa_key->g = BN_bin2bn(g_blob.data, g_blob.data_length, NULL);
        dsa_key->p = BN_bin2bn(p_blob.data, p_blob.data_length, NULL);
        dsa_key->q = BN_bin2bn(q_blob.data, q_blob.data_length, NULL);

        if (dsa_key->g == NULL || dsa_key->p == NULL || dsa_key->q == NULL)
            return NULL;
    }

    if (!DSA_generate_key(dsa_key.get())) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    DsaKey* new_key = new DsaKey(dsa_key.release(), authorizations);
    *error = new_key ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return new_key;
}

DsaKey::DsaKey(const KeyBlob& blob, keymaster_error_t* error) : AsymmetricKey(blob) {
    if (error)
        *error = LoadKey(blob);
}

Operation* DsaKey::CreateOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                                   keymaster_padding_t padding, keymaster_error_t* error) {
    Operation* op;
    switch (purpose) {
    case KM_PURPOSE_SIGN:
        op = new DsaSignOperation(purpose, digest, padding, dsa_key_.release());
        break;
    case KM_PURPOSE_VERIFY:
        op = new DsaVerifyOperation(purpose, digest, padding, dsa_key_.release());
        break;
    default:
        *error = KM_ERROR_UNIMPLEMENTED;
        return NULL;
    }
    *error = op ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

bool DsaKey::EvpToInternal(const EVP_PKEY* pkey) {
    dsa_key_.reset(EVP_PKEY_get1_DSA(const_cast<EVP_PKEY*>(pkey)));
    return dsa_key_.get() != NULL;
}

bool DsaKey::InternalToEvp(EVP_PKEY* pkey) const {
    return EVP_PKEY_set1_DSA(pkey, dsa_key_.get()) == 1;
}

/* static */
EcdsaKey* EcdsaKey::GenerateKey(const AuthorizationSet& key_description, keymaster_error_t* error) {
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

    EcdsaKey* new_key = new EcdsaKey(ecdsa_key.release(), authorizations);
    *error = new_key ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return new_key;
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

EcdsaKey::EcdsaKey(const KeyBlob& blob, keymaster_error_t* error) : AsymmetricKey(blob) {
    if (error)
        *error = LoadKey(blob);
}

Operation* EcdsaKey::CreateOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                                     keymaster_padding_t padding, keymaster_error_t* error) {
    Operation* op;
    switch (purpose) {
    case KM_PURPOSE_SIGN:
        op = new EcdsaSignOperation(purpose, digest, padding, ecdsa_key_.release());
        break;
    case KM_PURPOSE_VERIFY:
        op = new EcdsaVerifyOperation(purpose, digest, padding, ecdsa_key_.release());
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
