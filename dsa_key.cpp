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

#include "dsa_key.h"
#include "dsa_operation.h"
#include "openssl_utils.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

const uint32_t DSA_DEFAULT_KEY_SIZE = 2048;

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

DsaKey* DsaKey::GenerateKey(const AuthorizationSet& key_description, const Logger& logger,
                            keymaster_error_t* error) {
    if (!error)
        return NULL;

    AuthorizationSet authorizations(key_description);

    uint32_t key_size = DSA_DEFAULT_KEY_SIZE;
    if (!authorizations.GetTagValue(TAG_KEY_SIZE, &key_size))
        authorizations.push_back(Authorization(TAG_KEY_SIZE, key_size));

    UniquePtr<DSA, DSA_Delete> dsa_key(DSA_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (dsa_key.get() == NULL || pkey.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    // If anything goes wrong in the next section, it's a param problem.
    *error = KM_ERROR_INVALID_DSA_PARAMS;

    keymaster_blob_t g_blob;
    keymaster_blob_t p_blob;
    keymaster_blob_t q_blob;
    GetDsaParamData(authorizations, TAG_DSA_GENERATOR, &g_blob);
    GetDsaParamData(authorizations, TAG_DSA_P, &p_blob);
    GetDsaParamData(authorizations, TAG_DSA_Q, &q_blob);

    if (g_blob.data == NULL && p_blob.data == NULL && q_blob.data == NULL) {
        logger.info("DSA parameters unspecified, generating them for key size %d", key_size);
        if (!DSA_generate_parameters_ex(dsa_key.get(), key_size, NULL /* seed */, 0 /* seed_len */,
                                        NULL /* counter_ret */, NULL /* h_ret */,
                                        NULL /* callback */)) {
            logger.severe("DSA parameter generation failed.");
            return NULL;
        }

        SetDsaParamData(&authorizations, TAG_DSA_GENERATOR, dsa_key->g);
        SetDsaParamData(&authorizations, TAG_DSA_P, dsa_key->p);
        SetDsaParamData(&authorizations, TAG_DSA_Q, dsa_key->q);
    } else if (g_blob.data == NULL || p_blob.data == NULL || q_blob.data == NULL) {
        logger.severe("Some DSA parameters provided.  Provide all or none");
        return NULL;
    } else {
        // All params provided. Use them.
        dsa_key->g = BN_bin2bn(g_blob.data, g_blob.data_length, NULL);
        dsa_key->p = BN_bin2bn(p_blob.data, p_blob.data_length, NULL);
        dsa_key->q = BN_bin2bn(q_blob.data, q_blob.data_length, NULL);
        if (dsa_key->g == NULL || dsa_key->p == NULL || dsa_key->q == NULL) {
            return NULL;
        }
    }

    if (!DSA_generate_key(dsa_key.get())) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    DsaKey* new_key = new DsaKey(dsa_key.release(), authorizations, logger);
    *error = new_key ? KM_ERROR_OK : KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return new_key;
}

template <keymaster_tag_t T>
keymaster_error_t GetOrCheckDsaParam(TypedTag<KM_BIGNUM, T> tag, BIGNUM* bn,
                                     AuthorizationSet* auths) {
    keymaster_blob_t blob;
    if (auths->GetTagValue(tag, &blob)) {
        // value specified, make sure it matches
        UniquePtr<BIGNUM, BIGNUM_Delete> extracted_bn(BN_bin2bn(blob.data, blob.data_length, NULL));
        if (extracted_bn.get() == NULL)
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        if (BN_cmp(extracted_bn.get(), bn) != 0)
            return KM_ERROR_IMPORT_PARAMETER_MISMATCH;
    } else {
        // value not specified, add it
        UniquePtr<uint8_t[]> data(new uint8_t[BN_num_bytes(bn)]);
        BN_bn2bin(bn, data.get());
        auths->push_back(tag, data.get(), BN_num_bytes(bn));
    }
    return KM_ERROR_OK;
}

static size_t calculate_key_size_in_bits(DSA* dsa_key) {
    // Openssl provides no convenient way to get a DSA key size, but dsa_key->p is L bits long.
    // There may be some leading zeros that mess up this calculation, but DSA key sizes are also
    // constrained to be multiples of 64 bits.  So the key size is the bit length of p rounded up to
    // the nearest 64.
    return ((BN_num_bytes(dsa_key->p) * 8) + 63) / 64 * 64;
}

/* static */
DsaKey* DsaKey::ImportKey(const AuthorizationSet& key_description, EVP_PKEY* pkey,
                          const Logger& logger, keymaster_error_t* error) {
    if (!error)
        return NULL;
    *error = KM_ERROR_UNKNOWN_ERROR;

    UniquePtr<DSA, DSA_Delete> dsa_key(EVP_PKEY_get1_DSA(pkey));
    if (!dsa_key.get())
        return NULL;

    AuthorizationSet authorizations(key_description);

    *error = GetOrCheckDsaParam(TAG_DSA_GENERATOR, dsa_key->g, &authorizations);
    if (*error != KM_ERROR_OK)
        return NULL;

    *error = GetOrCheckDsaParam(TAG_DSA_P, dsa_key->p, &authorizations);
    if (*error != KM_ERROR_OK)
        return NULL;

    *error = GetOrCheckDsaParam(TAG_DSA_Q, dsa_key->q, &authorizations);
    if (*error != KM_ERROR_OK)
        return NULL;

    uint32_t key_size_in_bits;
    if (authorizations.GetTagValue(TAG_KEY_SIZE, &key_size_in_bits)) {
        // key_bits specified, make sure it matches the key.
        if (key_size_in_bits != calculate_key_size_in_bits(dsa_key.get())) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
    } else {
        // key_size_bits not specified, add it.
        authorizations.push_back(TAG_KEY_SIZE, calculate_key_size_in_bits(dsa_key.get()));
    }

    keymaster_algorithm_t algorithm;
    if (authorizations.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        if (algorithm != KM_ALGORITHM_DSA) {
            *error = KM_ERROR_IMPORT_PARAMETER_MISMATCH;
            return NULL;
        }
    } else {
        authorizations.push_back(TAG_ALGORITHM, KM_ALGORITHM_DSA);
    }

    // Don't bother with the other parameters.  If the necessary padding, digest, purpose, etc. are
    // missing, the error will be diagnosed when the key is used (when auth checking is
    // implemented).
    *error = KM_ERROR_OK;
    return new DsaKey(dsa_key.release(), authorizations, logger);
}

DsaKey::DsaKey(const UnencryptedKeyBlob& blob, const Logger& logger, keymaster_error_t* error)
    : AsymmetricKey(blob, logger) {
    if (error)
        *error = LoadKey(blob);
}

Operation* DsaKey::CreateOperation(keymaster_purpose_t purpose, keymaster_error_t* error) {
    keymaster_digest_t digest = KM_DIGEST_NONE;
    if (!authorizations().GetTagValue(TAG_DIGEST, &digest) || digest != KM_DIGEST_NONE) {
        *error = KM_ERROR_UNSUPPORTED_DIGEST;
        return NULL;
    }

    Operation* op;
    switch (purpose) {
    case KM_PURPOSE_SIGN:
        op = new DsaSignOperation(purpose, logger_, digest, dsa_key_.release());
        break;
    case KM_PURPOSE_VERIFY:
        op = new DsaVerifyOperation(purpose, logger_, digest, dsa_key_.release());
        break;
    default:
        *error = KM_ERROR_INCOMPATIBLE_PURPOSE;
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

}  // namespace keymaster
