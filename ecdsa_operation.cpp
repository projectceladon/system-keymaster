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

#include <openssl/ecdsa.h>

#include "ecdsa_operation.h"
#include "openssl_utils.h"

namespace keymaster {

struct ECDSA_Delete {
    void operator()(EC_KEY* p) { EC_KEY_free(p); }
};

struct EC_GROUP_Delete {
    void operator()(EC_GROUP* p) { EC_GROUP_free(p); }
};

/* static */
keymaster_error_t EcdsaOperation::Generate(uint32_t key_size_bits, UniquePtr<uint8_t[]>* key_data,
                                           size_t* key_data_size) {
    if (key_data == NULL || key_data_size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<EC_KEY, ECDSA_Delete> ecdsa_key(EC_KEY_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (ecdsa_key.get() == NULL || pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    UniquePtr<EC_GROUP, EC_GROUP_Delete> group;
    switch (key_size_bits) {
    case 192:
        group.reset(EC_GROUP_new_by_curve_name(NID_X9_62_prime192v1));
        break;
    case 224:
        group.reset(EC_GROUP_new_by_curve_name(NID_secp224r1));
        break;
    case 256:
        group.reset(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
        break;
    case 384:
        group.reset(EC_GROUP_new_by_curve_name(NID_secp384r1));
        break;
    case 521:
        group.reset(EC_GROUP_new_by_curve_name(NID_secp521r1));
        break;
    default:
        break;
    }

    if (group.get() == NULL)
        // Technically, could also have been a memory allocation problem.
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;

    EC_GROUP_set_point_conversion_form(group.get(), POINT_CONVERSION_UNCOMPRESSED);
    EC_GROUP_set_asn1_flag(group.get(), OPENSSL_EC_NAMED_CURVE);

    if (EC_KEY_set_group(ecdsa_key.get(), group.get()) != 1 ||
        EC_KEY_generate_key(ecdsa_key.get()) != 1 || EC_KEY_check_key(ecdsa_key.get()) < 0 ||
        !EVP_PKEY_assign_EC_KEY(pkey.get(), ecdsa_key.get()))
        return KM_ERROR_UNKNOWN_ERROR;
    else
        release_because_ownership_transferred(ecdsa_key);

    *key_data_size = i2d_PrivateKey(pkey.get(), NULL);
    if (*key_data_size <= 0)
        return KM_ERROR_UNKNOWN_ERROR;

    key_data->reset(new uint8_t[*key_data_size]);
    uint8_t* tmp = key_data->get();
    i2d_PrivateKey(pkey.get(), &tmp);

    return KM_ERROR_OK;
}

}  // namespace keymaster
