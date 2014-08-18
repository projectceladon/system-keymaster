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

#include <openssl/bn.h>

#include "dsa_operation.h"
#include "openssl_utils.h"

namespace keymaster {

struct DSA_Delete {
    void operator()(DSA* p) { DSA_free(p); }
};

/* static */
keymaster_error_t DsaOperation::Generate(uint32_t key_size_bits, keymaster_blob_t* g,
                                         keymaster_blob_t* p, keymaster_blob_t* q,
                                         UniquePtr<uint8_t[]>* key_data, size_t* key_data_size) {
    if (g == NULL || p == NULL || q == NULL || key_data == NULL || key_data_size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<DSA, DSA_Delete> dsa_key(DSA_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (dsa_key.get() == NULL || pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (g->data == NULL && p->data == NULL && q->data == NULL) {
        // No params provided, generate them.
        if (!DSA_generate_parameters_ex(dsa_key.get(), key_size_bits, NULL /* seed */,
                                        0 /* seed_len */, NULL /* counter_ret */, NULL /* h_ret */,
                                        NULL /* callback */)) {
            // TODO(swillden): return a more precise error, depending on ERR_get_error();
            return KM_ERROR_INVALID_DSA_PARAMS;
        }
        convert_bn_to_blob(dsa_key->g, g);
        convert_bn_to_blob(dsa_key->p, p);
        convert_bn_to_blob(dsa_key->q, q);
    } else if (g->data == NULL || p->data == NULL || q->data == NULL) {
        // Some params provided, that's an error.  Provide them all or provide none.
        return KM_ERROR_INVALID_DSA_PARAMS;
    } else {
        // All params provided. Use them.
        dsa_key->g = BN_bin2bn(g->data, g->data_length, NULL);
        dsa_key->p = BN_bin2bn(p->data, p->data_length, NULL);
        dsa_key->q = BN_bin2bn(q->data, q->data_length, NULL);

        if (dsa_key->g == NULL || dsa_key->p == NULL || dsa_key->q == NULL)
            return KM_ERROR_INVALID_DSA_PARAMS;
    }

    if (!DSA_generate_key(dsa_key.get()) || !EVP_PKEY_assign_DSA(pkey.get(), dsa_key.get()))
        return KM_ERROR_UNKNOWN_ERROR;
    release_because_ownership_transferred(dsa_key);

    *key_data_size = i2d_PrivateKey(pkey.get(), NULL);
    if (*key_data_size <= 0)
        return KM_ERROR_UNKNOWN_ERROR;

    key_data->reset(new uint8_t[*key_data_size]);
    uint8_t* tmp = key_data->get();
    i2d_PrivateKey(pkey.get(), &tmp);

    return KM_ERROR_OK;
}

}  // namespace keymaster
