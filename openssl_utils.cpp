/*
 * Copyright 2015 The Android Open Source Project
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

#include "openssl_utils.h"

#include "openssl_err.h"

namespace keymaster {

void convert_bn_to_blob(BIGNUM* bn, keymaster_blob_t* blob) {
    blob->data_length = BN_num_bytes(bn);
    blob->data = new uint8_t[blob->data_length];
    BN_bn2bin(bn, const_cast<uint8_t*>(blob->data));
}

static int convert_to_evp(keymaster_algorithm_t algorithm) {
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return EVP_PKEY_RSA;
    case KM_ALGORITHM_ECDSA:
        return EVP_PKEY_EC;
    default:
        return -1;
    };
}

keymaster_error_t convert_pkcs8_blob_to_evp(const uint8_t* key_data, size_t key_length,
                                            keymaster_algorithm_t expected_algorithm,
                                            UniquePtr<EVP_PKEY, EVP_PKEY_Delete>* pkey) {
    if (key_data == NULL || key_length <= 0)
        return KM_ERROR_INVALID_KEY_BLOB;

    UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete> pkcs8(
        d2i_PKCS8_PRIV_KEY_INFO(NULL, &key_data, key_length));
    if (pkcs8.get() == NULL)
        return TranslateLastOpenSslError(true /* log_message */);

    pkey->reset(EVP_PKCS82PKEY(pkcs8.get()));
    if (!pkey->get())
        return TranslateLastOpenSslError(true /* log_message */);

    if (EVP_PKEY_type((*pkey)->type) != convert_to_evp(expected_algorithm)) {
        LOG_E("EVP key algorithm was %d, not the expected %d", EVP_PKEY_type((*pkey)->type),
              convert_to_evp(expected_algorithm));
        return KM_ERROR_INVALID_KEY_BLOB;
    }

    return KM_ERROR_OK;
}

}  // namespace keymaster
