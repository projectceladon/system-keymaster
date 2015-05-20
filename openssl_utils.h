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

#ifndef SYSTEM_KEYMASTER_OPENSSL_UTILS_H_
#define SYSTEM_KEYMASTER_OPENSSL_UTILS_H_

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <UniquePtr.h>

#include <hardware/keymaster_defs.h>

namespace keymaster {

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const { BN_free(p); }
};

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const { PKCS8_PRIV_KEY_INFO_free(p); }
};

struct RSA_Delete {
    void operator()(RSA* p) { RSA_free(p); }
};

/**
 * Many OpenSSL APIs take ownership of an argument on success but don't free the argument on
 * failure. This means we need to tell our scoped pointers when we've transferred ownership, without
 * triggering a warning by not using the result of release().
 */
template <typename T, typename Delete_T>
inline void release_because_ownership_transferred(UniquePtr<T, Delete_T>& p) {
    T* val __attribute__((unused)) = p.release();
}

void convert_bn_to_blob(BIGNUM* bn, keymaster_blob_t* blob);

keymaster_error_t convert_pkcs8_blob_to_evp(const uint8_t* key_data, size_t key_length,
                                            keymaster_algorithm_t expected_algorithm,
                                            UniquePtr<EVP_PKEY, EVP_PKEY_Delete>* pkey);

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_OPENSSL_UTILS_H_
