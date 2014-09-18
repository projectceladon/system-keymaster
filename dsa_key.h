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

#ifndef SYSTEM_KEYMASTER_DSA_KEY_H_
#define SYSTEM_KEYMASTER_DSA_KEY_H_

#include <openssl/dsa.h>

#include "asymmetric_key.h"

namespace keymaster {

class DsaKey : public AsymmetricKey {
  public:
    static DsaKey* GenerateKey(const AuthorizationSet& key_description, const Logger& logger,
                               keymaster_error_t* error);
    static DsaKey* ImportKey(const AuthorizationSet& key_description, EVP_PKEY* pkey,
                             const Logger& logger, keymaster_error_t* error);
    DsaKey(const UnencryptedKeyBlob& blob, const Logger& logger, keymaster_error_t* error);

    virtual Operation* CreateOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                                       keymaster_padding_t padding, keymaster_error_t* error);

  private:
    DsaKey(DSA* dsa_key, const AuthorizationSet auths, const Logger& logger)
        : AsymmetricKey(auths, logger), dsa_key_(dsa_key) {}

    virtual int evp_key_type() { return EVP_PKEY_DSA; }
    virtual bool InternalToEvp(EVP_PKEY* pkey) const;
    virtual bool EvpToInternal(const EVP_PKEY* pkey);

    struct DSA_Delete {
        void operator()(DSA* p) { DSA_free(p); }
    };

    UniquePtr<DSA, DSA_Delete> dsa_key_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_DSA_KEY_H_
