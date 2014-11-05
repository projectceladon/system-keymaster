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

#ifndef SYSTEM_KEYMASTER_EDCSA_KEY_H_
#define SYSTEM_KEYMASTER_EDCSA_KEY_H_

#include <openssl/ecdsa.h>

#include "asymmetric_key.h"

namespace keymaster {

class EcdsaKey : public AsymmetricKey {
  public:
    static EcdsaKey* GenerateKey(const AuthorizationSet& key_description, const Logger& logger,
                                 keymaster_error_t* error);
    static EcdsaKey* ImportKey(const AuthorizationSet& key_description, EVP_PKEY* pkey,
                               const Logger& logger, keymaster_error_t* error);
    EcdsaKey(const UnencryptedKeyBlob& blob, const Logger& logger, keymaster_error_t* error);

    virtual Operation* CreateOperation(keymaster_purpose_t purpose, keymaster_digest_t digest,
                                       keymaster_padding_t padding, keymaster_error_t* error);

  private:
    EcdsaKey(EC_KEY* ecdsa_key, const AuthorizationSet auths, const Logger& logger)
        : AsymmetricKey(auths, logger), ecdsa_key_(ecdsa_key) {}

    static EC_GROUP* choose_group(size_t key_size_bits);
    static keymaster_error_t get_group_size(const EC_GROUP& group, size_t* key_size_bits);

    virtual int evp_key_type() { return EVP_PKEY_EC; }
    virtual bool InternalToEvp(EVP_PKEY* pkey) const;
    virtual bool EvpToInternal(const EVP_PKEY* pkey);

    struct ECDSA_Delete {
        void operator()(EC_KEY* p) { EC_KEY_free(p); }
    };

    struct EC_GROUP_Delete {
        void operator()(EC_GROUP* p) { EC_GROUP_free(p); }
    };

    UniquePtr<EC_KEY, ECDSA_Delete> ecdsa_key_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_ECDSA_KEY_H_
