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

class EcdsaKeyFactory : public AsymmetricKeyFactory {
  public:
    virtual keymaster_algorithm_t registry_key() const { return KM_ALGORITHM_ECDSA; }

    virtual Key* GenerateKey(const AuthorizationSet& key_description, keymaster_error_t* error);
    virtual Key* ImportKey(const AuthorizationSet& key_description,
                           keymaster_key_format_t key_format, const uint8_t* key_data,
                           size_t key_data_length, keymaster_error_t* error);
    virtual Key* LoadKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error);
    virtual Key* RescopeKey(const UnencryptedKeyBlob& blob,
                            const AuthorizationSet& new_authorizations, keymaster_error_t* error);

  private:
    static EC_GROUP* choose_group(size_t key_size_bits);
    static keymaster_error_t get_group_size(const EC_GROUP& group, size_t* key_size_bits);

    struct EC_GROUP_Delete {
        void operator()(EC_GROUP* p) { EC_GROUP_free(p); }
    };
};

class EcdsaSignOperationFactory;
class EcdsaVerifyOperationFactory;

class EcdsaKey : public AsymmetricKey {
  private:
    friend EcdsaKeyFactory;
    friend EcdsaSignOperationFactory;
    friend EcdsaVerifyOperationFactory;

    EcdsaKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error);
    EcdsaKey(EC_KEY* ecdsa_key, const AuthorizationSet auths)
        : AsymmetricKey(auths), ecdsa_key_(ecdsa_key) {}

    virtual int evp_key_type() { return EVP_PKEY_EC; }
    virtual bool InternalToEvp(EVP_PKEY* pkey) const;
    virtual bool EvpToInternal(const EVP_PKEY* pkey);

    struct ECDSA_Delete {
        void operator()(EC_KEY* p) { EC_KEY_free(p); }
    };

    EC_KEY* key() const { return EC_KEY_dup(ecdsa_key_.get()); }

    UniquePtr<EC_KEY, ECDSA_Delete> ecdsa_key_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_ECDSA_KEY_H_
