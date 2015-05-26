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

#ifndef SYSTEM_KEYMASTER_EC_KEY_H_
#define SYSTEM_KEYMASTER_EC_KEY_H_

#include <openssl/ec.h>

#include "asymmetric_key.h"

namespace keymaster {

class EcKeyFactory : public AsymmetricKeyFactory {
  public:
    EcKeyFactory(const KeymasterContext* context) : AsymmetricKeyFactory(context) {}

    keymaster_error_t GenerateKey(const AuthorizationSet& key_description,
                                  KeymasterKeyBlob* key_blob, AuthorizationSet* hw_enforced,
                                  AuthorizationSet* sw_enforced) const override;
    keymaster_error_t ImportKey(const AuthorizationSet& key_description,
                                keymaster_key_format_t input_key_material_format,
                                const KeymasterKeyBlob& input_key_material,
                                KeymasterKeyBlob* output_key_blob, AuthorizationSet* hw_enforced,
                                AuthorizationSet* sw_enforced) const override;

    keymaster_error_t CreateEmptyKey(const AuthorizationSet& hw_enforced,
                                     const AuthorizationSet& sw_enforced,
                                     UniquePtr<AsymmetricKey>* key) const override;

    keymaster_error_t UpdateImportKeyDescription(const AuthorizationSet& key_description,
                                                 keymaster_key_format_t key_format,
                                                 const KeymasterKeyBlob& key_material,
                                                 AuthorizationSet* updated_description,
                                                 uint32_t* key_size) const;

  private:
    static EC_GROUP* choose_group(size_t key_size_bits);
    static keymaster_error_t get_group_size(const EC_GROUP& group, size_t* key_size_bits);
};

class EcdsaKeyFactory : public EcKeyFactory {
  public:
    EcdsaKeyFactory(const KeymasterContext* context) : EcKeyFactory(context) {}

    OperationFactory* GetOperationFactory(keymaster_purpose_t purpose) const override;

    keymaster_algorithm_t keymaster_key_type() const override { return KM_ALGORITHM_EC; }
    int evp_key_type() const override { return EVP_PKEY_EC; }
};

class EcdsaOperationFactory;

class EcKey : public AsymmetricKey {
  public:
    EcKey(const AuthorizationSet& hw_enforced, const AuthorizationSet& sw_enforced,
          keymaster_error_t* error)
        : AsymmetricKey(hw_enforced, sw_enforced, error) {}

    bool InternalToEvp(EVP_PKEY* pkey) const override;
    bool EvpToInternal(const EVP_PKEY* pkey) override;

    EC_KEY* key() const { return EC_KEY_dup(ec_key_.get()); }

  protected:
    EcKey(EC_KEY* ec_key, const AuthorizationSet& hw_enforced, const AuthorizationSet& sw_enforced,
          keymaster_error_t* error)
        : AsymmetricKey(hw_enforced, sw_enforced, error), ec_key_(ec_key) {}

  private:
    UniquePtr<EC_KEY, EC_Delete> ec_key_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_EC_KEY_H_
