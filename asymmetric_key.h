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

#ifndef SYSTEM_KEYMASTER_ASYMMETRIC_KEY_H
#define SYSTEM_KEYMASTER_ASYMMETRIC_KEY_H

#include <openssl/evp.h>

#include "key.h"
#include "openssl_utils.h"

namespace keymaster {

class AsymmetricKey;

class AsymmetricKeyFactory : public KeyFactory {
  public:
    AsymmetricKeyFactory(const KeymasterContext* context) : KeyFactory(context) {}

    keymaster_error_t KeyMaterialToEvpKey(keymaster_key_format_t key_format,
                                          const KeymasterKeyBlob& key_material,
                                          UniquePtr<EVP_PKEY, EVP_PKEY_Delete>* evp_pkey) const;
    keymaster_error_t EvpKeyToKeyMaterial(const EVP_PKEY* evp_pkey,
                                          KeymasterKeyBlob* key_blob) const;

    keymaster_error_t LoadKey(const KeymasterKeyBlob& key_material,
                              const AuthorizationSet& hw_enforced,
                              const AuthorizationSet& sw_enforced,
                              UniquePtr<Key>* key) const override;

    virtual keymaster_error_t CreateEmptyKey(const AuthorizationSet& hw_enforced,
                                             const AuthorizationSet& sw_enforced,
                                             UniquePtr<AsymmetricKey>* key) const = 0;

    virtual keymaster_algorithm_t keymaster_key_type() const = 0;
    virtual int evp_key_type() const = 0;

    virtual const keymaster_key_format_t* SupportedImportFormats(size_t* format_count) const;
    virtual const keymaster_key_format_t* SupportedExportFormats(size_t* format_count) const;
};

class AsymmetricKey : public Key {
  public:
    AsymmetricKey(const AuthorizationSet& hw_enforced, const AuthorizationSet& sw_enforced,
                  keymaster_error_t* error)
        : Key(hw_enforced, sw_enforced, error) {}

    keymaster_error_t key_material(UniquePtr<uint8_t[]>* material, size_t* size) const override;
    keymaster_error_t formatted_key_material(keymaster_key_format_t format,
                                             UniquePtr<uint8_t[]>* material,
                                             size_t* size) const override;

    virtual bool InternalToEvp(EVP_PKEY* pkey) const = 0;
    virtual bool EvpToInternal(const EVP_PKEY* pkey) = 0;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_ASYMMETRIC_KEY_H
