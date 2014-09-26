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

namespace keymaster {

class AsymmetricKey : public Key {
  public:
  protected:
    AsymmetricKey(const KeyBlob& blob, const Logger& logger) : Key(blob, logger) {}
    keymaster_error_t LoadKey(const UnencryptedKeyBlob& blob);

    /**
     * Return a copy of raw key material, in the key's preferred binary format.
     */
    virtual keymaster_error_t key_material(UniquePtr<uint8_t[]>* material, size_t* size) const;

    /**
     * Return a copy of raw key material, in the specified format.
     */
    virtual keymaster_error_t formatted_key_material(keymaster_key_format_t format,
                                                     UniquePtr<uint8_t[]>* material,
                                                     size_t* size) const;

  protected:
    AsymmetricKey(const AuthorizationSet& auths, const Logger& logger) : Key(auths, logger) {}

  private:
    virtual int evp_key_type() = 0;
    virtual bool InternalToEvp(EVP_PKEY* pkey) const = 0;
    virtual bool EvpToInternal(const EVP_PKEY* pkey) = 0;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_ASYMMETRIC_KEY_H
