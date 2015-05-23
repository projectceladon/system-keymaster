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

#ifndef SYSTEM_KEYMASTER_AES_KEY_H_
#define SYSTEM_KEYMASTER_AES_KEY_H_

#include <openssl/aes.h>

#include "symmetric_key.h"

namespace keymaster {

class AesKeyFactory : public SymmetricKeyFactory {
  public:
    keymaster_algorithm_t registry_key() const { return KM_ALGORITHM_AES; }

    Key* LoadKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error) override;
    SymmetricKey* CreateKey(const AuthorizationSet& auths) override;
};

class AesKey : public SymmetricKey {
  public:
    AesKey(const AuthorizationSet& auths) : SymmetricKey(auths) {}
    AesKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error) : SymmetricKey(blob, error) {}

  private:
    bool size_supported(size_t key_size) const override {
        // AES keys only come in three sizes, 128, 192 and 256 bits.
        return key_size == 128 / 8 || key_size == 192 / 8 || key_size == 256 / 8;
    }
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_AES_KEY_H_
