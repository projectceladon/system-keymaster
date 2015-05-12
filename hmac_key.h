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

#ifndef SYSTEM_KEYMASTER_HMAC_KEY_H_
#define SYSTEM_KEYMASTER_HMAC_KEY_H_

#include "symmetric_key.h"

namespace keymaster {

class HmacKeyFactory : public SymmetricKeyFactory {
  public:
    keymaster_algorithm_t registry_key() const override { return KM_ALGORITHM_HMAC; }

    Key* LoadKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error) override;
    SymmetricKey* CreateKey(const AuthorizationSet& auths) override;
};

class HmacKey : public SymmetricKey {
    static const size_t MAX_HMAC_KEY_SIZE = 256; /* Arbitrary limit, for DoS prevention */

  public:
    HmacKey(const AuthorizationSet& auths) : SymmetricKey(auths) {}
    HmacKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error) : SymmetricKey(blob, error) {}

  private:
    bool size_supported(size_t key_size) const override { return key_size < MAX_HMAC_KEY_SIZE; }
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_HMAC_KEY_H_
