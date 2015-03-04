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

#include "hmac_key.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include "hmac_operation.h"

namespace keymaster {

class HmacKeyFactory : public SymmetricKeyFactory {
  public:
    keymaster_algorithm_t registry_key() const { return KM_ALGORITHM_HMAC; }

    virtual Key* LoadKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error) {
        return new HmacKey(blob, error);
    }

    virtual SymmetricKey* CreateKey(const AuthorizationSet& auths) { return new HmacKey(auths); }
};

static KeyFactoryRegistry::Registration<HmacKeyFactory> registration;

}  // namespace keymaster
