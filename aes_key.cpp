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

#include "aes_key.h"

#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "aes_operation.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

class AesKeyFactory : public SymmetricKeyFactory {
  public:
    keymaster_algorithm_t registry_key() const { return KM_ALGORITHM_AES; }

    virtual Key* LoadKey(const UnencryptedKeyBlob& blob, const Logger& logger,
                         keymaster_error_t* error) {
        return new AesKey(blob, logger, error);
    }

    virtual SymmetricKey* CreateKey(const AuthorizationSet& auths, const Logger& logger) {
        return new AesKey(auths, logger);
    }
};
static KeyFactoryRegistry::Registration<AesKeyFactory> registration;

}  // namespace keymaster
