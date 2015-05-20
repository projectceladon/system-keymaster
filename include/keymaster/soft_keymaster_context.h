/*
 * Copyright 2015 The Android Open Source Project
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

#ifndef SYSTEM_KEYMASTER_SOFT_KEYMASTER_CONTEXT_H_
#define SYSTEM_KEYMASTER_SOFT_KEYMASTER_CONTEXT_H_

#include <memory>

#include <hardware/keymaster0.h>
#include <keymaster/keymaster_context.h>

namespace keymaster {

class SoftKeymasterKeyRegistrations;
class Keymaster0Engine;

/**
 * SoftKeymasterContext provides the context for a non-secure implementation of AndroidKeymaster.
 */
class SoftKeymasterContext : public KeymasterContext {
  public:
    SoftKeymasterContext(keymaster0_device_t* keymaster0_device);

    keymaster_error_t CreateKeyBlob(const AuthorizationSet& auths, keymaster_key_origin_t origin,
                                    const KeymasterKeyBlob& key_material, KeymasterKeyBlob* blob,
                                    AuthorizationSet* hw_enforced,
                                    AuthorizationSet* sw_enforced) const override;

    keymaster_error_t ParseKeyBlob(const KeymasterKeyBlob& blob,
                                   const AuthorizationSet& additional_params,
                                   KeymasterKeyBlob* key_material, AuthorizationSet* hw_enforced,
                                   AuthorizationSet* sw_enforced) const override;
    keymaster_error_t AddRngEntropy(const uint8_t* buf, size_t length) const override;
    keymaster_error_t GenerateRandom(uint8_t* buf, size_t length) const override;

  private:
    std::unique_ptr<Keymaster0Engine> engine_;
    std::unique_ptr<SoftKeymasterKeyRegistrations> registrations_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_SOFT_KEYMASTER_CONTEXT_H_
