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

keymaster_error_t HmacKeyFactory::LoadKey(const KeymasterKeyBlob& key_material,
                                          const AuthorizationSet& hw_enforced,
                                          const AuthorizationSet& sw_enforced,
                                          UniquePtr<Key>* key) {
    if (!key)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    keymaster_error_t error;
    key->reset(new HmacKey(key_material, hw_enforced, sw_enforced, &error));
    if (!key->get())
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return error;
}

}  // namespace keymaster
