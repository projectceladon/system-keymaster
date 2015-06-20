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

#include <new>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "aes_operation.h"

namespace keymaster {

AesEncryptionOperationFactory encrypt_factory;
AesDecryptionOperationFactory decrypt_factory;

OperationFactory* AesKeyFactory::GetOperationFactory(keymaster_purpose_t purpose) const {
    switch (purpose) {
    case KM_PURPOSE_ENCRYPT:
        return &encrypt_factory;
    case KM_PURPOSE_DECRYPT:
        return &decrypt_factory;
    default:
        return nullptr;
    }
}

keymaster_error_t AesKeyFactory::LoadKey(const KeymasterKeyBlob& key_material,
                                         const AuthorizationSet& hw_enforced,
                                         const AuthorizationSet& sw_enforced,
                                         UniquePtr<Key>* key) const {
    if (!key)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    keymaster_error_t error = KM_ERROR_OK;
    key->reset(new (std::nothrow) AesKey(key_material, hw_enforced, sw_enforced, &error));
    if (!key->get())
        error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return error;
}

}  // namespace keymaster
