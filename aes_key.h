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

#include "key.h"

namespace keymaster {

const uint32_t MAX_AES_CHUNK_LENGTH = 64 * 1024;

class AesKey : public Key {
  public:
    static const int MAX_KEY_SIZE = 32;
    static const int MAX_MAC_LENGTH = 16;

    AesKey(const UnencryptedKeyBlob& blob, const Logger& logger, keymaster_error_t* error);
    ~AesKey();

    static AesKey* GenerateKey(const AuthorizationSet& key_description, const Logger& logger,
                               keymaster_error_t* error);

    static bool size_is_supported(size_t key_size_in_bits) {
        return (key_size_in_bits == 128 || key_size_in_bits == 192 || key_size_in_bits == 256);
    };

    static bool block_mode_is_supported(keymaster_block_mode_t block_mode) {
        return (block_mode == KM_MODE_OCB);
    }

    static bool chunk_length_is_supported(uint32_t chunk_length) {
        return (chunk_length <= MAX_AES_CHUNK_LENGTH);
    }

    static bool mac_length_required(keymaster_block_mode_t) { return true; }

    static bool mac_length_is_supported(keymaster_block_mode_t, uint32_t mac_length) {
        return (mac_length <= MAX_MAC_LENGTH);
    }

    static bool padding_is_supported(keymaster_block_mode_t, keymaster_padding_t padding) {
        return (padding == KM_PAD_NONE);
    }

    virtual Operation* CreateOperation(keymaster_purpose_t, keymaster_error_t* error);
    virtual keymaster_error_t key_material(UniquePtr<uint8_t[]>* key_material, size_t* size) const;
    virtual keymaster_error_t formatted_key_material(keymaster_key_format_t, UniquePtr<uint8_t[]>*,
                                                     size_t*) const {
        return KM_ERROR_UNIMPLEMENTED;
    }

  private:
    AesKey(const uint8_t(&key_data)[MAX_KEY_SIZE], size_t key_data_size, AuthorizationSet& auths,
           const Logger& logger);

    keymaster_error_t LoadKey(const UnencryptedKeyBlob& blob);
    static bool ModeAndPurposesAreCompatible(const AuthorizationSet& auths,
                                             keymaster_block_mode_t block_mode,
                                             const Logger& logger);
    Operation* CreateOcbOperation(keymaster_purpose_t, keymaster_error_t* error);

    const size_t key_data_size_;
    uint8_t key_data_[MAX_KEY_SIZE];
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_AES_KEY_H_
