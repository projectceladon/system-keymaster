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

#ifndef SYSTEM_KEYMASTER_KDF_H_
#define SYSTEM_KEYMASTER_KDF_H_

#include <keymaster/serializable.h>

namespace keymaster {

// Kdf is an abstract class that provides an interface to a
// key derivation function.
class Kdf {
  public:
    virtual ~Kdf() {}

    virtual bool Init(Buffer& secret, Buffer& salt, Buffer& info, size_t key_bytes_to_generate) = 0;
    virtual bool Init(const uint8_t* secret, size_t secret_len, const uint8_t* salt,
                      size_t salt_len, const uint8_t* info, size_t info_len,
                      size_t key_bytes_to_generate) = 0;

    virtual bool secret_key(Buffer* buf) const = 0;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_KDF_H_
