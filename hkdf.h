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

#ifndef SYSTEM_KEYMASTER_HKDF_H_
#define SYSTEM_KEYMASTER_HKDF_H_

#include "kdf.h"

#include <keymaster/serializable.h>

#include <UniquePtr.h>

namespace keymaster {

// Rfc5869Sha256Kdf implements the key derivation function specified in RFC 5869 (using
// SHA256) and outputs key material, as needed by ECIES.
// See https://tools.ietf.org/html/rfc5869 for details.
class Rfc5869Sha256Kdf : public Kdf {
  public:
    Rfc5869Sha256Kdf() : initalized_(false) {}
    ~Rfc5869Sha256Kdf() {}

    // Kdf interface.
    bool Init(Buffer& secret, Buffer& salt, Buffer& info, size_t key_bytes_to_generate);

    bool Init(const uint8_t* secret, size_t secret_len, const uint8_t* salt, size_t salt_len,
              const uint8_t* info, size_t info_len, size_t key_bytes_to_generate);

    bool secret_key(Buffer* buf) const {
        return initalized_ && buf->Reinitialize(secret_key_.get(), secret_key_len_);
    }

  private:
    bool initalized_;
    UniquePtr<uint8_t[]> output_;
    UniquePtr<uint8_t[]> secret_key_;
    size_t secret_key_len_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_HKDF_H_
