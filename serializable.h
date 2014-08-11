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

#ifndef SYSTEM_KEYMASTER_SERIALIZABLE_H_
#define SYSTEM_KEYMASTER_SERIALIZABLE_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cstddef>

namespace keymaster {

class Serializable {
  public:
    virtual ~Serializable() {}
    virtual size_t SerializedSize() const = 0;
    virtual uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const = 0;

    // Deserialize from the provided buffer, copying the data into newly-allocated storage.  Returns
    // true if successful, and advances *buf past the bytes read.
    virtual bool Deserialize(const uint8_t** buf, const uint8_t* end) = 0;
};

// Don't implement this, so that accidentally passing a pointer arg causes link error.
template <typename T> uint8_t* append_to_buf(uint8_t* buf, const uint8_t* end, T* ptr);

template <typename T> inline uint8_t* append_to_buf(uint8_t* buf, const uint8_t* end, T value) {
    if (buf + sizeof(value) <= end)
        memcpy(buf, &value, sizeof(value));
    return buf + sizeof(value);
}

inline uint8_t* append_to_buf(uint8_t* buf, const uint8_t* end, const void* data, size_t data_len) {
    if (buf + data_len <= end)
        memcpy(buf, data, data_len);
    return buf + data_len;
}

inline uint8_t* append_size_and_data_to_buf(uint8_t* buf, const uint8_t* end, const void* data,
                                            size_t data_len) {
    buf = append_to_buf(buf, end, static_cast<uint32_t>(data_len));
    return append_to_buf(buf, end, data, data_len);
}

bool copy_from_buf(const uint8_t** buf, const uint8_t* end, void* dest, size_t size);

// Allocates dest.
bool copy_size_and_data_from_buf(const uint8_t** buf, const uint8_t* end, size_t* size,
                                 uint8_t** dest);

template <typename T> inline bool copy_from_buf(const uint8_t** buf, const uint8_t* end, T* value) {
    return copy_from_buf(buf, end, static_cast<void*>(value), sizeof(T));
}

template <typename T> inline bool copy_from_buf(uint8_t** buf, const uint8_t* end, T* value) {
    return copy_from_buf(const_cast<const uint8_t**>(buf), end, static_cast<void*>(value),
                         sizeof(T));
}

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_SERIALIZABLE_H_
