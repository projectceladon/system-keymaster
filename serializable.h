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

namespace keymaster {

class Serializable {
  public:
    virtual ~Serializable() {}
    virtual size_t SerializedSize() const = 0;
    virtual uint8_t* Serialize(uint8_t* buf) const = 0;

    // Deserialize from the provided buffer, using the buffer directly rather than making copies.
    // Serializable objects that are deserialized this way must not live longer than their buffers.
    // Serializables that can't or don't want to support inplace should just return false.
    //
    // Callers should *not* assume that modifications to the buffer will be reflected in the
    // deserialized object, or that the object will avoid modifying the buffer.  Whether and when
    // the buffer is modified is an implementation detil of the Serializable subclass.
    //
    // *buf is advanced as the data is read, so callers can sequence deserialization calls
    // to parse a sequence of deserializable objects.  For the same reason, end is a pointer
    // to one past the end of the buffer rather than a size, so that sequences of calls can
    // pass the same value, rather than having to update a size as data is consumed.
    //
    // Returns true if deserialization was successful.  If false is returned, no guarantees
    // are made about the state of the deserialized object. In general, it should not be used.
    // In addition, no guarantees are made about the value of *buf.
    virtual bool DeserializeInPlace(uint8_t** buf, const uint8_t* end) = 0;

    // Deserialize from the provided buffer, copying the data into newly-allocated storage.  Returns
    // true if successful, and advances *buf past the bytes read.
    virtual bool DeserializeToCopy(const uint8_t** buf, const uint8_t* end) = 0;
};

template <typename T> inline uint8_t* append_to_buf(uint8_t* buf, T value) {
    memcpy(buf, &value, sizeof(value));
    return buf + sizeof(value);
}

inline uint8_t* append_to_buf(uint8_t* buf, const void* data, size_t data_len) {
    memcpy(buf, data, data_len);
    return buf + data_len;
}

inline uint8_t* append_size_and_data_to_buf(uint8_t* buf, const void* data, size_t data_len) {
    buf = append_to_buf(buf, static_cast<uint32_t>(data_len));
    return append_to_buf(buf, data, data_len);
}

bool copy_from_buf(const uint8_t** buf, const uint8_t* end, void* dest, size_t size);

template <typename T> inline bool copy_from_buf(const uint8_t** buf, const uint8_t* end, T* value) {
    return copy_from_buf(buf, end, static_cast<void*>(value), sizeof(T));
}

template <typename T> inline bool copy_from_buf(uint8_t** buf, const uint8_t* end, T* value) {
    return copy_from_buf(const_cast<const uint8_t**>(buf), end, static_cast<void*>(value),
                         sizeof(T));
}

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_SERIALIZABLE_H_
