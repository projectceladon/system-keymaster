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

#include "serializable.h"

namespace keymaster {

uint8_t* append_to_buf(uint8_t* buf, const uint8_t* end, const void* data, size_t data_len) {
    if (buf + data_len <= end)
        memcpy(buf, data, data_len);
    return buf + data_len;
}

bool copy_from_buf(const uint8_t** buf_ptr, const uint8_t* end, void* dest, size_t size) {
    if (end < *buf_ptr + size)
        return false;
    memcpy(dest, *buf_ptr, size);
    *buf_ptr += size;
    return true;
}

bool copy_size_and_data_from_buf(const uint8_t** buf_ptr, const uint8_t* end, size_t* size,
                                 UniquePtr<uint8_t[]>* dest) {
    if (!copy_uint32_from_buf(buf_ptr, end, size) || *buf_ptr + *size > end) {
        return false;
    }
    if (*size == 0) {
        dest->reset();
        return true;
    }
    dest->reset(new uint8_t[*size]);
    if (dest->get() == NULL)
        return false;
    return copy_from_buf(buf_ptr, end, dest->get(), *size);
}

}  // namespace keymaster
