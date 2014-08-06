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

bool copy_from_buf(const uint8_t** buf, const uint8_t* end, void* dest, size_t size) {
    if (end < *buf + size)
        return false;
    memcpy(dest, *buf, size);
    *buf += size;
    return true;
}

}  // namespace keymaster
