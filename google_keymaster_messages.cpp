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

#include "google_keymaster_messages.h"

namespace keymaster {

GenerateKeyResponse::~GenerateKeyResponse() { delete[] key_blob.key_material; }

size_t GenerateKeyResponse::SerializedSize() const {
    if (error == KM_ERROR_OK) {
        return sizeof(int32_t) /* error */ + sizeof(uint32_t) /* key size */ +
               key_blob.key_material_size + sizeof(uint32_t) /* enforced size */ +
               enforced.SerializedSize() + sizeof(uint32_t) /* unenforced size */ +
               unenforced.SerializedSize();
    } else {
        return sizeof(error);
    }
}

uint8_t* GenerateKeyResponse::Serialize(uint8_t* buf, const uint8_t* end) const {
    buf = append_to_buf(buf, end, static_cast<int32_t>(error));
    if (error == KM_ERROR_OK) {
        buf = append_size_and_data_to_buf(buf, end, key_blob.key_material,
                                          key_blob.key_material_size);
        buf = append_to_buf(buf, end, static_cast<uint32_t>(enforced.SerializedSize()));
        buf = enforced.Serialize(buf, end);
        buf = append_to_buf(buf, end, static_cast<uint32_t>(unenforced.SerializedSize()));
        buf = unenforced.Serialize(buf, end);
    };
    return buf;
}

bool GenerateKeyResponse::Deserialize(const uint8_t** buf, const uint8_t* end) {
    delete[] key_blob.key_material;

    if (!copy_from_buf(buf, end, &error))
        return false;

    if (end == *buf)
        // Nothing but an error
        return true;

    uint32_t key_material_size;
    if (!copy_from_buf(buf, end, &key_material_size) || end - *buf < key_material_size)
        return false;

    key_blob.key_material = new uint8_t[key_material_size];
    key_blob.key_material_size = key_material_size;

    if (key_blob.key_material == NULL ||
        !copy_from_buf(buf, end, key_blob.key_material, key_blob.key_material_size))
        return false;

    uint32_t enforced_size;
    if (!copy_from_buf(buf, end, &enforced_size) || end - *buf < enforced_size ||
        !enforced.Deserialize(buf, *buf + enforced_size))
        return false;

    uint32_t unenforced_size;
    if (!copy_from_buf(buf, end, &unenforced_size) || end - *buf < unenforced_size ||
        !unenforced.Deserialize(buf, *buf + unenforced_size))
        return false;

    return true;
}

}  // namespace keymaster
