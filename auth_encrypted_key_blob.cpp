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

#include "auth_encrypted_key_blob.h"

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/authorization_set.h>
#include <keymaster/logger.h>

#include "ocb_utils.h"

namespace keymaster {

const uint32_t CURRENT_BLOB_VERSION = 0;

keymaster_error_t SerializeAuthEncryptedBlob(const KeymasterKeyBlob& encrypted_key_material,
                                             const AuthorizationSet& hw_enforced,
                                             const AuthorizationSet& sw_enforced,

                                             const Buffer& nonce, const Buffer& tag,
                                             KeymasterKeyBlob* key_blob) {
    size_t size = 1 /* version byte */ + nonce.SerializedSize() +
                  encrypted_key_material.SerializedSize() + tag.SerializedSize() +
                  hw_enforced.SerializedSize() + sw_enforced.SerializedSize();

    if (!key_blob->Reset(size))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    uint8_t* buf = key_blob->writable_data();
    const uint8_t* end = key_blob->key_material + key_blob->key_material_size;

    *buf++ = CURRENT_BLOB_VERSION;
    buf = nonce.Serialize(buf, end);
    buf = encrypted_key_material.Serialize(buf, end);
    buf = tag.Serialize(buf, end);
    buf = hw_enforced.Serialize(buf, end);
    buf = sw_enforced.Serialize(buf, end);
    if (buf != key_blob->key_material + key_blob->key_material_size)
        return KM_ERROR_UNKNOWN_ERROR;

    return KM_ERROR_OK;
}

keymaster_error_t DeserializeAuthEncryptedBlob(const KeymasterKeyBlob& key_blob,
                                               KeymasterKeyBlob* encrypted_key_material,
                                               AuthorizationSet* hw_enforced,
                                               AuthorizationSet* sw_enforced, Buffer* nonce,
                                               Buffer* tag) {
    const uint8_t* tmp = key_blob.key_material;
    const uint8_t** buf_ptr = &tmp;
    const uint8_t* end = tmp + key_blob.key_material_size;

    uint8_t version = *(*buf_ptr)++;
    if (version != CURRENT_BLOB_VERSION ||  //
        !nonce->Deserialize(buf_ptr, end) || nonce->available_read() != OCB_NONCE_LENGTH ||
        !encrypted_key_material->Deserialize(buf_ptr, end) ||  //
        !tag->Deserialize(buf_ptr, end) || tag->available_read() != OCB_TAG_LENGTH ||
        !hw_enforced->Deserialize(buf_ptr, end) ||  //
        !sw_enforced->Deserialize(buf_ptr, end))
        return KM_ERROR_INVALID_KEY_BLOB;
    return KM_ERROR_OK;
}

}  // namespace keymaster
