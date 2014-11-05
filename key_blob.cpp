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

#include <assert.h>

#include <keymaster/google_keymaster_utils.h>
#include <keymaster/key_blob.h>

namespace keymaster {

const size_t KeyBlob::NONCE_LENGTH;
const size_t KeyBlob::TAG_LENGTH;

KeyBlob::KeyBlob(const keymaster_key_blob_t& key_blob)
    : error_(KM_ERROR_OK), nonce_(new uint8_t[NONCE_LENGTH]), tag_(new uint8_t[TAG_LENGTH]) {
    if (!nonce_.get() || !tag_.get()) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }
    error_ = KM_ERROR_OK;

    const uint8_t* key_material = key_blob.key_material;
    if (!Deserialize(&key_material, key_blob.key_material + key_blob.key_material_size))
        return;
}

size_t KeyBlob::SerializedSize() const {
    return NONCE_LENGTH + sizeof(uint32_t) + key_material_length() + TAG_LENGTH +
           enforced_.SerializedSize() + unenforced_.SerializedSize();
}

uint8_t* KeyBlob::Serialize(uint8_t* buf, const uint8_t* end) const {
    const uint8_t* start = buf;
    buf = append_to_buf(buf, end, nonce(), NONCE_LENGTH);
    buf = append_size_and_data_to_buf(buf, end, encrypted_key_material(), key_material_length());
    buf = append_to_buf(buf, end, tag(), TAG_LENGTH);
    buf = enforced_.Serialize(buf, end);
    buf = unenforced_.Serialize(buf, end);
    assert(buf - start == static_cast<ptrdiff_t>(SerializedSize()));
    return buf;
}

bool KeyBlob::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    if (!copy_from_buf(buf_ptr, end, nonce_.get(), NONCE_LENGTH) ||
        !copy_size_and_data_from_buf(buf_ptr, end, &key_material_length_,
                                     &encrypted_key_material_) ||
        !copy_from_buf(buf_ptr, end, tag_.get(), TAG_LENGTH) ||
        !enforced_.Deserialize(buf_ptr, end) || !unenforced_.Deserialize(buf_ptr, end)) {
        error_ = KM_ERROR_INVALID_KEY_BLOB;
        return false;
    }
    return ExtractKeyCharacteristics();
}

KeyBlob::KeyBlob(const AuthorizationSet& enforced, const AuthorizationSet& unenforced)
    : error_(KM_ERROR_OK), enforced_(enforced), unenforced_(unenforced) {
}

void KeyBlob::SetEncryptedKey(uint8_t* encrypted_key_material, size_t encrypted_key_material_length,
                              uint8_t* nonce, uint8_t* tag) {
    ClearKeyData();
    encrypted_key_material_.reset(encrypted_key_material);
    key_material_length_ = encrypted_key_material_length;
    nonce_.reset(nonce);
    tag_.reset(tag);
}

bool KeyBlob::ExtractKeyCharacteristics() {
    if (!enforced_.GetTagValue(TAG_ALGORITHM, &algorithm_) &&
        !unenforced_.GetTagValue(TAG_ALGORITHM, &algorithm_)) {
        error_ = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return false;
    }
    if (!enforced_.GetTagValue(TAG_KEY_SIZE, &key_size_bits_) &&
        !unenforced_.GetTagValue(TAG_KEY_SIZE, &key_size_bits_)) {
        error_ = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return false;
    }
    return true;
}

}  // namespace keymaster
