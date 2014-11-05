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

#ifndef SYSTEM_KEYMASTER_KEY_BLOB_H_
#define SYSTEM_KEYMASTER_KEY_BLOB_H_

#include <cstddef>

#include <stdint.h>

#include <UniquePtr.h>

#include <keymaster/authorization_set.h>
#include <keymaster/google_keymaster_utils.h>
#include <keymaster/keymaster_defs.h>
#include <keymaster/serializable.h>

namespace keymaster {

/**
 * This class represents a Keymaster key blob, including authorization sets and encrypted key
 * material.  It serializes and deserializes blob arrays, and provides access to the data in the
 * blob.
 */
class KeyBlob : public Serializable {
  public:
    static const size_t NONCE_LENGTH = 12;
    static const size_t TAG_LENGTH = 128 / 8;

    /**
     * Create a KeyBlob, extracting the enforced and unenforced sets.  The KeyBlob does *not* take
     * ownership of \p key_blob.
     *
     * IMPORTANT: After constructing a KeyBlob, call error() to verify that the blob is usable.
     */
    KeyBlob(const uint8_t* key_blob, size_t key_blob_length);

    /**
     * Create a KeyBlob, extracting the enforced and unenforced sets.  The KeyBlob does *not* take
     * ownership of \p key_blob's contents.
     *
     * IMPORTANT: After constructing a KeyBlob, call error() to verify that the blob is usable.
     */
    KeyBlob(const keymaster_key_blob_t& key_blob);

    ~KeyBlob() {
        ClearKeyData();
        // AuthorizationSets clear themselves.
    }

    size_t SerializedSize() const;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const;
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end);

    /**
     * Returns KM_ERROR_OK if all is well, or an appropriate error code if there is a problem.  This
     * error code should be checked after construction or deserialization, and if it does not return
     * KM_ERROR_OK, then don't call any other methods.
     */
    inline keymaster_error_t error() { return error_; }

    inline const uint8_t* nonce() const { return nonce_.get(); }
    inline const uint8_t* encrypted_key_material() const { return encrypted_key_material_.get(); }
    inline size_t key_material_length() const { return key_material_length_; }
    inline const uint8_t* tag() const { return tag_.get(); }

    inline const AuthorizationSet& enforced() const { return enforced_; }
    inline const AuthorizationSet& unenforced() const { return unenforced_; }
    inline keymaster_algorithm_t algorithm() const { return algorithm_; }
    inline size_t key_size_bits() const { return key_size_bits_; }

  protected:
    /**
     * Create a KeyBlob containing the specified authorization data.
     *
     * IMPORTANT: After constructing a KeyBlob, call error() to verify that the blob is usable.
     */
    KeyBlob(const AuthorizationSet& enforced, const AuthorizationSet& unenforced);

    /**
     * Set encrypted key and supporting nonce and tag.  Takes ownership of all arguments.
     */
    void SetEncryptedKey(uint8_t* encrypted_key_material, size_t encrypted_key_material_length,
                         uint8_t* nonce, uint8_t* tag);

    keymaster_error_t error_;

  private:
    void ClearKeyData() {
        // None of these are sensitive, but clear them anyway.
        if (encrypted_key_material_.get())
            memset_s(encrypted_key_material_.get(), 0, key_material_length_);
        if (nonce_.get())
            memset_s(nonce_.get(), 0, NONCE_LENGTH);
        if (tag_.get())
            memset_s(tag_.get(), 0, TAG_LENGTH);
    }

    bool DeserializeUnversionedBlob(const uint8_t** buf_ptr, const uint8_t* end);

    bool ExtractKeyCharacteristics();

    UniquePtr<uint8_t[]> nonce_;
    UniquePtr<uint8_t[]> encrypted_key_material_;
    UniquePtr<uint8_t[]> tag_;
    size_t key_material_length_;
    AuthorizationSet enforced_;
    AuthorizationSet unenforced_;
    keymaster_algorithm_t algorithm_;
    uint32_t key_size_bits_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_KEY_BLOB_H_
