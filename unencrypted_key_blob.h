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

#ifndef SYSTEM_KEYMASTER_UNENCRYPTED_KEY_BLOB_H_
#define SYSTEM_KEYMASTER_UNENCRYPTED_KEY_BLOB_H_

#include <keymaster/key_blob.h>

namespace keymaster {

class AeCtx;

/**
 * Extends KeyBlob to provide access the the unencrypted key material as well as the encrypted form.
 */
class UnencryptedKeyBlob : public KeyBlob {
  public:
    /**
     * Create a UnencryptedKeyBlob containing the specified authorization data and key material.  \p
     * key will be encrypted with a key derived from \p master_key, using OCB authenticated
     * encryption with \p nonce.  It is critically important that nonces NEVER be reused.  The most
     * convenient way to accomplish that is to choose them randomly.
     *
     * IMPORTANT: After constructing a UnencryptedKeyBlob, call error() to verify that the blob is
     * usable.
     */
    UnencryptedKeyBlob(const AuthorizationSet& enforced, const AuthorizationSet& unenforced,
                       const AuthorizationSet& hidden, const uint8_t* unencrypted_key,
                       size_t unencrypted_key_length, const uint8_t* master_key,
                       size_t master_key_length, const uint8_t nonce[NONCE_LENGTH]);

    /**
     * Create a UnencryptedKeyBlob, extracting the enforced and unenforced sets and decrypting the
     * key.  The KeyBlob does *not* take ownership of key_blob.
     *
     * IMPORTANT: After constructing a UnencryptedKeyBlob, call error() to verify that the blob is
     * usable.
     */
    UnencryptedKeyBlob(const keymaster_key_blob_t& key_blob, const AuthorizationSet& hidden,
                       const uint8_t* master_key, size_t master_key_length);

    inline const uint8_t* unencrypted_key_material() const {
        return unencrypted_key_material_.get();
    }
    inline size_t unencrypted_key_material_length() const {
        return unencrypted_key_material_length_;
    }
    inline const AuthorizationSet& hidden() const { return hidden_; }

  private:
    void DecryptKey(const uint8_t* master_key, size_t master_key_length);
    void EncryptKey(const uint8_t* master_key, size_t master_key_length, const uint8_t* nonce);

    /**
     * Create an AES_OCB context initialized with a key derived using \p master_key and the
     * authorizations.
     */
    AeCtx* InitializeKeyWrappingContext(const uint8_t* master_key, size_t master_key_length);

    const uint8_t* BuildDerivationData(size_t* derivation_data_len) const;

    UniquePtr<uint8_t[]> unencrypted_key_material_;
    size_t unencrypted_key_material_length_;
    AuthorizationSet hidden_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_UNENCRYPTED_KEY_BLOB_H_
