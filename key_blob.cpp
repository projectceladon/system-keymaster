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

#include <openssl/aes.h>
#include <openssl/sha.h>

#include "ae.h"
#include "key_blob.h"
#include "google_keymaster_utils.h"

namespace keymaster {

struct AeCtxDelete {
    void operator()(ae_ctx* p) {
        ae_clear(p);
        ae_free(p);
    }
};

const size_t KeyBlob::NONCE_LENGTH;
const size_t KeyBlob::TAG_LENGTH;

KeyBlob::KeyBlob(const AuthorizationSet& enforced, const AuthorizationSet& unenforced,
                 const AuthorizationSet& hidden, const keymaster_key_blob_t& key,
                 const keymaster_key_blob_t& master_key, uint8_t nonce[NONCE_LENGTH])
    : error_(KM_ERROR_OK), enforced_(enforced), unenforced_(unenforced), hidden_(hidden) {
    if (enforced_.is_valid() == AuthorizationSet::ALLOCATION_FAILURE ||
        unenforced_.is_valid() == AuthorizationSet::ALLOCATION_FAILURE) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }

    if (enforced_.is_valid() != AuthorizationSet::OK ||
        unenforced_.is_valid() != AuthorizationSet::OK) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return;
    }

    memcpy(nonce_, nonce, NONCE_LENGTH);

    key_material_length_ = key.key_material_size;
    key_material_.reset(new uint8_t[key_material_length_]);
    encrypted_key_material_.reset(new uint8_t[key_material_length_]);

    if (key_material_.get() == NULL || encrypted_key_material_.get() == NULL) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }

    memcpy(key_material_.get(), key.key_material, key_material_length_);
    EncryptKey(master_key);
}

KeyBlob::KeyBlob(const keymaster_key_blob_t& key, const AuthorizationSet& hidden,
                 const keymaster_key_blob_t& master_key)
    : hidden_(hidden) {
    if (!Deserialize(const_cast<const uint8_t**>(&(key.key_material)),
                     key.key_material + key.key_material_size))
        return;
    DecryptKey(master_key);
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

bool KeyBlob::Deserialize(const uint8_t** buf, const uint8_t* end) {
    uint8_t* tmp_key_ptr = NULL;

    if (!copy_from_buf(buf, end, nonce_, NONCE_LENGTH) ||
        !copy_size_and_data_from_buf(buf, end, &key_material_length_, &tmp_key_ptr) ||
        !copy_from_buf(buf, end, tag_, TAG_LENGTH) || !enforced_.Deserialize(buf, end) ||
        !unenforced_.Deserialize(buf, end)) {
        if (tmp_key_ptr != NULL)
            delete[] tmp_key_ptr;
        error_ = KM_ERROR_INVALID_KEY_BLOB;
        return false;
    }

    encrypted_key_material_.reset(tmp_key_ptr);
    key_material_.reset(new uint8_t[key_material_length_]);
    return true;
}

void KeyBlob::EncryptKey(const keymaster_key_blob_t& master_key) {
    UniquePtr<ae_ctx, AeCtxDelete> ctx(InitializeKeyWrappingContext(master_key, &error_));
    if (error_ != KM_ERROR_OK)
        return;

    int ae_err = ae_encrypt(ctx.get(), nonce_, key_material(), key_material_length(),
                            NULL /* additional data */, 0 /* additional data length */,
                            encrypted_key_material_.get(), tag_, 1 /* final */);
    if (ae_err < 0) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return;
    }
    assert(ae_err == static_cast<int>(key_material_length_));
    error_ = KM_ERROR_OK;
}

void KeyBlob::DecryptKey(const keymaster_key_blob_t& master_key) {
    UniquePtr<ae_ctx, AeCtxDelete> ctx(InitializeKeyWrappingContext(master_key, &error_));
    if (error_ != KM_ERROR_OK)
        return;

    int ae_err = ae_decrypt(ctx.get(), nonce_, encrypted_key_material(), key_material_length(),
                            NULL /* additional data */, 0 /* additional data length */,
                            key_material_.get(), tag(), 1 /* final */);
    if (ae_err == AE_INVALID) {
        // Authentication failed!  Decryption probably succeeded(ish), but we don't want to return
        // any data when the authentication fails, so clear it.
        memset(key_material_.get(), 0, key_material_length());
        error_ = KM_ERROR_INVALID_KEY_BLOB;
        return;
    } else if (ae_err < 0) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return;
    }
    assert(ae_err == static_cast<int>(key_material_length_));
    error_ = KM_ERROR_OK;
}

ae_ctx* KeyBlob::InitializeKeyWrappingContext(const keymaster_key_blob_t& master_key,
                                              keymaster_error_t* error) const {
    size_t derivation_data_length;
    UniquePtr<const uint8_t[]> derivation_data(BuildDerivationData(&derivation_data_length));
    if (derivation_data.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    *error = KM_ERROR_OK;
    UniquePtr<ae_ctx, AeCtxDelete> ctx(ae_allocate(NULL));

    SHA256_CTX sha256_ctx;
    UniquePtr<uint8_t[]> hash_buf(new uint8_t[SHA256_DIGEST_LENGTH]);
    Eraser hash_eraser(hash_buf.get(), SHA256_DIGEST_LENGTH);
    UniquePtr<uint8_t[]> derived_key(new uint8_t[AES_BLOCK_SIZE]);
    Eraser derived_key_eraser(derived_key.get(), AES_BLOCK_SIZE);

    if (ctx.get() == NULL || hash_buf.get() == NULL || derived_key.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    Eraser sha256_ctx_eraser(sha256_ctx);

    // Hash derivation data.
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, derivation_data.get(), derivation_data_length);
    SHA256_Final(hash_buf.get(), &sha256_ctx);

    // Encrypt hash with master key to build derived key.
    AES_KEY aes_key;
    Eraser aes_key_eraser(AES_KEY);
    if (AES_set_encrypt_key(master_key.key_material, master_key.key_material_size * 8, &aes_key) !=
        0) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }
    AES_encrypt(hash_buf.get(), derived_key.get(), &aes_key);

    // Set up AES OCB context using derived key.
    if (ae_init(ctx.get(), derived_key.get(), AES_BLOCK_SIZE, NONCE_LENGTH, TAG_LENGTH) ==
        AE_SUCCESS)
        return ctx.release();
    else {
        memset(ctx.get(), 0, ae_ctx_sizeof());
        return NULL;
    }
}

const uint8_t* KeyBlob::BuildDerivationData(size_t* derivation_data_length) const {
    *derivation_data_length =
        hidden_.SerializedSize() + enforced_.SerializedSize() + unenforced_.SerializedSize();
    uint8_t* derivation_data = new uint8_t[*derivation_data_length];
    if (derivation_data != NULL) {
        uint8_t* buf = derivation_data;
        uint8_t* end = derivation_data + *derivation_data_length;
        buf = hidden_.Serialize(buf, end);
        buf = enforced_.Serialize(buf, end);
        buf = unenforced_.Serialize(buf, end);
    }
    return derivation_data;
}

}  // namespace keymaster
