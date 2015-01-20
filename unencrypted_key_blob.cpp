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

#include <keymaster/google_keymaster_utils.h>

#include "ae.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

class UnencryptedKeyBlob::AeCtx {
  public:
    AeCtx() : ctx_(ae_allocate(NULL)) {}
    ~AeCtx() {
        ae_clear(ctx_);
        ae_free(ctx_);
    }

    ae_ctx* get() { return ctx_; }

  private:
    ae_ctx* ctx_;
};

UnencryptedKeyBlob::UnencryptedKeyBlob(const AuthorizationSet& enforced,
                                       const AuthorizationSet& unenforced,
                                       const AuthorizationSet& hidden,
                                       const uint8_t* unencrypted_key,
                                       size_t unencrypted_key_length, const uint8_t* master_key,
                                       size_t master_key_length, const uint8_t nonce[NONCE_LENGTH])
    : KeyBlob(enforced, unenforced), hidden_(hidden) {
    // Check that KeyBlob ctor succeeded.
    if (error_ != KM_ERROR_OK)
        return;

    if (hidden_.is_valid() == AuthorizationSet::ALLOCATION_FAILURE) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }

    if (hidden_.is_valid() != AuthorizationSet::OK) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return;
    }

    unencrypted_key_material_.reset(new uint8_t[unencrypted_key_length]);
    if (!unencrypted_key_material_.get()) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }

    unencrypted_key_material_length_ = unencrypted_key_length;
    memcpy(unencrypted_key_material_.get(), unencrypted_key, unencrypted_key_length);
    EncryptKey(master_key, master_key_length, nonce);
}

UnencryptedKeyBlob::UnencryptedKeyBlob(const keymaster_key_blob_t& key,
                                       const AuthorizationSet& hidden, const uint8_t* master_key,
                                       size_t master_key_length)
    : KeyBlob(key), hidden_(hidden) {
    // Check that KeyBlob ctor succeeded.
    if (error_ != KM_ERROR_OK)
        return;
    DecryptKey(master_key, master_key_length);
}

void UnencryptedKeyBlob::EncryptKey(const uint8_t* master_key, size_t master_key_length,
                                    const uint8_t* nonce) {
    UniquePtr<AeCtx> ctx(InitializeKeyWrappingContext(master_key, master_key_length));
    if (error_ != KM_ERROR_OK)
        return;

    UniquePtr<uint8_t[]> encrypted_key_material(new uint8_t[unencrypted_key_material_length()]);
    UniquePtr<uint8_t[]> tag(new uint8_t[TAG_LENGTH]);
    UniquePtr<uint8_t[]> nonce_copy(new uint8_t[NONCE_LENGTH]);
    if (!encrypted_key_material.get() || !tag.get() || !nonce_copy.get()) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }
    memcpy(nonce_copy.get(), nonce, NONCE_LENGTH);

    int ae_err =
        ae_encrypt(ctx->get(), nonce, unencrypted_key_material(), unencrypted_key_material_length(),
                   NULL /* additional data */, 0 /* additional data length */,
                   encrypted_key_material.get(), tag.get(), 1 /* final */);
    if (ae_err < 0) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return;
    }
    assert(ae_err == static_cast<int>(unencrypted_key_material_length()));

    SetEncryptedKey(encrypted_key_material.release(), unencrypted_key_material_length(),
                    nonce_copy.release(), tag.release());
}

void UnencryptedKeyBlob::DecryptKey(const uint8_t* master_key, size_t master_key_length) {
    UniquePtr<AeCtx> ctx(InitializeKeyWrappingContext(master_key, master_key_length));
    if (error_ != KM_ERROR_OK)
        return;

    unencrypted_key_material_length_ = key_material_length();
    unencrypted_key_material_.reset(new uint8_t[unencrypted_key_material_length_]);
    int ae_err = ae_decrypt(ctx->get(), nonce(), encrypted_key_material(), key_material_length(),
                            NULL /* additional data */, 0 /* additional data length */,
                            unencrypted_key_material_.get(), tag(), 1 /* final */);
    if (ae_err == AE_INVALID) {
        // Authentication failed!  Decryption probably succeeded(ish), but we don't want to return
        // any data when the authentication fails, so clear it.
        memset_s(unencrypted_key_material_.get(), 0, unencrypted_key_material_length());
        error_ = KM_ERROR_INVALID_KEY_BLOB;
        return;
    } else if (ae_err < 0) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return;
    }
    assert(ae_err == static_cast<int>(unencrypted_key_material_length()));
    error_ = KM_ERROR_OK;
}

UnencryptedKeyBlob::AeCtx*
UnencryptedKeyBlob::InitializeKeyWrappingContext(const uint8_t* master_key,
                                                 size_t master_key_length) {
    size_t derivation_data_length;
    UniquePtr<const uint8_t[]> derivation_data(BuildDerivationData(&derivation_data_length));
    if (derivation_data.get() == NULL) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    UniquePtr<AeCtx> ctx(new AeCtx);

    SHA256_CTX sha256_ctx;
    UniquePtr<uint8_t[]> hash_buf(new uint8_t[SHA256_DIGEST_LENGTH]);
    Eraser hash_eraser(hash_buf.get(), SHA256_DIGEST_LENGTH);
    UniquePtr<uint8_t[]> derived_key(new uint8_t[AES_BLOCK_SIZE]);
    Eraser derived_key_eraser(derived_key.get(), AES_BLOCK_SIZE);

    if (ctx.get() == NULL || hash_buf.get() == NULL || derived_key.get() == NULL) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
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
    if (AES_set_encrypt_key(master_key, master_key_length * 8, &aes_key) != 0) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }
    AES_encrypt(hash_buf.get(), derived_key.get(), &aes_key);

    // Set up AES OCB context using derived key.
    if (ae_init(ctx->get(), derived_key.get(), AES_BLOCK_SIZE /* key length */, NONCE_LENGTH,
                TAG_LENGTH) == AE_SUCCESS)
        return ctx.release();
    else {
        memset_s(ctx->get(), 0, ae_ctx_sizeof());
        return NULL;
    }
}

const uint8_t* UnencryptedKeyBlob::BuildDerivationData(size_t* derivation_data_length) const {
    *derivation_data_length =
        hidden_.SerializedSize() + enforced().SerializedSize() + unenforced().SerializedSize();
    uint8_t* derivation_data = new uint8_t[*derivation_data_length];
    if (derivation_data != NULL) {
        uint8_t* buf = derivation_data;
        uint8_t* end = derivation_data + *derivation_data_length;
        buf = hidden_.Serialize(buf, end);
        buf = enforced().Serialize(buf, end);
        buf = unenforced().Serialize(buf, end);
    }
    return derivation_data;
}

}  // namespace keymaster
