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

#include <stdio.h>

#include <openssl/aes.h>
#include <openssl/rand.h>

#include "aes_operation.h"

namespace keymaster {

keymaster_error_t AesOcbOperation::Initialize(uint8_t* key, size_t key_size, size_t nonce_length,
                                              size_t tag_length) {
    if (tag_length > MAX_TAG_LENGTH ||nonce_length > MAX_NONCE_LENGTH)
        return KM_ERROR_INVALID_KEY_BLOB;

    if (ae_init(ctx(), key, key_size, nonce_length, tag_length) != AE_SUCCESS) {
        memset_s(ctx(), 0, ae_ctx_sizeof());
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t AesOcbOperation::EncryptChunk(const uint8_t* nonce, size_t /* nonce_length */,
                                                size_t tag_length,
                                                const keymaster_blob_t additional_data,
                                                uint8_t* chunk, size_t chunk_size, Buffer* output) {
    if (!ctx())
        return KM_ERROR_UNKNOWN_ERROR;
    uint8_t __attribute__((aligned(16))) tag[MAX_TAG_LENGTH];

    // Encrypt chunk in place.
    int ae_err = ae_encrypt(ctx(), nonce, chunk, chunk_size, additional_data.data,
                            additional_data.data_length, chunk, tag, AE_FINALIZE);

    if (ae_err < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(ae_err == (int)buffered_data_length());

    output->write(chunk, buffered_data_length());
    output->write(tag, tag_length);

    return KM_ERROR_OK;
}

keymaster_error_t AesOcbOperation::DecryptChunk(const uint8_t* nonce, size_t /* nonce_length */,
                                                const uint8_t* tag, size_t /* tag_length */,
                                                const keymaster_blob_t additional_data,
                                                uint8_t* chunk, size_t chunk_size, Buffer* output) {
    if (!ctx())
        return KM_ERROR_UNKNOWN_ERROR;

    // Decrypt chunk in place
    int ae_err = ae_decrypt(ctx(), nonce, chunk, chunk_size, additional_data.data,
                            additional_data.data_length, chunk, tag, AE_FINALIZE);
    if (ae_err == AE_INVALID)
        return KM_ERROR_VERIFICATION_FAILED;
    else if (ae_err < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(ae_err == (int)buffered_data_length());
    output->write(chunk, chunk_size);

    return KM_ERROR_OK;
}

}  // namespace keymaster
