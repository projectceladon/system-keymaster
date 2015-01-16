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

#include <openssl/aes.h>
#include <openssl/rand.h>

#include "aes_operation.h"

namespace keymaster {

keymaster_error_t AesOcbEncryptOperation::Begin() {
    chunk_.reset(new uint8_t[chunk_length_]);
    if (!chunk_.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!RAND_bytes(nonce_, NONCE_LENGTH))
        return KM_ERROR_UNKNOWN_ERROR;

    if (ae_init(ctx_.get(), key_, key_size_, array_size(nonce_), tag_length_) != AE_SUCCESS) {
        memset_s(ctx_.get(), 0, ae_ctx_sizeof());
        return KM_ERROR_UNKNOWN_ERROR;
    }

    return KM_ERROR_OK;
}

keymaster_error_t AesOcbEncryptOperation::Update(const Buffer& input, Buffer* output,
                                                 size_t* input_consumed) {
    const uint8_t* plaintext = input.peek_read();
    const uint8_t* plaintext_end = plaintext + input.available_read();

    while (plaintext + chunk_unfilled_space() < plaintext_end) {
        size_t to_process = chunk_unfilled_space();
        memcpy(chunk_.get() + chunk_offset_, plaintext, to_process);
        chunk_offset_ += to_process;
        assert(chunk_offset_ == chunk_length_);

        keymaster_error_t error = ProcessChunk(output);
        if (error != KM_ERROR_OK)
            return error;
        plaintext += to_process;
    }

    // Copy remaining data into chunk_.
    assert(plaintext_end - plaintext < chunk_unfilled_space());
    memcpy(chunk_.get() + chunk_offset_, plaintext, plaintext_end - plaintext);
    chunk_offset_ += (plaintext_end - plaintext);

    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t AesOcbEncryptOperation::Finish(const Buffer& /* signature */, Buffer* output) {
    keymaster_error_t error = KM_ERROR_OK;
    if (chunk_offset_ > 0)
        error = ProcessChunk(output);
    return error;
}

keymaster_error_t AesOcbEncryptOperation::ProcessChunk(Buffer* output) {
    if (!nonce_written_) {
        if (!output->reserve(NONCE_LENGTH + chunk_length_ + tag_length_))
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        output->write(nonce_, NONCE_LENGTH);
        nonce_written_ = true;
    } else {
        IncrementNonce();
    }

    if (!output->reserve(output->available_read() + chunk_offset_ + tag_length_))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    int ae_err = ae_encrypt(ctx_.get(), nonce_, chunk_.get(), chunk_offset_, additional_data_.data,
                            additional_data_.data_length, output->peek_write(), tag_, AE_FINALIZE);
    if (ae_err < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    output->advance_write(chunk_offset_);
    chunk_offset_ = 0;

    // Output the tag.
    output->write(tag_, tag_length_);

    return KM_ERROR_OK;
}

void AesOcbEncryptOperation::IncrementNonce() {
    for (int i = NONCE_LENGTH - 1; i > 0; --i)
        if (++nonce_[i])
            break;
}

}  // namespace keymaster
