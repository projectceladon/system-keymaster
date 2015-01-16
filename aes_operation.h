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

#ifndef SYSTEM_KEYMASTER_AES_OPERATION_H_
#define SYSTEM_KEYMASTER_AES_OPERATION_H_

#include <keymaster/key_blob.h>

#include "ocb_utils.h"
#include "operation.h"

namespace keymaster {

class AesOcbEncryptOperation : public Operation {
  public:
    static const size_t NONCE_LENGTH = 12;
    static const size_t MAX_TAG_LENGTH = 16;
    static const size_t MAX_KEY_LENGTH = 32;

    AesOcbEncryptOperation(const Logger& logger, uint8_t* key, size_t key_size, size_t chunk_length,
                           size_t tag_length, keymaster_blob_t additional_data)
        : Operation(KM_PURPOSE_ENCRYPT, logger), key_size_(key_size), chunk_length_(chunk_length),
          chunk_offset_(0), tag_length_(tag_length), additional_data_(additional_data),
          nonce_written_(false) {
        assert(key_size <= MAX_KEY_LENGTH);
        memcpy(key_, key, key_size);
    }
    ~AesOcbEncryptOperation() {
        // Wipe sensitive buffers.
        memset_s(chunk_.get(), 0, chunk_length_);
        memset_s(const_cast<uint8_t*>(additional_data_.data), 0, additional_data_.data_length);
        memset_s(key_, 0, MAX_KEY_LENGTH);
        memset_s(tag_, 0, MAX_TAG_LENGTH);
        delete[] additional_data_.data;
    }

    virtual keymaster_error_t Begin();
    virtual keymaster_error_t Update(const Buffer& input, Buffer* output, size_t* input_consumed);
    virtual keymaster_error_t Finish(const Buffer& /* signature */, Buffer* output);
    virtual keymaster_error_t Abort() { return KM_ERROR_UNIMPLEMENTED; }

  private:
    ptrdiff_t chunk_unfilled_space() { return chunk_length_ - chunk_offset_; }

    keymaster_error_t StartIncrementalEncryption();
    keymaster_error_t DoIncrementalEncryption(const uint8_t* input, size_t input_size,
                                              Buffer* output, size_t* input_consumed);
    keymaster_error_t ProcessChunk(Buffer* output);
    void IncrementNonce();

    AeCtx ctx_;
    size_t key_size_;
    size_t chunk_length_;
    UniquePtr<uint8_t[]> chunk_;
    size_t chunk_offset_;
    size_t tag_length_;
    keymaster_blob_t additional_data_;
    uint8_t __attribute__((aligned(16))) key_[MAX_KEY_LENGTH];
    uint8_t __attribute__((aligned(16))) nonce_[NONCE_LENGTH];
    bool nonce_written_;
    uint8_t __attribute__((aligned(16))) tag_[MAX_TAG_LENGTH];
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_AES_OPERATION_H_
