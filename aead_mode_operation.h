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

#ifndef SYSTEM_KEYMASTER_AEAD_MODE_OPERATION_H_
#define SYSTEM_KEYMASTER_AEAD_MODE_OPERATION_H_

#include "operation.h"

namespace keymaster {

class AeadModeOperation : public Operation {
  public:
    static const size_t MAX_CHUNK_LENGTH = 64 * 1024;
    static const size_t MAX_NONCE_LENGTH = 12;
    static const size_t MAX_TAG_LENGTH = 16;
    static const size_t MAX_KEY_LENGTH = 32;

    AeadModeOperation(keymaster_purpose_t purpose, const uint8_t* key, size_t key_size,
                      size_t chunk_length, size_t tag_length, size_t nonce_length,
                      bool caller_nonce)
        : Operation(purpose), key_size_(key_size), tag_length_(tag_length),
          nonce_length_(nonce_length),
          processing_unit_(purpose == KM_PURPOSE_DECRYPT ? chunk_length + tag_length
                                                         : chunk_length),
          caller_nonce_(caller_nonce) {
        assert(key_size <= MAX_KEY_LENGTH);
        memcpy(key_, key, key_size);
    }
    ~AeadModeOperation() {
        // Wipe sensitive buffers.
        memset_s(buffer_.get(), 0, processing_unit_);
        memset_s(key_, 0, MAX_KEY_LENGTH);
    }

    virtual keymaster_error_t Begin(const AuthorizationSet& input_params,
                                    AuthorizationSet* output_params);
    virtual keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                                     Buffer* output, size_t* input_consumed);
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);

  protected:
    size_t buffered_data_length() const { return buffer_end_; }
    const uint8_t* key() const { return key_; }
    size_t key_size() const { return key_size_; }

  private:
    /*
     * These methods do the actual crypto operations.
     *
     * TODO(swillden): Consider refactoring these to a separate class, integrating them via
     * composition rather than inheritance.
     */
    virtual keymaster_error_t Initialize(uint8_t* key, size_t key_size, size_t nonce_length,
                                         size_t tag_length) = 0;
    virtual keymaster_error_t EncryptChunk(const uint8_t* nonce, size_t nonce_length,
                                           size_t tag_length,
                                           const keymaster_blob_t additional_data, uint8_t* chunk,
                                           size_t chunk_size, Buffer* output) = 0;
    virtual keymaster_error_t DecryptChunk(const uint8_t* nonce, size_t nonce_length,
                                           const uint8_t* tag, size_t tag_length,
                                           const keymaster_blob_t additional_data, uint8_t* chunk,
                                           size_t chunk_size, Buffer* output) = 0;

    size_t EstimateOutputSize(const Buffer& input, Buffer* output);
    keymaster_error_t ProcessChunk(const keymaster_blob_t& associated_data, Buffer* output);

    size_t buffer_free_space() const { return processing_unit_ - buffer_end_; }

    const uint8_t* AppendToBuffer(const uint8_t* data, size_t data_length);
    void ExtractTagFromBuffer();
    void ClearBuffer() { buffer_end_ = 0; }
    keymaster_error_t HandleNonce(const AuthorizationSet& input_params,
                                  AuthorizationSet* output_params);
    keymaster_error_t ExtractNonce(const AuthorizationSet& input_params);
    keymaster_error_t GenerateNonce();
    void IncrementNonce();

    const size_t key_size_;
    const size_t tag_length_;
    const size_t nonce_length_;
    const size_t processing_unit_;
    const bool caller_nonce_;
    UniquePtr<uint8_t[]> buffer_;
    size_t buffer_end_;
    uint8_t __attribute__((aligned(16))) key_[MAX_KEY_LENGTH];
    uint8_t __attribute__((aligned(16))) tag_[MAX_TAG_LENGTH];
    uint8_t __attribute__((aligned(16))) nonce_[MAX_NONCE_LENGTH];
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_AEAD_MODE_OPERATION_H_
