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

#include "aead_mode_operation.h"
#include "ocb_utils.h"
#include "operation.h"

namespace keymaster {

class AesOcbOperation : public AeadModeOperation {
  public:
    static const size_t NONCE_LENGTH = 12;
    static const size_t MAX_TAG_LENGTH = 16;
    static const size_t MAX_KEY_LENGTH = 32;

    AesOcbOperation(keymaster_purpose_t purpose, const Logger& logger, const uint8_t* key,
                    size_t key_size, size_t chunk_length, size_t tag_length,
                    keymaster_blob_t additional_data)
        : AeadModeOperation(purpose, logger, key, key_size, chunk_length, tag_length, NONCE_LENGTH,
                            additional_data) {}

    virtual keymaster_error_t Abort() {
        /* All cleanup is in the dtor */
        return KM_ERROR_OK;
    }

  protected:
    ae_ctx* ctx() { return ctx_.get(); }

  private:
    virtual keymaster_error_t Initialize(uint8_t* key, size_t key_size, size_t nonce_length,
                                         size_t tag_length);
    virtual keymaster_error_t EncryptChunk(const uint8_t* nonce, size_t nonce_length,
                                           size_t tag_length,
                                           const keymaster_blob_t additional_data, uint8_t* chunk,
                                           size_t chunk_size, Buffer* output);
    virtual keymaster_error_t DecryptChunk(const uint8_t* nonce, size_t nonce_length,
                                           const uint8_t* tag, size_t tag_length,
                                           const keymaster_blob_t additional_data, uint8_t* chunk,
                                           size_t chunk_size, Buffer* output);
    AeCtx ctx_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_AES_OPERATION_H_
