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

#ifndef SYSTEM_KEYMASTER_HMAC_OPERATION_H_
#define SYSTEM_KEYMASTER_HMAC_OPERATION_H_

#include "operation.h"

#include <openssl/hmac.h>

namespace keymaster {

class HmacOperation : public Operation {
  public:
    HmacOperation(keymaster_purpose_t purpose, const Logger& logger, const uint8_t* key_data,
                  size_t key_data_size, keymaster_digest_t digest, size_t tag_length);
    ~HmacOperation();

    virtual keymaster_error_t Begin(const AuthorizationSet& input_params,
                                    AuthorizationSet* output_params);
    virtual keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                                     Buffer* output, size_t* input_consumed);
    virtual keymaster_error_t Abort();
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);

  private:
    HMAC_CTX ctx_;
    keymaster_error_t error_;
    const size_t tag_length_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_HMAC_OPERATION_H_
