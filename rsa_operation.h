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

#ifndef SYSTEM_KEYMASTER_RSA_OPERATION_H_
#define SYSTEM_KEYMASTER_RSA_OPERATION_H_

#include "openssl/evp.h"

#include "key_blob.h"
#include "operation.h"

namespace keymaster {

class RsaOperation : public Operation {
  public:
    RsaOperation(keymaster_purpose_t purpose, const KeyBlob& key);
    ~RsaOperation();

    virtual keymaster_error_t Begin() {
        // In this case, all of the actual intialization was done in the constructor.
        return error_;
    }
    virtual keymaster_error_t Update(const Buffer& input, Buffer* output);
    virtual keymaster_error_t Finish(const Buffer& signature, Buffer* output);
    virtual keymaster_error_t Abort() {
        // Nothing to do.
        return KM_ERROR_OK;
    }

  private:
    keymaster_error_t StoreData(const Buffer& input);

    keymaster_error_t error_;
    keymaster_digest_t digest_;
    keymaster_padding_t padding_;
    RSA* rsa_key_;
    Buffer data_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_RSA_OPERATION_H_
