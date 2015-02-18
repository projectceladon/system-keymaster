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

#ifndef SYSTEM_KEYMASTER_ECDSA_OPERATION_H_
#define SYSTEM_KEYMASTER_ECDSA_OPERATION_H_

#include <openssl/ec.h>

#include <UniquePtr.h>

#include <keymaster/key_blob.h>

#include "operation.h"

namespace keymaster {

class EcdsaOperation : public Operation {
  public:
    EcdsaOperation(keymaster_purpose_t purpose, const Logger& logger, EC_KEY* key)
        : Operation(purpose, logger), ecdsa_key_(key) {}
    ~EcdsaOperation();

    virtual keymaster_error_t Begin(const AuthorizationSet& /* input_params */,
                                    AuthorizationSet* /* output_params */) {
        return KM_ERROR_OK;
    }
    virtual keymaster_error_t Update(const AuthorizationSet& /* additional_params */,
                                     const Buffer& input, Buffer* output, size_t* input_consumed);
    virtual keymaster_error_t Abort() { return KM_ERROR_OK; }

  protected:
    keymaster_error_t StoreData(const Buffer& input, size_t* input_consumed);

    EC_KEY* ecdsa_key_;
    Buffer data_;
};

class EcdsaSignOperation : public EcdsaOperation {
  public:
    EcdsaSignOperation(keymaster_purpose_t purpose, const Logger& logger, EC_KEY* key)
        : EcdsaOperation(purpose, logger, key) {}
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);
};

class EcdsaVerifyOperation : public EcdsaOperation {
  public:
    EcdsaVerifyOperation(keymaster_purpose_t purpose, const Logger& logger, EC_KEY* key)
        : EcdsaOperation(purpose, logger, key) {}
    virtual keymaster_error_t Finish(const AuthorizationSet& additional_params,
                                     const Buffer& signature, Buffer* output);
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_ECDSA_OPERATION_H_
