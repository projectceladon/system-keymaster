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

#include <UniquePtr.h>

#include <keymaster/key_blob.h>

#include "operation.h"

namespace keymaster {

class RsaOperation : public Operation {
  public:
    RsaOperation(keymaster_purpose_t purpose, const Logger& logger, keymaster_padding_t padding,
                 RSA* key)
        : Operation(purpose, logger), rsa_key_(key), padding_(padding) {}
    ~RsaOperation();

    virtual keymaster_error_t Begin(const AuthorizationSet& /* input_params */,
                                    AuthorizationSet* /* output_params */) {
        return KM_ERROR_OK;
    }
    virtual keymaster_error_t Update(const Buffer& input, Buffer* output, size_t* input_consumed);
    virtual keymaster_error_t Abort() { return KM_ERROR_OK; }

  protected:
    keymaster_error_t StoreData(const Buffer& input, size_t* input_consumed);

    RSA* rsa_key_;
    keymaster_padding_t padding_;
    Buffer data_;
};

class RsaSignOperation : public RsaOperation {
  public:
    RsaSignOperation(const Logger& logger, keymaster_digest_t digest, keymaster_padding_t padding,
                     RSA* key)
        : RsaOperation(KM_PURPOSE_SIGN, logger, padding, key), digest_(digest) {}
    virtual keymaster_error_t Finish(const Buffer& signature, Buffer* output);

  private:
    keymaster_digest_t digest_;
};

class RsaVerifyOperation : public RsaOperation {
  public:
    RsaVerifyOperation(const Logger& logger, keymaster_digest_t digest, keymaster_padding_t padding,
                       RSA* key)
        : RsaOperation(KM_PURPOSE_VERIFY, logger, padding, key), digest_(digest) {}
    virtual keymaster_error_t Finish(const Buffer& signature, Buffer* output);

  private:
    keymaster_digest_t digest_;
};

class RsaEncryptOperation : public RsaOperation {
  public:
    RsaEncryptOperation(const Logger& logger, keymaster_padding_t padding, RSA* key)
        : RsaOperation(KM_PURPOSE_ENCRYPT, logger, padding, key) {}
    virtual keymaster_error_t Finish(const Buffer& signature, Buffer* output);
};

class RsaDecryptOperation : public RsaOperation {
  public:
    RsaDecryptOperation(const Logger& logger, keymaster_padding_t padding, RSA* key)
        : RsaOperation(KM_PURPOSE_DECRYPT, logger, padding, key) {}
    virtual keymaster_error_t Finish(const Buffer& signature, Buffer* output);
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_RSA_OPERATION_H_
