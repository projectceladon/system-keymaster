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

#include <limits.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "rsa_operation.h"
#include "openssl_utils.h"

namespace keymaster {

struct RSA_Delete {
    void operator()(RSA* p) const { RSA_free(p); }
};

RsaOperation::~RsaOperation() {
    if (rsa_key_ != NULL)
        RSA_free(rsa_key_);
}

keymaster_error_t RsaOperation::Update(const AuthorizationSet& /* additional_params */,
                                       const Buffer& input, Buffer* /* output */,
                                       size_t* input_consumed) {
    assert(input_consumed);
    switch (purpose()) {
    default:
        return KM_ERROR_UNIMPLEMENTED;
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
    case KM_PURPOSE_ENCRYPT:
    case KM_PURPOSE_DECRYPT:
        return StoreData(input, input_consumed);
    }
}

keymaster_error_t RsaOperation::StoreData(const Buffer& input, size_t* input_consumed) {
    assert(input_consumed);
    if (!data_.reserve(data_.available_read() + input.available_read()) ||
        !data_.write(input.peek_read(), input.available_read()))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t RsaSignOperation::Finish(const AuthorizationSet& /* additional_params */,
                                           const Buffer& /* signature */, Buffer* output) {
    assert(output);
    output->Reinitialize(RSA_size(rsa_key_));
    int bytes_encrypted = RSA_private_encrypt(data_.available_read(), data_.peek_read(),
                                              output->peek_write(), rsa_key_, RSA_NO_PADDING);
    if (bytes_encrypted < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(bytes_encrypted == RSA_size(rsa_key_));
    output->advance_write(bytes_encrypted);
    return KM_ERROR_OK;
}

keymaster_error_t RsaVerifyOperation::Finish(const AuthorizationSet& /* additional_params */,
                                             const Buffer& signature, Buffer* /* output */) {
#if defined(OPENSSL_IS_BORINGSSL)
    size_t message_size = data_.available_read();
#else
    if (data_.available_read() > INT_MAX)
        return KM_ERROR_INVALID_INPUT_LENGTH;
    int message_size = (int)data_.available_read();
#endif

    if (message_size != RSA_size(rsa_key_))
        return KM_ERROR_INVALID_INPUT_LENGTH;

    if (data_.available_read() != signature.available_read())
        return KM_ERROR_VERIFICATION_FAILED;

    UniquePtr<uint8_t[]> decrypted_data(new uint8_t[RSA_size(rsa_key_)]);
    int bytes_decrypted = RSA_public_decrypt(signature.available_read(), signature.peek_read(),
                                             decrypted_data.get(), rsa_key_, RSA_NO_PADDING);
    if (bytes_decrypted < 0)
        return KM_ERROR_UNKNOWN_ERROR;
    assert(bytes_decrypted == RSA_size(rsa_key_));

    if (memcmp_s(decrypted_data.get(), data_.peek_read(), data_.available_read()) == 0)
        return KM_ERROR_OK;
    return KM_ERROR_VERIFICATION_FAILED;
}

const int OAEP_PADDING_OVERHEAD = 41;
const int PKCS1_PADDING_OVERHEAD = 11;

keymaster_error_t RsaEncryptOperation::Finish(const AuthorizationSet& /* additional_params */,
                                              const Buffer& /* signature */, Buffer* output) {
    assert(output);
    int openssl_padding;

#if defined(OPENSSL_IS_BORINGSSL)
    size_t message_size = data_.available_read();
#else
    if (data_.available_read() > INT_MAX)
        return KM_ERROR_INVALID_INPUT_LENGTH;
    int message_size = (int)data_.available_read();
#endif

    switch (padding_) {
    case KM_PAD_RSA_OAEP:
        openssl_padding = RSA_PKCS1_OAEP_PADDING;
        if (message_size >= RSA_size(rsa_key_) - OAEP_PADDING_OVERHEAD) {
            logger().error("Cannot encrypt %d bytes with %d-byte key and OAEP padding",
                           data_.available_read(), RSA_size(rsa_key_));
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        break;
    case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
        openssl_padding = RSA_PKCS1_PADDING;
        if (message_size >= RSA_size(rsa_key_) - PKCS1_PADDING_OVERHEAD) {
            logger().error("Cannot encrypt %d bytes with %d-byte key and PKCS1 padding",
                           data_.available_read(), RSA_size(rsa_key_));
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
        break;
    default:
        logger().error("Padding mode %d not supported", padding_);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    output->Reinitialize(RSA_size(rsa_key_));
    int bytes_encrypted = RSA_public_encrypt(data_.available_read(), data_.peek_read(),
                                             output->peek_write(), rsa_key_, openssl_padding);

    if (bytes_encrypted < 0) {
        logger().error("Error %d encrypting data with RSA", ERR_get_error());
        return KM_ERROR_UNKNOWN_ERROR;
    }
    assert(bytes_encrypted == RSA_size(rsa_key_));
    output->advance_write(bytes_encrypted);

    return KM_ERROR_OK;
}

keymaster_error_t RsaDecryptOperation::Finish(const AuthorizationSet& /* additional_params */,
                                              const Buffer& /* signature */, Buffer* output) {
    assert(output);
    int openssl_padding;
    switch (padding_) {
    case KM_PAD_RSA_OAEP:
        openssl_padding = RSA_PKCS1_OAEP_PADDING;
        break;
    case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
        openssl_padding = RSA_PKCS1_PADDING;
        break;
    default:
        logger().error("Padding mode %d not supported", padding_);
        return KM_ERROR_UNSUPPORTED_PADDING_MODE;
    }

    output->Reinitialize(RSA_size(rsa_key_));
    int bytes_decrypted = RSA_private_decrypt(data_.available_read(), data_.peek_read(),
                                              output->peek_write(), rsa_key_, openssl_padding);

    if (bytes_decrypted < 0) {
        logger().error("Error %d decrypting data with RSA", ERR_get_error());
        return KM_ERROR_UNKNOWN_ERROR;
    }
    output->advance_write(bytes_decrypted);

    return KM_ERROR_OK;
}

}  // namespace keymaster
