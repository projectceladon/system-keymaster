/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "openssl_err.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <hardware/keymaster_defs.h>
#include <keymaster/logger.h>

namespace keymaster {

static keymaster_error_t TranslateEvpError(int reason);

keymaster_error_t TranslateLastOpenSslError(bool log_message) {
    unsigned long error = ERR_peek_last_error();

    if (log_message) {
        LOG_D("%s", ERR_error_string(error, NULL));
    }

    int reason = ERR_GET_REASON(error);
    switch (ERR_GET_LIB(error)) {

    case ERR_LIB_EVP:
        return TranslateEvpError(reason);

    case ERR_LIB_ASN1:
        // TODO(swillden): Consider a better return code.
        return KM_ERROR_INVALID_ARGUMENT;
    }

    return KM_ERROR_UNKNOWN_ERROR;
}

keymaster_error_t TranslateEvpError(int reason) {
    switch (reason) {

    case EVP_R_UNKNOWN_DIGEST:
        return KM_ERROR_UNSUPPORTED_DIGEST;

    case EVP_R_UNSUPPORTED_PRF:
    case EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM:
    case EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION:
    case EVP_R_UNSUPPORTED_SALT_TYPE:
    case EVP_R_UNKNOWN_PBE_ALGORITHM:
    case EVP_R_UNSUPORTED_NUMBER_OF_ROUNDS:
    case EVP_R_UNSUPPORTED_ALGORITHM:
    case EVP_R_UNSUPPORTED_CIPHER:
    case EVP_R_OPERATON_NOT_INITIALIZED:
    case EVP_R_PKCS8_UNKNOWN_BROKEN_TYPE:
    case EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE:
    case EVP_R_UNKNOWN_CIPHER:
        return KM_ERROR_UNSUPPORTED_ALGORITHM;

    case EVP_R_UNKNOWN_OPTION:
    case EVP_R_TOO_LARGE:
    case EVP_R_KEYGEN_FAILURE:
    case EVP_R_NO_OPERATION_SET:
    case EVP_R_NO_SIGN_FUNCTION_CONFIGURED:
    case EVP_R_NO_VERIFY_FUNCTION_CONFIGURED:
    case EVP_R_MESSAGE_DIGEST_IS_NULL:
    case EVP_R_METHOD_NOT_SUPPORTED:
    case EVP_R_INVALID_OPERATION:
    case EVP_R_IV_TOO_LARGE:
    case EVP_R_NO_KEY_SET:
    case EVP_R_NO_CIPHER_SET:
    case EVP_R_NO_DEFAULT_DIGEST:
    case EVP_R_NO_DIGEST_SET:
    case EVP_R_EVP_PBE_CIPHERINIT_ERROR:
    case EVP_R_INITIALIZATION_ERROR:
    case EVP_R_INPUT_NOT_INITIALIZED:
    case EVP_R_CAMELLIA_KEY_SETUP_FAILED:
    case EVP_R_AES_IV_SETUP_FAILED:
    case EVP_R_AES_KEY_SETUP_FAILED:
    case EVP_R_FIPS_MODE_NOT_SUPPORTED:
    case EVP_R_ASN1_LIB:
    case EVP_R_COMMAND_NOT_SUPPORTED:
    case EVP_R_CTRL_NOT_IMPLEMENTED:
    case EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED:
    case EVP_R_DISABLED_FOR_FIPS:
    case EVP_R_ERROR_SETTING_FIPS_MODE:
    case EVP_R_INVALID_FIPS_MODE:
        return KM_ERROR_UNKNOWN_ERROR;

    case EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
    case EVP_R_WRONG_FINAL_BLOCK_LENGTH:
        return KM_ERROR_INVALID_INPUT_LENGTH;

    case EVP_R_UNSUPPORTED_KEYLENGTH:
    case EVP_R_BAD_KEY_LENGTH:
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;

    case EVP_R_BAD_BLOCK_LENGTH:
    case EVP_R_BN_DECODE_ERROR:
    case EVP_R_BN_PUBKEY_ERROR:
    case EVP_R_BUFFER_TOO_SMALL:
    case EVP_R_CIPHER_PARAMETER_ERROR:
    case EVP_R_ERROR_LOADING_SECTION:
    case EVP_R_EXPECTING_AN_RSA_KEY:
    case EVP_R_EXPECTING_A_DH_KEY:
    case EVP_R_EXPECTING_A_DSA_KEY:
    case EVP_R_EXPECTING_A_ECDSA_KEY:
    case EVP_R_EXPECTING_A_EC_KEY:
    case EVP_R_INVALID_DIGEST:
    case EVP_R_INVALID_KEY_LENGTH:
    case EVP_R_MISSING_PARAMETERS:
    case EVP_R_NO_DSA_PARAMETERS:
    case EVP_R_PRIVATE_KEY_DECODE_ERROR:
    case EVP_R_PRIVATE_KEY_ENCODE_ERROR:
    case EVP_R_PUBLIC_KEY_NOT_RSA:
    case EVP_R_WRONG_PUBLIC_KEY_TYPE:
        return KM_ERROR_INVALID_KEY_BLOB;

    case EVP_R_BAD_DECRYPT:
    case EVP_R_DIFFERENT_PARAMETERS:
    case EVP_R_DECODE_ERROR:
    case EVP_R_ENCODE_ERROR:
        return KM_ERROR_INVALID_ARGUMENT;

    case EVP_R_DIFFERENT_KEY_TYPES:
        return KM_ERROR_INCOMPATIBLE_ALGORITHM;
    }

    return KM_ERROR_UNKNOWN_ERROR;
}

}  // namespace keymaster
