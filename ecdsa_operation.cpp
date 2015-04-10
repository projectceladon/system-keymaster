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

#include <openssl/ecdsa.h>

#include "ec_key.h"
#include "ecdsa_operation.h"
#include "openssl_err.h"
#include "openssl_utils.h"

namespace keymaster {

static const keymaster_digest_t supported_digests[] = {KM_DIGEST_NONE};

class EcdsaSignOperationFactory : public OperationFactory {
  public:
    virtual KeyType registry_key() const { return KeyType(KM_ALGORITHM_EC, KM_PURPOSE_SIGN); }

    virtual Operation* CreateOperation(const Key& key, keymaster_error_t* error) {
        const EcKey* ecdsa_key = static_cast<const EcKey*>(&key);
        if (!ecdsa_key) {
            *error = KM_ERROR_UNKNOWN_ERROR;
            return NULL;
        }

        keymaster_digest_t digest;
        if (!ecdsa_key->authorizations().GetTagValue(TAG_DIGEST, &digest) &&
            !ecdsa_key->authorizations().GetTagValue(TAG_DIGEST_OLD, &digest)) {
            *error = KM_ERROR_UNSUPPORTED_DIGEST;
            return NULL;
        }

        Operation* op = new EcdsaSignOperation(KM_PURPOSE_SIGN, digest, ecdsa_key->key());
        if (!op)
            *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return op;
    }

    virtual const keymaster_digest_t* SupportedDigests(size_t* digest_count) const {
        *digest_count = array_length(supported_digests);
        return supported_digests;
    }
};
static OperationFactoryRegistry::Registration<EcdsaSignOperationFactory> sign_registration;

class EcdsaVerifyOperationFactory : public OperationFactory {
  public:
    virtual KeyType registry_key() const { return KeyType(KM_ALGORITHM_EC, KM_PURPOSE_VERIFY); }

    virtual Operation* CreateOperation(const Key& key, keymaster_error_t* error) {
        const EcKey* ecdsa_key = static_cast<const EcKey*>(&key);
        if (!ecdsa_key) {
            *error = KM_ERROR_UNKNOWN_ERROR;
            return NULL;
        }

        keymaster_digest_t digest;
        if (!ecdsa_key->authorizations().GetTagValue(TAG_DIGEST, &digest) &&
            !ecdsa_key->authorizations().GetTagValue(TAG_DIGEST_OLD, &digest)) {
            *error = KM_ERROR_UNSUPPORTED_DIGEST;
            return NULL;
        }

        Operation* op = new EcdsaVerifyOperation(KM_PURPOSE_VERIFY, digest, ecdsa_key->key());
        if (!op)
            *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return op;
    }

    virtual const keymaster_digest_t* SupportedDigests(size_t* digest_count) const {
        *digest_count = array_length(supported_digests);
        return supported_digests;
    }
};
static OperationFactoryRegistry::Registration<EcdsaVerifyOperationFactory> verify_registration;

EcdsaOperation::~EcdsaOperation() {
    if (ecdsa_key_ != NULL)
        EC_KEY_free(ecdsa_key_);
}

keymaster_error_t EcdsaOperation::Update(const AuthorizationSet& /* additional_params */,
                                         const Buffer& input, Buffer* /* output */,
                                         size_t* input_consumed) {
    assert(input_consumed);
    switch (purpose()) {
    default:
        return KM_ERROR_UNIMPLEMENTED;
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        return StoreData(input, input_consumed);
    }
}

keymaster_error_t EcdsaOperation::StoreData(const Buffer& input, size_t* input_consumed) {
    if (!data_.reserve(data_.available_read() + input.available_read()) ||
        !data_.write(input.peek_read(), input.available_read()))
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaSignOperation::Finish(const AuthorizationSet& /* additional_params */,
                                             const Buffer& /* signature */, Buffer* output) {
    assert(output);
    output->Reinitialize(ECDSA_size(ecdsa_key_));
    unsigned int siglen;
    if (!ECDSA_sign(0 /* type -- ignored */, data_.peek_read(), data_.available_read(),
                    output->peek_write(), &siglen, ecdsa_key_))
        return TranslateLastOpenSslError();
    output->advance_write(siglen);
    return KM_ERROR_OK;
}

keymaster_error_t EcdsaVerifyOperation::Finish(const AuthorizationSet& /* additional_params */,
                                               const Buffer& signature, Buffer* /* output */) {
    int result = ECDSA_verify(0 /* type -- ignored */, data_.peek_read(), data_.available_read(),
                              signature.peek_read(), signature.available_read(), ecdsa_key_);
    if (result < 0)
        return TranslateLastOpenSslError();
    else if (result == 0)
        return KM_ERROR_VERIFICATION_FAILED;
    else
        return KM_ERROR_OK;
}

}  // namespace keymaster
