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

class EcdsaOperationFactory : public OperationFactory {
  private:
    KeyType registry_key() const override { return KeyType(KM_ALGORITHM_EC, purpose()); }
    Operation* CreateOperation(const Key& key, const AuthorizationSet& begin_params,
                               keymaster_error_t* error) override;
    const keymaster_digest_t* SupportedDigests(size_t* digest_count) const override;

    virtual keymaster_purpose_t purpose() const = 0;
    virtual Operation* InstantiateOperation(keymaster_digest_t digest, EC_KEY* key) = 0;
};

Operation* EcdsaOperationFactory::CreateOperation(const Key& key,
                                                  const AuthorizationSet& begin_params,
                                                  keymaster_error_t* error) {
    const EcKey* ecdsa_key = static_cast<const EcKey*>(&key);
    if (!ecdsa_key) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return nullptr;
    }

    *error = KM_ERROR_UNSUPPORTED_DIGEST;
    keymaster_digest_t digest;
    if (!begin_params.GetTagValue(TAG_DIGEST, &digest)) {
        LOG_E("%d digests specified in begin params", begin_params.GetTagCount(TAG_DIGEST));
        return nullptr;
    } else if (!supported(digest)) {
        LOG_E("Digest %d not supported", digest);
        return nullptr;
    } else if (!ecdsa_key->authorizations().Contains(TAG_DIGEST, digest) &&
               !ecdsa_key->authorizations().Contains(TAG_DIGEST_OLD, digest)) {
        LOG_E("Digest %d was specified, but not authorized by key", digest);
        *error = KM_ERROR_INCOMPATIBLE_DIGEST;
        return NULL;
    }
    *error = KM_ERROR_OK;

    Operation* op = InstantiateOperation(digest, ecdsa_key->key());
    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

const keymaster_digest_t* EcdsaOperationFactory::SupportedDigests(size_t* digest_count) const {
    *digest_count = array_length(supported_digests);
    return supported_digests;
}

class EcdsaSignOperationFactory : public EcdsaOperationFactory {
  private:
    keymaster_purpose_t purpose() const override { return KM_PURPOSE_SIGN; }
    Operation* InstantiateOperation(keymaster_digest_t digest, EC_KEY* key) {
        return new EcdsaSignOperation(purpose(), digest, key);
    }
};

static OperationFactoryRegistry::Registration<EcdsaSignOperationFactory> sign_registration;

class EcdsaVerifyOperationFactory : public EcdsaOperationFactory {
  public:
    keymaster_purpose_t purpose() const override { return KM_PURPOSE_VERIFY; }
    Operation* InstantiateOperation(keymaster_digest_t digest, EC_KEY* key) {
        return new EcdsaVerifyOperation(KM_PURPOSE_VERIFY, digest, key);
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
