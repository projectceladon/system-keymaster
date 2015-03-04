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

#include "hmac_operation.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "openssl_err.h"
#include "symmetric_key.h"

#if defined(OPENSSL_IS_BORINGSSL)
typedef size_t openssl_size_t;
#else
typedef int openssl_size_t;
#endif

namespace keymaster {

/**
 * Abstract base for HMAC operation factories.  This class does all of the work to create
 * HMAC operations.
 */
class HmacOperationFactory : public OperationFactory {
  public:
    virtual KeyType registry_key() const { return KeyType(KM_ALGORITHM_HMAC, purpose()); }

    virtual Operation* CreateOperation(const Key& key, keymaster_error_t* error);

    virtual const keymaster_digest_t* SupportedDigests(size_t* digest_count) const;

    virtual keymaster_purpose_t purpose() const = 0;
};

Operation* HmacOperationFactory::CreateOperation(const Key& key, keymaster_error_t* error) {
    *error = KM_ERROR_OK;

    uint32_t tag_length;
    if (!key.authorizations().GetTagValue(TAG_MAC_LENGTH, &tag_length))
        *error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;

    keymaster_digest_t digest;
    if (!key.authorizations().GetTagValue(TAG_DIGEST, &digest))
        *error = KM_ERROR_UNSUPPORTED_DIGEST;

    if (*error != KM_ERROR_OK)
        return NULL;

    const SymmetricKey* symmetric_key = static_cast<const SymmetricKey*>(&key);
    if (!symmetric_key) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return NULL;
    }

    Operation* op = new HmacOperation(purpose(), symmetric_key->key_data(),
                                      symmetric_key->key_data_size(), digest, tag_length);
    if (!op)
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return op;
}

static keymaster_digest_t supported_digests[] = {KM_DIGEST_SHA1, KM_DIGEST_SHA_2_224,
                                                 KM_DIGEST_SHA_2_256, KM_DIGEST_SHA_2_384,
                                                 KM_DIGEST_SHA_2_512};
const keymaster_digest_t* HmacOperationFactory::SupportedDigests(size_t* digest_count) const {
    *digest_count = array_length(supported_digests);
    return supported_digests;
}

/**
 * Concrete factory for creating HMAC signing operations.
 */
class HmacSignOperationFactory : public HmacOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_SIGN; }
};
static OperationFactoryRegistry::Registration<HmacSignOperationFactory> sign_registration;

/**
 * Concrete factory for creating HMAC verification operations.
 */
class HmacVerifyOperationFactory : public HmacOperationFactory {
    keymaster_purpose_t purpose() const { return KM_PURPOSE_VERIFY; }
};
static OperationFactoryRegistry::Registration<HmacVerifyOperationFactory> verify_registration;

HmacOperation::HmacOperation(keymaster_purpose_t purpose, const uint8_t* key_data,
                             size_t key_data_size, keymaster_digest_t digest, size_t tag_length)
    : Operation(purpose), error_(KM_ERROR_OK), tag_length_(tag_length) {
    // Initialize CTX first, so dtor won't crash even if we error out later.
    HMAC_CTX_init(&ctx_);

    const EVP_MD* md;
    switch (digest) {
    case KM_DIGEST_SHA1:
        md = EVP_sha1();
        break;
    case KM_DIGEST_SHA_2_224:
        md = EVP_sha224();
        break;
    case KM_DIGEST_SHA_2_256:
        md = EVP_sha256();
        break;
    case KM_DIGEST_SHA_2_384:
        md = EVP_sha384();
        break;
    case KM_DIGEST_SHA_2_512:
        md = EVP_sha512();
        break;
    default:
        error_ = KM_ERROR_UNSUPPORTED_DIGEST;
        return;
    }

    if ((openssl_size_t)tag_length_ > EVP_MD_size(md)) {
        error_ = KM_ERROR_UNSUPPORTED_MAC_LENGTH;
        return;
    }

    HMAC_Init_ex(&ctx_, key_data, key_data_size, md, NULL /* engine */);
}

HmacOperation::~HmacOperation() {
    HMAC_CTX_cleanup(&ctx_);
}

keymaster_error_t HmacOperation::Begin(const AuthorizationSet& /* input_params */,
                                       AuthorizationSet* /* output_params */) {
    return error_;
}

keymaster_error_t HmacOperation::Update(const AuthorizationSet& /* additional_params */,
                                        const Buffer& input, Buffer* /* output */,
                                        size_t* input_consumed) {
    if (!HMAC_Update(&ctx_, input.peek_read(), input.available_read()))
        return TranslateLastOpenSslError();
    *input_consumed = input.available_read();
    return KM_ERROR_OK;
}

keymaster_error_t HmacOperation::Abort() {
    return KM_ERROR_OK;
}

keymaster_error_t HmacOperation::Finish(const AuthorizationSet& /* additional_params */,
                                        const Buffer& signature, Buffer* output) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    if (!HMAC_Final(&ctx_, digest, &digest_len))
        return TranslateLastOpenSslError();

    switch (purpose()) {
    case KM_PURPOSE_SIGN:
        output->reserve(tag_length_);
        output->write(digest, tag_length_);
        return KM_ERROR_OK;
    case KM_PURPOSE_VERIFY:
        if (signature.available_read() != tag_length_)
            return KM_ERROR_INVALID_INPUT_LENGTH;
        if (memcmp(signature.peek_read(), digest, tag_length_) != 0)
            return KM_ERROR_VERIFICATION_FAILED;
        return KM_ERROR_OK;
    default:
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
}

}  // namespace keymaster
