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

#include <openssl/bn.h>

#include "dsa_operation.h"
#include "openssl_utils.h"

namespace keymaster {

struct DSA_Delete {
    void operator()(DSA* p) { DSA_free(p); }
};

/* static */
keymaster_error_t DsaOperation::Generate(uint32_t key_size_bits, keymaster_blob_t* g,
                                         keymaster_blob_t* p, keymaster_blob_t* q,
                                         UniquePtr<uint8_t[]>* key_data, size_t* key_data_size) {
    if (g == NULL || p == NULL || q == NULL || key_data == NULL || key_data_size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<DSA, DSA_Delete> dsa_key(DSA_new());
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (dsa_key.get() == NULL || pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (g->data == NULL && p->data == NULL && q->data == NULL) {
        // No params provided, generate them.
        if (!DSA_generate_parameters_ex(dsa_key.get(), key_size_bits, NULL /* seed */,
                                        0 /* seed_len */, NULL /* counter_ret */, NULL /* h_ret */,
                                        NULL /* callback */)) {
            // TODO(swillden): return a more precise error, depending on ERR_get_error();
            return KM_ERROR_INVALID_DSA_PARAMS;
        }
        convert_bn_to_blob(dsa_key->g, g);
        convert_bn_to_blob(dsa_key->p, p);
        convert_bn_to_blob(dsa_key->q, q);
    } else if (g->data == NULL || p->data == NULL || q->data == NULL) {
        // Some params provided, that's an error.  Provide them all or provide none.
        return KM_ERROR_INVALID_DSA_PARAMS;
    } else {
        // All params provided. Use them.
        dsa_key->g = BN_bin2bn(g->data, g->data_length, NULL);
        dsa_key->p = BN_bin2bn(p->data, p->data_length, NULL);
        dsa_key->q = BN_bin2bn(q->data, q->data_length, NULL);

        if (dsa_key->g == NULL || dsa_key->p == NULL || dsa_key->q == NULL)
            return KM_ERROR_INVALID_DSA_PARAMS;
    }

    if (!DSA_generate_key(dsa_key.get()) || !EVP_PKEY_assign_DSA(pkey.get(), dsa_key.get()))
        return KM_ERROR_UNKNOWN_ERROR;
    release_because_ownership_transferred(dsa_key);

    *key_data_size = i2d_PrivateKey(pkey.get(), NULL);
    if (*key_data_size <= 0)
        return KM_ERROR_UNKNOWN_ERROR;

    key_data->reset(new uint8_t[*key_data_size]);
    uint8_t* tmp = key_data->get();
    i2d_PrivateKey(pkey.get(), &tmp);

    return KM_ERROR_OK;
}

DsaOperation::DsaOperation(keymaster_purpose_t purpose, const KeyBlob& key)
    : Operation(purpose), dsa_key_(NULL) {
    assert(key.algorithm() == KM_ALGORITHM_DSA);

    if ((!key.enforced().GetTagValue(TAG_DIGEST, &digest_) &&
         !key.unenforced().GetTagValue(TAG_DIGEST, &digest_)) ||
        digest_ != KM_DIGEST_NONE) {
        error_ = KM_ERROR_UNSUPPORTED_DIGEST;
        return;
    }

    if ((!key.enforced().GetTagValue(TAG_PADDING, &padding_) &&
         !key.unenforced().GetTagValue(TAG_PADDING, &padding_)) ||
        padding_ != KM_PAD_NONE) {
        error_ = KM_ERROR_UNSUPPORTED_PADDING_MODE;
        return;
    }

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> evp_key(EVP_PKEY_new());
    if (evp_key.get() == NULL) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }

    EVP_PKEY* tmp_pkey = evp_key.get();
    const uint8_t* key_material = key.key_material();
    if (d2i_PrivateKey(EVP_PKEY_DSA, &tmp_pkey, &key_material, key.key_material_length()) == NULL) {
        error_ = KM_ERROR_INVALID_KEY_BLOB;
        return;
    }

    dsa_key_ = EVP_PKEY_get1_DSA(evp_key.get());
    if (dsa_key_ == NULL) {
        error_ = KM_ERROR_UNKNOWN_ERROR;
        return;
    }

    // Since we're not using a digest function, we just need to store the text, up to the key
    // size, until Finish is called, so we allocate a place to put it.
    if (!data_.Reinitialize(DSA_size(dsa_key_))) {
        error_ = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }
    error_ = KM_ERROR_OK;
}

DsaOperation::~DsaOperation() {
    if (dsa_key_ != NULL)
        DSA_free(dsa_key_);
}

keymaster_error_t DsaOperation::Update(const Buffer& input, Buffer* /* output */) {
    switch (purpose()) {
    default:
        return KM_ERROR_UNIMPLEMENTED;
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        return StoreData(input);
    }
}

keymaster_error_t DsaOperation::StoreData(const Buffer& input) {
    if (!data_.write(input.peek_read(), input.available_read()))
        return KM_ERROR_INVALID_INPUT_LENGTH;
    return KM_ERROR_OK;
}

keymaster_error_t DsaOperation::Finish(const Buffer& signature, Buffer* output) {
    switch (purpose()) {
    case KM_PURPOSE_SIGN: {
        output->Reinitialize(DSA_size(dsa_key_));
        if (data_.available_read() != output->buffer_size())
            return KM_ERROR_INVALID_INPUT_LENGTH;

        unsigned int siglen;
        if (!DSA_sign(0 /* type -- ignored */, data_.peek_read(), data_.available_read(),
                      output->peek_write(), &siglen, dsa_key_))
            return KM_ERROR_UNKNOWN_ERROR;
        output->advance_write(siglen);
        return KM_ERROR_OK;
    }
    case KM_PURPOSE_VERIFY: {
        if ((int)data_.available_read() != DSA_size(dsa_key_))
            return KM_ERROR_INVALID_INPUT_LENGTH;

        int result = DSA_verify(0 /* type -- ignored */, data_.peek_read(), data_.available_read(),
                                signature.peek_read(), signature.available_read(), dsa_key_);
        if (result< 0)
            return KM_ERROR_UNKNOWN_ERROR;
        else if (result == 0)
            return KM_ERROR_VERIFICATION_FAILED;
        else
            return KM_ERROR_OK;
    }
    default:
        return KM_ERROR_UNIMPLEMENTED;
    }
}

}  // namespace keymaster
