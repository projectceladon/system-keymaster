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

#include <assert.h>
#include <string.h>

#include <cstddef>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <UniquePtr.h>

#include "ae.h"
#include "google_keymaster.h"
#include "google_keymaster_utils.h"
#include "key_blob.h"

namespace keymaster {

GoogleKeymaster::GoogleKeymaster() {
}
GoogleKeymaster::~GoogleKeymaster() {
}

const int RSA_DEFAULT_KEY_SIZE = 2048;
const int RSA_DEFAULT_EXPONENT = 65537;

struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const {
        BN_free(p);
    }
};
typedef UniquePtr<BIGNUM, BIGNUM_Delete> Unique_BIGNUM;

struct RSA_Delete {
    void operator()(RSA* p) const {
        RSA_free(p);
    }
};
typedef UniquePtr<RSA, RSA_Delete> Unique_RSA;

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

struct AE_CTX_Delete {
    void operator()(ae_ctx* ctx) const {
        ae_free(ctx);
    }
};
typedef UniquePtr<ae_ctx, AE_CTX_Delete> Unique_ae_ctx;

struct ByteArray_Delete {
    void operator()(void* p) const {
        delete[] reinterpret_cast<uint8_t*>(p);
    }
};

/**
 * Many OpenSSL APIs take ownership of an argument on success but don't free the argument on
 * failure. This means we need to tell our scoped pointers when we've transferred ownership, without
 * triggering a warning by not using the result of release().
 */
template <typename T, typename Delete_T>
inline void release_because_ownership_transferred(UniquePtr<T, Delete_T>& p) {
    T* val __attribute__((unused)) = p.release();
}

keymaster_algorithm_t supported_algorithms[] = {
    KM_ALGORITHM_RSA,
};

template <typename T>
bool check_supported(keymaster_algorithm_t algorithm, SupportedResponse<T>* response) {
    if (!array_contains(supported_algorithms, algorithm)) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return false;
    }
    return true;
}

void
GoogleKeymaster::SupportedAlgorithms(SupportedResponse<keymaster_algorithm_t>* response) const {
    if (response == NULL)
        return;
    response->SetResults(supported_algorithms);
}

void
GoogleKeymaster::SupportedBlockModes(keymaster_algorithm_t algorithm,
                                     SupportedResponse<keymaster_block_mode_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;
    response->error = KM_ERROR_OK;
}

keymaster_padding_t rsa_supported_padding[] = {KM_PAD_NONE};

void
GoogleKeymaster::SupportedPaddingModes(keymaster_algorithm_t algorithm,
                                       SupportedResponse<keymaster_padding_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        response->SetResults(rsa_supported_padding);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

keymaster_digest_t rsa_supported_digests[] = {KM_DIGEST_NONE};
void GoogleKeymaster::SupportedDigests(keymaster_algorithm_t algorithm,
                                       SupportedResponse<keymaster_digest_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        response->SetResults(rsa_supported_digests);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

keymaster_key_format_t rsa_supported_import_formats[] = {KM_KEY_FORMAT_PKCS8};
void
GoogleKeymaster::SupportedImportFormats(keymaster_algorithm_t algorithm,
                                        SupportedResponse<keymaster_key_format_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        response->SetResults(rsa_supported_import_formats);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

keymaster_key_format_t rsa_supported_export_formats[] = {KM_KEY_FORMAT_X509};
void
GoogleKeymaster::SupportedExportFormats(keymaster_algorithm_t algorithm,
                                        SupportedResponse<keymaster_key_format_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        response->SetResults(rsa_supported_export_formats);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

template <typename Message>
void store_bignum(Message* message, void (Message::*set)(const void* value, size_t size),
                  BIGNUM* bignum) {
    size_t bufsize = BN_num_bytes(bignum);
    UniquePtr<uint8_t[]> buf(new uint8_t[bufsize]);
    int bytes_written = BN_bn2bin(bignum, buf.get());
    (message->*set)(buf.get(), bytes_written);
}

void GoogleKeymaster::GenerateKey(const GenerateKeyRequest& request,
                                  GenerateKeyResponse* response) {
    if (response == NULL)
        return;
    response->error = KM_ERROR_OK;

    if (!CopyAuthorizations(request.key_description, response))
        return;

    AuthorizationSet hidden_auths;
    response->error = BuildHiddenAuthorizations(request.key_description, &hidden_auths);
    if (response->error != KM_ERROR_OK)
        return;

    keymaster_algorithm_t algorithm;
    if (!request.key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        if (!GenerateRsa(request.key_description, response, &hidden_auths))
            return;
        break;
    default:
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
}

void GoogleKeymaster::GetKeyCharacteristics(const GetKeyCharacteristicsRequest& request,
                                            GetKeyCharacteristicsResponse* response) {
    AuthorizationSet hidden;
    hidden.push_back(TAG_APPLICATION_ID, request.client_id.data, request.client_id.data_length);
    if (request.app_data.data != NULL)
        hidden.push_back(TAG_APPLICATION_DATA, request.app_data.data, request.app_data.data_length);
    hidden.push_back(RootOfTrustTag());

    KeyBlob blob(request.key_blob, hidden, MasterKey());
    if (blob.error() != KM_ERROR_OK) {
        response->error = blob.error();
        return;
    }
    response->enforced.Reinitialize(blob.enforced());
    response->unenforced.Reinitialize(blob.unenforced());
    response->error = KM_ERROR_OK;
}

bool GoogleKeymaster::GenerateRsa(const AuthorizationSet& key_auths, GenerateKeyResponse* response,
                                  AuthorizationSet* hidden_auths) {
    uint64_t public_exponent = RSA_DEFAULT_EXPONENT;
    if (!key_auths.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent))
        AddAuthorization(Authorization(TAG_RSA_PUBLIC_EXPONENT, public_exponent), response);

    uint32_t key_size = RSA_DEFAULT_KEY_SIZE;
    if (!key_auths.GetTagValue(TAG_KEY_SIZE, &key_size))
        AddAuthorization(Authorization(TAG_KEY_SIZE, key_size), response);

    Unique_BIGNUM exponent(BN_new());
    Unique_RSA rsa_key(RSA_new());
    Unique_EVP_PKEY pkey(EVP_PKEY_new());
    if (rsa_key.get() == NULL || pkey.get() == NULL) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }

    if (!BN_set_word(exponent.get(), public_exponent) ||
        !RSA_generate_key_ex(rsa_key.get(), key_size, exponent.get(), NULL /* callback */)) {
        response->error = KM_ERROR_UNKNOWN_ERROR;
        return false;
    }

    if (!EVP_PKEY_assign_RSA(pkey.get(), rsa_key.get())) {
        response->error = KM_ERROR_UNKNOWN_ERROR;
        return false;
    } else {
        release_because_ownership_transferred(rsa_key);
    }

    int der_length = i2d_PrivateKey(pkey.get(), NULL);
    if (der_length <= 0) {
        response->error = KM_ERROR_UNKNOWN_ERROR;
        return false;
    }
    UniquePtr<uint8_t[]> der_data(new uint8_t[der_length]);
    if (der_data.get() == NULL) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }

    uint8_t* tmp = der_data.get();
    i2d_PrivateKey(pkey.get(), &tmp);

    return CreateKeyBlob(response, *hidden_auths, der_data.get(), der_length);
}

bool GoogleKeymaster::CreateKeyBlob(GenerateKeyResponse* response,
                                    const AuthorizationSet& hidden_auths, uint8_t* key_bytes,
                                    size_t key_length) {
    uint8_t nonce[KeyBlob::NONCE_LENGTH];
    GenerateNonce(nonce, array_size(nonce));

    keymaster_key_blob_t key_data = {key_bytes, key_length};
    UniquePtr<KeyBlob> blob(new KeyBlob(response->enforced, response->unenforced, hidden_auths,
                                        key_data, MasterKey(), nonce));
    if (blob.get() == NULL) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }

    if (blob->error() != KM_ERROR_OK) {
        return blob->error();
        return false;
    }

    size_t size = blob->SerializedSize();
    UniquePtr<uint8_t[]> blob_bytes(new uint8_t[size]);
    if (blob_bytes.get() == NULL) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }
    blob->Serialize(blob_bytes.get(), blob_bytes.get() + size);
    response->key_blob.key_material_size = size;
    response->key_blob.key_material = blob_bytes.release();
    return true;
}

static keymaster_error_t CheckAuthorizationSet(const AuthorizationSet& set) {
    switch (set.is_valid()) {
    case AuthorizationSet::OK:
        return KM_ERROR_OK;
    case AuthorizationSet::ALLOCATION_FAILURE:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    case AuthorizationSet::MALFORMED_DATA:
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

bool GoogleKeymaster::CopyAuthorizations(const AuthorizationSet& key_description,
                                         GenerateKeyResponse* response) {
    for (size_t i = 0; i < key_description.size(); ++i) {
        switch (key_description[i].tag) {
        case KM_TAG_ROOT_OF_TRUST:
        case KM_TAG_CREATION_DATETIME:
        case KM_TAG_ORIGIN:
            response->error = KM_ERROR_INVALID_TAG;
            return false;
        case KM_TAG_ROLLBACK_RESISTANT:
            response->error = KM_ERROR_UNSUPPORTED_TAG;
            return false;
        default:
            AddAuthorization(key_description[i], response);
            break;
        }
    }

    AddAuthorization(Authorization(TAG_CREATION_DATETIME, java_time(time(NULL))), response);
    AddAuthorization(Authorization(TAG_ORIGIN, origin()), response);

    response->error = CheckAuthorizationSet(response->enforced);
    if (response->error != KM_ERROR_OK)
        return false;
    response->error = CheckAuthorizationSet(response->unenforced);
    if (response->error != KM_ERROR_OK)
        return false;

    return true;
}

keymaster_error_t GoogleKeymaster::BuildHiddenAuthorizations(const AuthorizationSet& input_set,
                                                AuthorizationSet* hidden) {
    keymaster_blob_t entry;
    if (input_set.GetTagValue(TAG_APPLICATION_ID, &entry))
        hidden->push_back(TAG_APPLICATION_ID, entry.data, entry.data_length);
    if (input_set.GetTagValue(TAG_APPLICATION_DATA, &entry))
        hidden->push_back(TAG_APPLICATION_DATA, entry.data, entry.data_length);
    hidden->push_back(RootOfTrustTag());

    return CheckAuthorizationSet(*hidden);
}

void GoogleKeymaster::AddAuthorization(const keymaster_key_param_t& auth,
                                       GenerateKeyResponse* response) {
    switch (auth.tag) {
    case KM_TAG_ROOT_OF_TRUST:
    case KM_TAG_APPLICATION_ID:
    case KM_TAG_APPLICATION_DATA:
        // Skip.  We handle these tags separately.
        break;
    default:
        if (is_enforced(auth.tag))
            response->enforced.push_back(auth);
        else
            response->unenforced.push_back(auth);
        break;
    }
}

}  // namespace keymaster
