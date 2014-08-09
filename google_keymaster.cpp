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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <UniquePtr.h>

#include "ae.h"
#include "google_keymaster.h"
#include "google_keymaster_utils.h"

// We need placement new, but we don't want to pull in any standard C++ libs at the moment.
// Luckily, it's trivial to just implement it.
inline void* operator new(size_t /* size */, void* here) { return here; }

namespace keymaster {

const int NONCE_LENGTH = 12;
const int TAG_LENGTH = 128 / 8;
#define REQUIRED_ALIGNMENT_FOR_AES_OCB 16

GoogleKeymaster::GoogleKeymaster() {}

GoogleKeymaster::~GoogleKeymaster() {}

const int RSA_DEFAULT_KEY_SIZE = 2048;
const int RSA_DEFAULT_EXPONENT = 65537;

#define CHECK_ERR(err)                                                                             \
    if ((err) != OK)                                                                               \
        return err;

struct BIGNUM_Delete {
    void operator()(BIGNUM* p) const { BN_free(p); }
};
typedef UniquePtr<BIGNUM, BIGNUM_Delete> Unique_BIGNUM;

struct RSA_Delete {
    void operator()(RSA* p) const { RSA_free(p); }
};
typedef UniquePtr<RSA, RSA_Delete> Unique_RSA;

struct EVP_PKEY_Delete {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};
typedef UniquePtr<EVP_PKEY, EVP_PKEY_Delete> Unique_EVP_PKEY;

struct AE_CTX_Delete {
    void operator()(ae_ctx* ctx) const { ae_free(ctx); }
};
typedef UniquePtr<ae_ctx, AE_CTX_Delete> Unique_ae_ctx;

struct ByteArray_Delete {
    void operator()(void* p) const { delete[] reinterpret_cast<uint8_t*>(p); }
};

// Context buffer used for AES OCB encryptions.
uint8_t aes_ocb_ctx_buf[896];

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

    keymaster_algorithm_t algorithm;
    if (!request.key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        if (!GenerateRsa(request.key_description, response))
            return;
        break;
    default:
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }
}

class KeyBlob {
  public:
    static KeyBlob* AllocAndInit(GenerateKeyResponse* response, size_t key_len) {
        size_t blob_length = get_size(response->enforced, response->unenforced, key_len);
        KeyBlob* blob(reinterpret_cast<KeyBlob*>(new uint8_t[blob_length]));
        return new (blob) KeyBlob(response->enforced, response->unenforced, key_len);
    }

    inline size_t length() {
        return get_size(enforced_length(), unenforced_length(), key_length());
    }
    inline uint8_t* nonce() { return nonce_; }
    inline size_t nonce_length() { return NONCE_LENGTH; }
    inline uint8_t* key_data() { return key_data_; }
    inline size_t key_length() { return key_length_; }
    inline size_t key_data_length() { return key_length_ + TAG_LENGTH; }
    inline uint8_t* enforced() {
        return key_data_ + key_length_ + TAG_LENGTH + padding(key_length_ + TAG_LENGTH);
    }
    inline size_t enforced_length() { return enforced_length_; }
    inline uint32_t* enforced_length_copy() {
        return reinterpret_cast<uint32_t*>(enforced() + enforced_length());
    }
    inline uint8_t* unenforced() { return enforced() + enforced_length_ + sizeof(uint32_t); }
    inline size_t unenforced_length() { return unenforced_length_; }
    inline uint8_t* end() { return unenforced() + unenforced_length_; }
    inline uint8_t* auth_data() { return enforced(); }
    inline size_t auth_data_length() { return end() - enforced(); }

  private:
    KeyBlob(AuthorizationSet& enforced_set, AuthorizationSet& unenforced_set, size_t key_len)
        : enforced_length_(enforced_set.SerializedSize()),
          unenforced_length_(unenforced_set.SerializedSize()), key_length_(key_len) {
        enforced_set.Serialize(enforced(), enforced() + enforced_length());
        unenforced_set.Serialize(unenforced(), unenforced() + unenforced_length());
    }

    uint32_t enforced_length_;
    uint32_t unenforced_length_;
    uint32_t key_length_;
    uint8_t nonce_[NONCE_LENGTH];
    uint8_t key_data_[] __attribute__((aligned(REQUIRED_ALIGNMENT_FOR_AES_OCB)));
    // Actual structure will also include:
    //    uint8_t enforced[] at key_data + key_length
    //    uint32_t enforced_length at key_data + key_length + enforced_length
    //    uint8_t unenforced[] at key_data + key_length + enforced_length.

    static size_t get_size(AuthorizationSet& enforced_set, AuthorizationSet& unenforced_set,
                           size_t key_len) {
        return get_size(enforced_set.SerializedSize(), unenforced_set.SerializedSize(), key_len);
    }

    static size_t get_size(size_t enforced_len, size_t unenforced_len, size_t key_len) {
        size_t pad_len = padding(key_len + TAG_LENGTH);
        return sizeof(KeyBlob) +   // includes lengths and nonce
               key_len +           // key in key_data_
               TAG_LENGTH +        // authentication tag in key_data_
               pad_len +           // padding to align authorization data
               enforced_len +      // enforced authorization data
               sizeof(uint32_t) +  // size of enforced authorization data.  This is also in
                                   // enforced_length_ but it's duplicated here to ensure that it's
                                   // included in the OCB-authenticated data, to enforce the
                                   // boundary between enforced and unenforced authorizations.
               unenforced_len;     // size of unenforced authorization data.
    }

    /**
     * Return the number of padding bytes needed to round up to the next alignment boundary.
     * boundary.
     */
    static size_t padding(size_t size) {
        return REQUIRED_ALIGNMENT_FOR_AES_OCB - (size % REQUIRED_ALIGNMENT_FOR_AES_OCB);
    }
};

keymaster_error_t GoogleKeymaster::WrapKey(uint8_t* key_data, size_t key_length, KeyBlob* blob) {
    assert(ae_ctx_sizeof() == (int)array_size(aes_ocb_ctx_buf));
    Eraser ctx_eraser(aes_ocb_ctx_buf, array_size(aes_ocb_ctx_buf));
    ae_ctx* ctx = reinterpret_cast<ae_ctx*>(aes_ocb_ctx_buf);
    int ae_err = ae_init(ctx, MasterKey(), MasterKeyLength(), blob->nonce_length(), TAG_LENGTH);
    if (ae_err != AE_SUCCESS) {
        return KM_ERROR_UNKNOWN_ERROR;
    }

    GetNonce(blob->nonce(), blob->nonce_length());
    ae_err = ae_encrypt(ctx, blob->nonce(), key_data, key_length, blob->auth_data(),
                        blob->auth_data_length(), blob->key_data(), NULL, 1 /* final */);
    if (ae_err < 0) {
        return KM_ERROR_UNKNOWN_ERROR;
    }
    assert(ae_err == (int)key_length + TAG_LENGTH);
    return KM_ERROR_OK;
}

bool GoogleKeymaster::CreateKeyBlob(GenerateKeyResponse* response, uint8_t* key_bytes,
                                    size_t key_length) {
    UniquePtr<KeyBlob, ByteArray_Delete> blob(KeyBlob::AllocAndInit(response, key_length));
    if (blob.get() == NULL) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }

    keymaster_error_t err = WrapKey(key_bytes, key_length, blob.get());
    if (err != KM_ERROR_OK) {
        response->error = err;
        return false;
    }

    response->key_blob.key_material_size = blob->length();
    response->key_blob.key_material = reinterpret_cast<uint8_t*>(blob.release());

    return true;
}

bool GoogleKeymaster::GenerateRsa(const AuthorizationSet& key_auths,
                                  GenerateKeyResponse* response) {
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

    return CreateKeyBlob(response, der_data.get(), der_length);
}

static keymaster_error_t CheckAuthorizationSet(const AuthorizationSet& set) {
    switch (set.is_valid()) {
    case AuthorizationSet::OK:
        return KM_ERROR_OK;
    case AuthorizationSet::ALLOCATION_FAILURE:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    case AuthorizationSet::BOUNDS_CHECKING_FAILURE:
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
    AddAuthorization(Authorization(TAG_ROOT_OF_TRUST, "SW", 2), response);

    response->error = CheckAuthorizationSet(response->enforced);
    if (response->error != KM_ERROR_OK)
        return false;
    response->error = CheckAuthorizationSet(response->unenforced);
    if (response->error != KM_ERROR_OK)
        return false;

    return true;
}

void GoogleKeymaster::AddAuthorization(const keymaster_key_param_t& auth,
                                       GenerateKeyResponse* response) {
    if (is_enforced(auth.tag))
        response->enforced.push_back(auth);
    else
        response->unenforced.push_back(auth);
}

}  // namespace keymaster
