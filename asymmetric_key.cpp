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

#include "asymmetric_key.h"

#include <openssl/x509.h>

#include <hardware/keymaster_defs.h>

#include "ecdsa_key.h"
#include "openssl_err.h"
#include "openssl_utils.h"
#include "rsa_key.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

struct PKCS8_PRIV_KEY_INFO_Delete {
    void operator()(PKCS8_PRIV_KEY_INFO* p) const { PKCS8_PRIV_KEY_INFO_free(p); }
};

EVP_PKEY* AsymmetricKeyFactory::ExtractEvpKey(keymaster_key_format_t key_format,
                                              keymaster_algorithm_t expected_algorithm,
                                              const uint8_t* key_data, size_t key_data_length,
                                              keymaster_error_t* error) {
    *error = KM_ERROR_OK;

    if (key_data == NULL || key_data_length <= 0) {
        *error = KM_ERROR_INVALID_KEY_BLOB;
        return NULL;
    }

    if (key_format != KM_KEY_FORMAT_PKCS8) {
        *error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
        return NULL;
    }

    UniquePtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_Delete> pkcs8(
        d2i_PKCS8_PRIV_KEY_INFO(NULL, &key_data, key_data_length));
    if (pkcs8.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    }

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKCS82PKEY(pkcs8.get()));
    if (pkey.get() == NULL || EVP_PKEY_type(pkey->type) != convert_to_evp(expected_algorithm)) {
        *error = KM_ERROR_INVALID_KEY_BLOB;
        return NULL;
    }

    return pkey.release();
}

static const keymaster_key_format_t supported_import_formats[] = {KM_KEY_FORMAT_PKCS8};
const keymaster_key_format_t* AsymmetricKeyFactory::SupportedImportFormats(size_t* format_count) {
    *format_count = array_length(supported_import_formats);
    return supported_import_formats;
}

static const keymaster_key_format_t supported_export_formats[] = {KM_KEY_FORMAT_X509};
const keymaster_key_format_t* AsymmetricKeyFactory::SupportedExportFormats(size_t* format_count) {
    *format_count = array_length(supported_export_formats);
    return supported_export_formats;
}

/* static */
int AsymmetricKeyFactory::convert_to_evp(keymaster_algorithm_t algorithm) {
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return EVP_PKEY_RSA;
    case KM_ALGORITHM_ECDSA:
        return EVP_PKEY_EC;
    default:
        return -1;
    };
}

keymaster_error_t AsymmetricKey::LoadKey(const UnencryptedKeyBlob& blob) {
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> evp_key(EVP_PKEY_new());
    if (evp_key.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    EVP_PKEY* tmp_pkey = evp_key.get();
    const uint8_t* key_material = blob.unencrypted_key_material();
    if (d2i_PrivateKey(evp_key_type(), &tmp_pkey, &key_material, blob.key_material_length()) ==
        NULL) {
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    if (!EvpToInternal(evp_key.get()))
        return TranslateLastOpenSslError();

    return KM_ERROR_OK;
}

keymaster_error_t AsymmetricKey::key_material(UniquePtr<uint8_t[]>* material, size_t* size) const {
    if (material == NULL || size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!InternalToEvp(pkey.get()))
        return TranslateLastOpenSslError();

    *size = i2d_PrivateKey(pkey.get(), NULL /* key_data*/);
    if (*size <= 0)
        return TranslateLastOpenSslError();

    material->reset(new uint8_t[*size]);
    uint8_t* tmp = material->get();
    i2d_PrivateKey(pkey.get(), &tmp);

    return KM_ERROR_OK;
}

keymaster_error_t AsymmetricKey::formatted_key_material(keymaster_key_format_t format,
                                                        UniquePtr<uint8_t[]>* material,
                                                        size_t* size) const {
    if (format != KM_KEY_FORMAT_X509)
        return KM_ERROR_UNSUPPORTED_KEY_FORMAT;

    if (material == NULL || size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (!InternalToEvp(pkey.get()))
        return TranslateLastOpenSslError();

    int key_data_length = i2d_PUBKEY(pkey.get(), NULL);
    if (key_data_length <= 0)
        return TranslateLastOpenSslError();

    material->reset(new uint8_t[key_data_length]);
    if (material->get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    uint8_t* tmp = material->get();
    if (i2d_PUBKEY(pkey.get(), &tmp) != key_data_length) {
        material->reset();
        return TranslateLastOpenSslError();
    }

    *size = key_data_length;
    return KM_ERROR_OK;
}

}  // namespace keymaster
