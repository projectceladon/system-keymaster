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
#include <keymaster/android_keymaster_utils.h>

#include "openssl_err.h"
#include "openssl_utils.h"

namespace keymaster {

keymaster_error_t
AsymmetricKeyFactory::KeyMaterialToEvpKey(keymaster_key_format_t key_format,
                                          const KeymasterKeyBlob& key_material,
                                          UniquePtr<EVP_PKEY, EVP_PKEY_Delete>* pkey) const {
    if (key_format != KM_KEY_FORMAT_PKCS8)
        return KM_ERROR_UNSUPPORTED_KEY_FORMAT;

    return convert_pkcs8_blob_to_evp(key_material.key_material, key_material.key_material_size,
                                     keymaster_key_type(), pkey);
}

keymaster_error_t AsymmetricKeyFactory::EvpKeyToKeyMaterial(const EVP_PKEY* pkey,
                                                            KeymasterKeyBlob* key_blob) const {
    int key_data_size = i2d_PrivateKey(pkey, NULL /* key_data*/);
    if (key_data_size <= 0)
        return TranslateLastOpenSslError();

    key_blob->Reset(key_data_size);
    if (!key_blob->key_material)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    uint8_t* tmp = key_blob->writable_data();
    i2d_PrivateKey(pkey, &tmp);

    return KM_ERROR_OK;
}

static const keymaster_key_format_t supported_import_formats[] = {KM_KEY_FORMAT_PKCS8};
const keymaster_key_format_t*
AsymmetricKeyFactory::SupportedImportFormats(size_t* format_count) const {
    *format_count = array_length(supported_import_formats);
    return supported_import_formats;
}

static const keymaster_key_format_t supported_export_formats[] = {KM_KEY_FORMAT_X509};
const keymaster_key_format_t*
AsymmetricKeyFactory::SupportedExportFormats(size_t* format_count) const {
    *format_count = array_length(supported_export_formats);
    return supported_export_formats;
}

keymaster_error_t AsymmetricKeyFactory::LoadKey(const KeymasterKeyBlob& key_material,
                                                const AuthorizationSet& hw_enforced,
                                                const AuthorizationSet& sw_enforced,
                                                UniquePtr<Key>* key) const {
    UniquePtr<AsymmetricKey> asymmetric_key;
    keymaster_error_t error = CreateEmptyKey(hw_enforced, sw_enforced, &asymmetric_key);
    if (error != KM_ERROR_OK)
        return error;

    const uint8_t* tmp = key_material.key_material;
    EVP_PKEY* pkey =
        d2i_PrivateKey(evp_key_type(), NULL /* pkey */, &tmp, key_material.key_material_size);
    if (!pkey)
        return TranslateLastOpenSslError();
    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey_deleter(pkey);

    if (!asymmetric_key->EvpToInternal(pkey))
        error = TranslateLastOpenSslError();
    else
        key->reset(asymmetric_key.release());

    return error;
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
