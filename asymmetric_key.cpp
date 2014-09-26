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

#include <openssl/x509.h>

#include <keymaster/keymaster_defs.h>

#include "asymmetric_key.h"
#include "openssl_utils.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

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
        return KM_ERROR_UNKNOWN_ERROR;

    return KM_ERROR_OK;
}

keymaster_error_t AsymmetricKey::key_material(UniquePtr<uint8_t[]>* material, size_t* size) const {
    if (material == NULL || size == NULL)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UniquePtr<EVP_PKEY, EVP_PKEY_Delete> pkey(EVP_PKEY_new());
    if (pkey.get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    if (!InternalToEvp(pkey.get()))
        return KM_ERROR_UNKNOWN_ERROR;

    *size = i2d_PrivateKey(pkey.get(), NULL /* key_data*/);
    if (*size <= 0)
        return KM_ERROR_UNKNOWN_ERROR;

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
        return KM_ERROR_UNKNOWN_ERROR;

    int key_data_length = i2d_PUBKEY(pkey.get(), NULL);
    if (key_data_length <= 0)
        return KM_ERROR_UNKNOWN_ERROR;

    material->reset(new uint8_t[key_data_length]);
    if (material->get() == NULL)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    uint8_t* tmp = material->get();
    if (i2d_PUBKEY(pkey.get(), &tmp) != key_data_length) {
        material->reset();
        return KM_ERROR_UNKNOWN_ERROR;
    }

    *size = key_data_length;
    return KM_ERROR_OK;
}

}  // namespace keymaster
