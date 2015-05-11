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

#include "symmetric_key.h"

#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <keymaster/logger.h>

#include "aes_key.h"
#include "hmac_key.h"
#include "openssl_err.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

Key* SymmetricKeyFactory::GenerateKey(const AuthorizationSet& key_description,
                                      keymaster_error_t* error) {
    UniquePtr<SymmetricKey> key(CreateKeyAndValidateSize(key_description, error));
    if (!key.get())
        return NULL;

    if (RAND_bytes(key->key_data_.get(), key->key_data_size_) != 1) {
        LOG_E("Error %ul generating %d bit AES key", ERR_get_error(), key->key_data_size_ * 8);
        *error = TranslateLastOpenSslError();
        return NULL;
    }

    if (*error != KM_ERROR_OK)
        return NULL;
    return key.release();
}

Key* SymmetricKeyFactory::ImportKey(const AuthorizationSet& key_description,
                                    keymaster_key_format_t format, const uint8_t* key_material,
                                    size_t key_material_length, keymaster_error_t* error) {
    UniquePtr<SymmetricKey> key(CreateKeyAndValidateSize(key_description, error));
    if (!key.get())
        return NULL;

    if (format != KM_KEY_FORMAT_RAW) {
        *error = KM_ERROR_UNSUPPORTED_KEY_FORMAT;
        return NULL;
    }

    if (key->key_data_size_ != key_material_length) {
        LOG_E("Expected %d byte key data but got %d bytes", key->key_data_size_,
              key_material_length);
        *error = KM_ERROR_INVALID_KEY_BLOB;
        return NULL;
    }

    key->key_data_size_ = key_material_length;
    memcpy(key->key_data_.get(), key_material, key_material_length);
    return key.release();
}

static const keymaster_key_format_t supported_import_formats[] = {KM_KEY_FORMAT_RAW};
const keymaster_key_format_t* SymmetricKeyFactory::SupportedImportFormats(size_t* format_count) {
    *format_count = array_length(supported_import_formats);
    return supported_import_formats;
}

SymmetricKey* SymmetricKeyFactory::CreateKeyAndValidateSize(const AuthorizationSet& key_description,
                                                            keymaster_error_t* error) {
    if (!error)
        return NULL;
    *error = KM_ERROR_OK;

    UniquePtr<SymmetricKey> key(CreateKey(key_description));

    uint32_t key_size_bits;
    if (!key_description.GetTagValue(TAG_KEY_SIZE, &key_size_bits) || key_size_bits % 8 != 0) {
        *error = KM_ERROR_UNSUPPORTED_KEY_SIZE;
        return NULL;
    }

    *error = key->set_size(key_size_bits / 8);
    if (*error != KM_ERROR_OK)
        return NULL;

    return key.release();
}

SymmetricKey::SymmetricKey(const UnencryptedKeyBlob& blob, keymaster_error_t* error)
    : Key(blob), key_data_size_(blob.unencrypted_key_material_length()) {
    key_data_.reset(new uint8_t[key_data_size_]);
    if (!key_data_.get()) {
        if (error)
            *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        key_data_size_ = 0;
        return;
    }

    memcpy(key_data_.get(), blob.unencrypted_key_material(), key_data_size_);
    if (error)
        *error = KM_ERROR_OK;
}

SymmetricKey::~SymmetricKey() {
    memset_s(key_data_.get(), 0, key_data_size_);
}

keymaster_error_t SymmetricKey::key_material(UniquePtr<uint8_t[]>* key_material,
                                             size_t* size) const {
    *size = key_data_size_;
    key_material->reset(new uint8_t[*size]);
    if (!key_material->get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(key_material->get(), key_data_.get(), *size);
    return KM_ERROR_OK;
}

keymaster_error_t SymmetricKey::set_size(size_t key_size) {
    if (!size_supported(key_size))
        return KM_ERROR_UNSUPPORTED_KEY_SIZE;

    key_data_.reset(new uint8_t[key_size]);
    if (!key_data_.get())
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    key_data_size_ = key_size;

    return KM_ERROR_OK;
}

}  // namespace keymaster
