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

#ifndef SYSTEM_KEYMASTER_SYMMETRIC_KEY_H_
#define SYSTEM_KEYMASTER_SYMMETRIC_KEY_H_

#include "key.h"

namespace keymaster {

class SymmetricKey;

class SymmetricKeyFactory : public KeyFactory {
    virtual Key* GenerateKey(const AuthorizationSet& key_description, const Logger& logger,
                             keymaster_error_t* error);
    virtual Key* ImportKey(const AuthorizationSet&, keymaster_key_format_t, const uint8_t*, size_t,
                           const Logger&, keymaster_error_t* error) {
        *error = KM_ERROR_UNIMPLEMENTED;
        return NULL;
    }

    virtual const keymaster_key_format_t* SupportedImportFormats(size_t* format_count) {
        return NoFormats(format_count);
    }
    virtual const keymaster_key_format_t* SupportedExportFormats(size_t* format_count) {
        return NoFormats(format_count);
    };

  private:
    virtual SymmetricKey* CreateKey(const AuthorizationSet& auths, const Logger& logger) = 0;
    const keymaster_key_format_t* NoFormats(size_t* format_count) {
        *format_count = 0;
        return NULL;
    }
};

class SymmetricKey : public Key {
  public:
    static const int MAX_KEY_SIZE = 32;
    static const int MAX_MAC_LENGTH = 32;
    static const uint32_t MAX_CHUNK_LENGTH = 64 * 1024;

    ~SymmetricKey();

    virtual keymaster_error_t key_material(UniquePtr<uint8_t[]>* key_material, size_t* size) const;
    virtual keymaster_error_t formatted_key_material(keymaster_key_format_t, UniquePtr<uint8_t[]>*,
                                                     size_t*) const {
        return KM_ERROR_UNIMPLEMENTED;
    }

  protected:
    keymaster_error_t error_;

    SymmetricKey(const UnencryptedKeyBlob& blob, const Logger& logger, keymaster_error_t* error);

    const uint8_t* key_data() const { return key_data_; }
    size_t key_data_size() const { return key_data_size_; }

    SymmetricKey(const AuthorizationSet& auths, const Logger& logger) : Key(auths, logger) {}

  private:
    friend SymmetricKeyFactory;

    keymaster_error_t LoadKey(const UnencryptedKeyBlob& blob);

    size_t key_data_size_;
    uint8_t key_data_[MAX_KEY_SIZE];
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_AES_KEY_H_
