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

#ifndef EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_
#define EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_

#include <common/ote_error.h>
#include <hardware/keymaster.h>

namespace keymaster {

/**
 * Software OpenSSL-based Keymaster device.
 *
 * IMPORTANT MAINTAINER NOTE: Pointers to instances of this class must be castable to hw_device_t
 * and keymaster_device. This means it must remain a standard layout class (no virtual functions and
 * no data members which aren't standard layout), and device_ must be the first data member.
 * Assertions in the constructor validate compliance with those constraints.
 */
class TrustyKeymasterDevice {
  public:
    /*
     * These are the only symbols that will be exported by libtrustykeymaster.  All functionality
     * can be reached via the function pointers in keymaster_device.
     */
    __attribute__((visibility("default"))) TrustyKeymasterDevice(const hw_module_t* module);

    __attribute__((visibility("default"))) keymaster_device* device();
    __attribute__((visibility("default"))) hw_device_t* hw_device();

    ~TrustyKeymasterDevice();

    te_error_t session_error() { return te_error_; }

    int generate_keypair(const keymaster_keypair_t key_type, const void* key_params,
                         uint8_t** key_blob, size_t* key_blob_length);
    int import_keypair(const uint8_t* key, const size_t key_length, uint8_t** key_blob,
                       size_t* key_blob_length);
    int get_keypair_public(const uint8_t* key_blob, const size_t key_blob_length,
                           uint8_t** x509_data, size_t* x509_data_length);
    int sign_data(const void* signing_params, const uint8_t* key_blob, const size_t key_blob_length,
                  const uint8_t* data, const size_t data_length, uint8_t** signed_data,
                  size_t* signed_data_length);
    int verify_data(const void* signing_params, const uint8_t* key_blob,
                    const size_t key_blob_length, const uint8_t* signed_data,
                    const size_t signed_data_length, const uint8_t* signature,
                    const size_t signature_length);

  private:
    /*
     * These static methods are the functions referenced through the function pointers in
     * keymaster_device.  They're all trivial wrappers.
     */
    static int close_device(hw_device_t* dev);
    static int generate_keypair(const keymaster_device_t* dev, const keymaster_keypair_t key_type,
                                const void* key_params, uint8_t** keyBlob, size_t* keyBlobLength);
    static int import_keypair(const struct keymaster_device* dev, const uint8_t* key,
                              const size_t key_length, uint8_t** key_blob, size_t* key_blob_length);
    static int get_keypair_public(const struct keymaster_device* dev, const uint8_t* key_blob,
                                  const size_t key_blob_length, uint8_t** x509_data,
                                  size_t* x509_data_length);
    static int sign_data(const struct keymaster_device* dev, const void* signing_params,
                         const uint8_t* key_blob, const size_t key_blob_length, const uint8_t* data,
                         const size_t data_length, uint8_t** signed_data,
                         size_t* signed_data_length);
    static int verify_data(const struct keymaster_device* dev, const void* signing_params,
                           const uint8_t* key_blob, const size_t key_blob_length,
                           const uint8_t* signed_data, const size_t signed_data_length,
                           const uint8_t* signature, const size_t signature_length);

    keymaster_device device_;
    void* trusty_session_;
    te_error_t te_error_;
};

}  // namespace keymaster

#endif  // EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_
