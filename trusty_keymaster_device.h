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

#include <hardware/keymaster.h>

namespace keymaster {

/**
 * Software OpenSSL-based Keymaster device.
 *
 * IMPORTANT MAINTAINER NOTE: Pointers to instances of this class must be castable to
 * keymaster_device and hw_device_t. This means it must remain a standard layout class (no virtual
 * functions and no data members which aren't standard layout), and device_ must be the first data
 * member. Assertions in the constructor validate compliance with those constraints.
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

    // v0.1 through v0.3 entry points
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

    // v0.4 entry points
    static keymaster_error_t (*get_supported_algorithms)(const struct keymaster_device* dev,
                                                         keymaster_algorithm_t* algorithms,
                                                         size_t* algorithms_length);
    static keymaster_error_t (*get_supported_block_modes)(const struct keymaster_device* dev,
                                                          keymaster_algorithm_t algorithm,
                                                          keymaster_block_mode_t* modes,
                                                          size_t* modes_length);
    static keymaster_error_t (*get_supported_padding_modes)(const struct keymaster_device* dev,
                                                            keymaster_algorithm_t algorithm,
                                                            keymaster_padding_t* modes,
                                                            size_t* modes_length);
    static keymaster_error_t (*get_supported_digests)(const struct keymaster_device* dev,
                                                      keymaster_algorithm_t algorithm,
                                                      keymaster_digest_t* digests,
                                                      size_t* digests_length);
    static keymaster_error_t (*get_supported_import_formats)(const struct keymaster_device* dev,
                                                             keymaster_algorithm_t algorithm,
                                                             keymaster_key_format_t* formats,
                                                             size_t* formats_length);
    static keymaster_error_t (*get_supported_export_formats)(const struct keymaster_device* dev,
                                                             keymaster_algorithm_t algorithm,
                                                             keymaster_key_format_t* formats,
                                                             size_t* formats_length);
    static keymaster_error_t (*add_rng_entropy)(uint8_t* data, size_t data_length);
    static keymaster_error_t (*generate_key)(const struct keymaster_device* dev,
                                             const keymaster_key_param_t* params,
                                             size_t params_count, keymaster_key_blob_t* key_blob,
                                             keymaster_key_characteristics_t** characteristics);
    static void (*get_key_characteristics)(const struct keymaster_device* dev,
                                           const keymaster_key_blob_t* key_blob,
                                           const keymaster_blob_t* client_id,
                                           const keymaster_blob_t* app_data,
                                           keymaster_key_characteristics_t** characteristics);
    static void (*free_characteristics)(const struct keymaster_device* dev,
                                        const keymaster_key_characteristics_t* p);
    static void (*rescope)(const struct keymaster_device* dev,
                           const keymaster_key_param_t* new_params, size_t new_params_count,
                           keymaster_key_blob_t* key_blob,
                           keymaster_key_characteristics_t** characteristics);
    static keymaster_error_t (*import_key)(const struct keymaster_device* dev,
                                           const keymaster_key_param_t* params, size_t params_count,
                                           keymaster_key_format_t key_format,
                                           const uint8_t* key_data, size_t key_data_length,
                                           keymaster_key_blob_t* key_blob,
                                           keymaster_key_characteristics_t** characteristics);
    static keymaster_error_t (*export_key)(const struct keymaster_device* dev,
                                           keymaster_key_format_t export_format,
                                           const keymaster_key_blob_t* key_to_export,
                                           uint8_t** export_data, size_t* export_data_length);
    static keymaster_error_t (*delete_key)(const struct keymaster_device* dev,
                                           const keymaster_key_blob_t* key);
    static int (*delete_all_keys)(const struct keymaster_device* dev);
    static keymaster_error_t (*begin)(const struct keymaster_device* dev,
                                      keymaster_purpose_t purpose, const keymaster_key_blob_t* key,
                                      const keymaster_key_param_t* params, size_t params_count,
                                      keymaster_operation_handle_t* operation_handle);
    static keymaster_error_t (*update)(const struct keymaster_device* dev,
                                       keymaster_operation_handle_t operation_handle,
                                       const uint8_t* input, size_t input_length,
                                       size_t* input_consumed, uint8_t** output,
                                       size_t* output_length, size_t* output_written);
    static keymaster_error_t (*finish)(const struct keymaster_device* dev,
                                       keymaster_operation_handle_t operation_handle,
                                       const uint8_t* signature, size_t signature_length,
                                       uint8_t** output, size_t* output_length,
                                       size_t* output_written);
    static keymaster_error_t (*abort)(const struct keymaster_device* dev,
                                      keymaster_operation_handle_t operation_handle);

    keymaster_device device_;
    void* trusty_session;
};

}  // namespace keymaster

#endif  // EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_
