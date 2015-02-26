/*
 * Copyright 2015 The Android Open Source Project
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

#ifndef SYSTEM_KEYMASTER_SOFT_KEYMASTER_DEVICE_H_
#define SYSTEM_KEYMASTER_SOFT_KEYMASTER_DEVICE_H_

#include <stdlib.h>

#include <hardware/keymaster1.h>

#include <keymaster/google_keymaster.h>
#include <keymaster/logger.h>

#include <UniquePtr.h>

namespace keymaster {

class AuthorizationSet;

/**
 * Software OpenSSL-based Keymaster implementation.
 *
 * IMPORTANT MAINTAINER NOTE: Pointers to instances of this class must be castable to hw_device_t
 * and keymaster_device. This means it must remain a standard layout class (no virtual functions and
 * no data members which aren't standard layout), and device_ must be the first data member.
 * Assertions in the constructor validate compliance with those constraints.
 */
class SoftKeymasterDevice {
  public:
    SoftKeymasterDevice(Logger* logger);

    hw_device_t* hw_device();

    // Public only for testing
    void GetVersion(const GetVersionRequest& req, GetVersionResponse* rsp) {
        impl_->GetVersion(req, rsp);
    }

  private:
    static keymaster_error_t ExtractSigningParams(const void* signing_params,
                                                  const uint8_t* key_blob, size_t key_blob_length,
                                                  AuthorizationSet* auth_set);
    static void StoreDefaultNewKeyParams(AuthorizationSet* auth_set);

    static int close_device(hw_device_t* dev);

    /*
     * These static methods are the functions referenced through the function pointers in
     * keymaster_device.
     */

    // Version 0.3 and below APIs
    static int generate_keypair(const keymaster1_device_t* dev, const keymaster_keypair_t key_type,
                                const void* key_params, uint8_t** keyBlob, size_t* keyBlobLength);
    static int import_keypair(const struct keymaster1_device* dev, const uint8_t* key,
                              const size_t key_length, uint8_t** key_blob, size_t* key_blob_length);
    static int get_keypair_public(const keymaster1_device_t* dev, const uint8_t* key_blob,
                                  const size_t key_blob_length, uint8_t** x509_data,
                                  size_t* x509_data_length);
    static int sign_data(const keymaster1_device_t* dev, const void* signing_params,
                         const uint8_t* key_blob, const size_t key_blob_length, const uint8_t* data,
                         const size_t data_length, uint8_t** signed_data,
                         size_t* signed_data_length);
    static int verify_data(const keymaster1_device_t* dev, const void* signing_params,
                           const uint8_t* key_blob, const size_t key_blob_length,
                           const uint8_t* signed_data, const size_t signed_data_length,
                           const uint8_t* signature, const size_t signature_length);

    // Version 0.4 APIs.
    static keymaster_error_t get_supported_algorithms(const keymaster1_device_t* dev,
                                                      keymaster_algorithm_t** algorithms,
                                                      size_t* algorithms_length);
    static keymaster_error_t get_supported_block_modes(const keymaster1_device_t* dev,
                                                       keymaster_algorithm_t algorithm,
                                                       keymaster_purpose_t purpose,
                                                       keymaster_block_mode_t** modes,
                                                       size_t* modes_length);
    static keymaster_error_t get_supported_padding_modes(const keymaster1_device_t* dev,
                                                         keymaster_algorithm_t algorithm,
                                                         keymaster_purpose_t purpose,
                                                         keymaster_padding_t** modes,
                                                         size_t* modes_length);
    static keymaster_error_t get_supported_digests(const keymaster1_device_t* dev,
                                                   keymaster_algorithm_t algorithm,
                                                   keymaster_purpose_t purpose,
                                                   keymaster_digest_t** digests,
                                                   size_t* digests_length);
    static keymaster_error_t get_supported_import_formats(const keymaster1_device_t* dev,
                                                          keymaster_algorithm_t algorithm,
                                                          keymaster_key_format_t** formats,
                                                          size_t* formats_length);
    static keymaster_error_t get_supported_export_formats(const keymaster1_device_t* dev,
                                                          keymaster_algorithm_t algorithm,
                                                          keymaster_key_format_t** formats,
                                                          size_t* formats_length);
    static keymaster_error_t add_rng_entropy(const keymaster1_device_t* dev, const uint8_t* data,
                                             size_t data_length);
    static keymaster_error_t generate_key(const keymaster1_device_t* dev,
                                          const keymaster_key_param_t* params, size_t params_count,
                                          keymaster_key_blob_t* key_blob,
                                          keymaster_key_characteristics_t** characteristics);
    static keymaster_error_t get_key_characteristics(const keymaster1_device_t* dev,
                                                     const keymaster_key_blob_t* key_blob,
                                                     const keymaster_blob_t* client_id,
                                                     const keymaster_blob_t* app_data,
                                                     keymaster_key_characteristics_t** character);
    static keymaster_error_t rescope(const keymaster1_device_t* dev,
                                     const keymaster_key_param_t* new_params,
                                     size_t new_params_count, const keymaster_key_blob_t* key_blob,
                                     const keymaster_blob_t* client_id,
                                     const keymaster_blob_t* app_data,
                                     keymaster_key_blob_t* rescoped_key_blob,
                                     keymaster_key_characteristics_t** characteristics);
    static keymaster_error_t import_key(const keymaster1_device_t* dev,
                                        const keymaster_key_param_t* params, size_t params_count,
                                        keymaster_key_format_t key_format, const uint8_t* key_data,
                                        size_t key_data_length, keymaster_key_blob_t* key_blob,
                                        keymaster_key_characteristics_t** characteristics);
    static keymaster_error_t
    export_key(const keymaster1_device_t* dev, keymaster_key_format_t export_format,
               const keymaster_key_blob_t* key_to_export, const keymaster_blob_t* client_id,
               const keymaster_blob_t* app_data, uint8_t** export_data, size_t* export_data_length);
    static keymaster_error_t begin(const keymaster1_device_t* dev, keymaster_purpose_t purpose,
                                   const keymaster_key_blob_t* key,
                                   const keymaster_key_param_t* params, size_t params_count,
                                   keymaster_key_param_t** out_params, size_t* out_params_count,
                                   keymaster_operation_handle_t* operation_handle);
    static keymaster_error_t
    update(const keymaster1_device_t* dev, keymaster_operation_handle_t operation_handle,
           const keymaster_key_param_t* params, size_t params_count, const uint8_t* input,
           size_t input_length, size_t* input_consumed, uint8_t** output, size_t* output_length);
    static keymaster_error_t finish(const keymaster1_device_t* dev,
                                    keymaster_operation_handle_t operation_handle,
                                    const keymaster_key_param_t* params, size_t params_count,
                                    const uint8_t* signature, size_t signature_length,
                                    uint8_t** output, size_t* output_length);
    static keymaster_error_t abort(const keymaster1_device_t* dev,
                                   keymaster_operation_handle_t operation_handle);

    keymaster1_device_t device_;
    UniquePtr<GoogleKeymaster> impl_;
};

}  // namespace keymaster

#endif  // EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_DEVICE_H_
