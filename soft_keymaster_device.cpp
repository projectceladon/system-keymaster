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

#include <keymaster/soft_keymaster_device.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>

#include <algorithm>

#include <type_traits>

#include <hardware/keymaster.h>
#define LOG_TAG "SoftKeymasterDevice"
#include <cutils/log.h>

#include <keymaster/authorization_set.h>
#include <keymaster/google_keymaster_messages.h>
#include <keymaster/key_blob.h>
#include <keymaster/soft_keymaster_logger.h>

#include "google_softkeymaster.h"

const uint32_t SEND_BUF_SIZE = 8192;
const uint32_t RECV_BUF_SIZE = 8192;

struct keystore_module soft_keymaster_device_module = {
    .common =
        {
         .tag = HARDWARE_MODULE_TAG,
         .module_api_version = KEYMASTER_MODULE_API_VERSION_0_4,
         .hal_api_version = HARDWARE_HAL_API_VERSION,
         .id = KEYSTORE_HARDWARE_MODULE_ID,
         .name = "Keymaster OpenSSL HAL",
         .author = "The Android Open Source Project",
         .methods = NULL,
         .dso = 0,
         .reserved = {},
        },
};

namespace keymaster {

SoftKeymasterDevice::SoftKeymasterDevice(Logger* logger)
    : impl_(new GoogleSoftKeymaster(16, logger)) {
#if __cplusplus >= 201103L || defined(__GXX_EXPERIMENTAL_CXX0X__)
    static_assert(std::is_standard_layout<SoftKeymasterDevice>::value,
                  "SoftKeymasterDevice must be standard layout");
    static_assert(offsetof(SoftKeymasterDevice, device_) == 0,
                  "device_ must be the first member of KeymasterOpenSsl");
    static_assert(offsetof(SoftKeymasterDevice, device_.common) == 0,
                  "common must be the first member of keymaster_device");
#else
    assert(reinterpret_cast<keymaster_device*>(this) == &device_);
    assert(reinterpret_cast<hw_device_t*>(this) == &(device_.common));
#endif
    logger->info("Creating device");
    logger->debug("Device address: %p", this);

    memset(&device_, 0, sizeof(device_));

    device_.common.tag = HARDWARE_DEVICE_TAG;
    device_.common.version = 1;
    device_.common.module = reinterpret_cast<hw_module_t*>(&soft_keymaster_device_module);
    device_.common.close = &close_device;

    device_.flags =
        KEYMASTER_SOFTWARE_ONLY | KEYMASTER_BLOBS_ARE_STANDALONE | KEYMASTER_SUPPORTS_EC;

    // V0.3 APIs
    device_.generate_keypair = generate_keypair;
    device_.import_keypair = import_keypair;
    device_.get_keypair_public = get_keypair_public;
    device_.delete_keypair = NULL;
    device_.delete_all = NULL;
    device_.sign_data = sign_data;
    device_.verify_data = verify_data;

    // V0.4 APIs
    device_.get_supported_algorithms = get_supported_algorithms;
    device_.get_supported_block_modes = get_supported_block_modes;
    device_.get_supported_padding_modes = get_supported_padding_modes;
    device_.get_supported_digests = get_supported_digests;
    device_.get_supported_import_formats = get_supported_import_formats;
    device_.get_supported_export_formats = get_supported_export_formats;
    device_.add_rng_entropy = add_rng_entropy;
    device_.generate_key = generate_key;
    device_.get_key_characteristics = get_key_characteristics;
    device_.rescope = rescope;
    device_.import_key = import_key;
    device_.export_key = export_key;
    device_.delete_key = NULL;
    device_.delete_all_keys = NULL;
    device_.begin = begin;
    device_.update = update;
    device_.finish = finish;
    device_.abort = abort;

    device_.context = NULL;
}

const uint64_t HUNDRED_YEARS = 1000LL * 60 * 60 * 24 * 365 * 100;

hw_device_t* SoftKeymasterDevice::hw_device() {
    return &device_.common;
}

static keymaster_key_characteristics_t* BuildCharacteristics(const AuthorizationSet& hw_enforced,
                                                             const AuthorizationSet& sw_enforced) {
    keymaster_key_characteristics_t* characteristics =
        reinterpret_cast<keymaster_key_characteristics_t*>(
            malloc(sizeof(keymaster_key_characteristics_t)));
    if (characteristics) {
        hw_enforced.CopyToParamSet(&characteristics->hw_enforced);
        sw_enforced.CopyToParamSet(&characteristics->sw_enforced);
    }
    return characteristics;
}

template <typename RequestType>
static void AddClientAndAppData(const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
                                RequestType* request) {
    request->additional_params.Clear();
    if (client_id)
        request->additional_params.push_back(TAG_APPLICATION_ID, *client_id);
    if (app_data)
        request->additional_params.push_back(TAG_APPLICATION_DATA, *app_data);
}

static inline SoftKeymasterDevice* convert_device(const keymaster_device* dev) {
    return reinterpret_cast<SoftKeymasterDevice*>(const_cast<keymaster_device*>(dev));
}

/* static */
int SoftKeymasterDevice::close_device(hw_device_t* dev) {
    delete reinterpret_cast<SoftKeymasterDevice*>(dev);
    return 0;
}

/* static */
int SoftKeymasterDevice::generate_keypair(const keymaster_device_t* dev,
                                          const keymaster_keypair_t key_type,
                                          const void* key_params, uint8_t** key_blob,
                                          size_t* key_blob_length) {
    convert_device(dev)->impl_->logger().debug("Device received generate_keypair");

    GenerateKeyRequest req;
    StoreDefaultNewKeyParams(&req.key_description);

    switch (key_type) {
    case TYPE_RSA: {
        req.key_description.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        const keymaster_rsa_keygen_params_t* rsa_params =
            static_cast<const keymaster_rsa_keygen_params_t*>(key_params);
        convert_device(dev)->impl_->logger().debug(
            "Generating RSA pair, modulus size: %u, public exponent: %lu", rsa_params->modulus_size,
            rsa_params->public_exponent);
        req.key_description.push_back(TAG_KEY_SIZE, rsa_params->modulus_size);
        req.key_description.push_back(TAG_RSA_PUBLIC_EXPONENT, rsa_params->public_exponent);
        break;
    }

    case TYPE_EC: {
        req.key_description.push_back(TAG_ALGORITHM, KM_ALGORITHM_ECDSA);
        const keymaster_ec_keygen_params_t* ec_params =
            static_cast<const keymaster_ec_keygen_params_t*>(key_params);
        convert_device(dev)->impl_->logger().debug("Generating ECDSA pair, key size: %u",
                                                   ec_params->field_size);
        req.key_description.push_back(TAG_KEY_SIZE, ec_params->field_size);
        break;
    }

    default:
        convert_device(dev)->impl_->logger().debug("Received request for unsuported key type %d",
                                                   key_type);
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }

    GenerateKeyResponse rsp;
    convert_device(dev)->impl_->GenerateKey(req, &rsp);

    *key_blob_length = rsp.key_blob.key_material_size;
    *key_blob = static_cast<uint8_t*>(malloc(*key_blob_length));
    if (!*key_blob)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(*key_blob, rsp.key_blob.key_material, *key_blob_length);
    convert_device(dev)->impl_->logger().debug("Returning %d bytes in key blob\n",
                                               (int)*key_blob_length);

    return KM_ERROR_OK;
}

/* static */
int SoftKeymasterDevice::import_keypair(const keymaster_device_t* dev, const uint8_t* key,
                                        const size_t key_length, uint8_t** key_blob,
                                        size_t* key_blob_length) {
    convert_device(dev)->impl_->logger().debug("Device received import_keypair");

    ImportKeyRequest request;
    StoreDefaultNewKeyParams(&request.key_description);
    request.SetKeyMaterial(key, key_length);
    request.key_format = KM_KEY_FORMAT_PKCS8;

    ImportKeyResponse response;
    convert_device(dev)->impl_->ImportKey(request, &response);

    *key_blob_length = response.key_blob.key_material_size;
    *key_blob = static_cast<uint8_t*>(malloc(*key_blob_length));
    if (!*key_blob)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(*key_blob, response.key_blob.key_material, *key_blob_length);
    convert_device(dev)->impl_->logger().debug("Returning %d bytes in key blob\n",
                                               (int)*key_blob_length);

    return KM_ERROR_OK;
}

/* static */
int SoftKeymasterDevice::get_keypair_public(const struct keymaster_device* dev,
                                            const uint8_t* key_blob, const size_t key_blob_length,
                                            uint8_t** x509_data, size_t* x509_data_length) {
    convert_device(dev)->impl_->logger().debug("Device received get_keypair_public");

    ExportKeyRequest req;
    req.SetKeyMaterial(key_blob, key_blob_length);
    req.key_format = KM_KEY_FORMAT_X509;

    ExportKeyResponse rsp;
    convert_device(dev)->impl_->ExportKey(req, &rsp);

    *x509_data_length = rsp.key_data_length;
    *x509_data = static_cast<uint8_t*>(malloc(*x509_data_length));
    if (!*x509_data)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(*x509_data, rsp.key_data, *x509_data_length);
    convert_device(dev)->impl_->logger().debug("Returning %d bytes in x509 key\n",
                                               (int)*x509_data_length);

    return KM_ERROR_OK;
}

/* static */
int SoftKeymasterDevice::sign_data(const keymaster_device_t* dev, const void* params,
                                   const uint8_t* key_blob, const size_t key_blob_length,
                                   const uint8_t* data, const size_t data_length,
                                   uint8_t** signed_data, size_t* signed_data_length) {
    convert_device(dev)->impl_->logger().debug("Device received sign_data");

    *signed_data_length = 0;

    BeginOperationRequest begin_request;
    begin_request.purpose = KM_PURPOSE_SIGN;
    begin_request.SetKeyMaterial(key_blob, key_blob_length);
    keymaster_error_t err =
        ExtractSigningParams(params, key_blob, key_blob_length, &begin_request.additional_params);
    if (err != KM_ERROR_OK)
        return err;

    BeginOperationResponse begin_response;
    convert_device(dev)->impl_->BeginOperation(begin_request, &begin_response);
    if (begin_response.error != KM_ERROR_OK)
        return begin_response.error;

    UpdateOperationRequest update_request;
    update_request.op_handle = begin_response.op_handle;
    update_request.input.Reinitialize(data, data_length);
    UpdateOperationResponse update_response;
    convert_device(dev)->impl_->UpdateOperation(update_request, &update_response);
    if (update_response.error != KM_ERROR_OK)
        return update_response.error;

    FinishOperationRequest finish_request;
    finish_request.op_handle = begin_response.op_handle;
    FinishOperationResponse finish_response;
    convert_device(dev)->impl_->FinishOperation(finish_request, &finish_response);
    if (finish_response.error != KM_ERROR_OK)
        return finish_response.error;

    *signed_data_length = finish_response.output.available_read();
    *signed_data = static_cast<uint8_t*>(malloc(*signed_data_length));
    if (!*signed_data)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    if (!finish_response.output.read(*signed_data, *signed_data_length))
        return KM_ERROR_UNKNOWN_ERROR;
    return KM_ERROR_OK;
}

/* static */
int SoftKeymasterDevice::verify_data(const keymaster_device_t* dev, const void* params,
                                     const uint8_t* key_blob, const size_t key_blob_length,
                                     const uint8_t* signed_data, const size_t signed_data_length,
                                     const uint8_t* signature, const size_t signature_length) {
    convert_device(dev)->impl_->logger().debug("Device received verify_data");

    BeginOperationRequest begin_request;
    begin_request.purpose = KM_PURPOSE_VERIFY;
    begin_request.SetKeyMaterial(key_blob, key_blob_length);
    {
        keymaster_error_t err = ExtractSigningParams(params, key_blob, key_blob_length,
                                                     &begin_request.additional_params);
        if (err != KM_ERROR_OK)
            return err;
    }

    BeginOperationResponse begin_response;
    convert_device(dev)->impl_->BeginOperation(begin_request, &begin_response);
    if (begin_response.error != KM_ERROR_OK)
        return begin_response.error;

    UpdateOperationRequest update_request;
    update_request.op_handle = begin_response.op_handle;
    update_request.input.Reinitialize(signed_data, signed_data_length);
    UpdateOperationResponse update_response;
    convert_device(dev)->impl_->UpdateOperation(update_request, &update_response);
    if (update_response.error != KM_ERROR_OK)
        return update_response.error;

    FinishOperationRequest finish_request;
    finish_request.op_handle = begin_response.op_handle;
    finish_request.signature.Reinitialize(signature, signature_length);
    FinishOperationResponse finish_response;
    convert_device(dev)->impl_->FinishOperation(finish_request, &finish_response);
    if (finish_response.error != KM_ERROR_OK)
        return finish_response.error;
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::get_supported_algorithms(const struct keymaster_device* dev,
                                                                keymaster_algorithm_t** algorithms,
                                                                size_t* algorithms_length) {
    if (!algorithms || !algorithms_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    SupportedResponse<keymaster_algorithm_t> response;
    convert_device(dev)->impl_->SupportedAlgorithms(&response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    *algorithms_length = response.results_length;
    *algorithms =
        reinterpret_cast<keymaster_algorithm_t*>(malloc(*algorithms_length * sizeof(**algorithms)));
    if (!*algorithms)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    std::copy(response.results, response.results + response.results_length, *algorithms);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::get_supported_block_modes(const struct keymaster_device* dev,
                                                                 keymaster_algorithm_t algorithm,
                                                                 keymaster_purpose_t purpose,
                                                                 keymaster_block_mode_t** modes,
                                                                 size_t* modes_length) {
    if (!modes || !modes_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    SupportedResponse<keymaster_block_mode_t> response;
    convert_device(dev)->impl_->SupportedBlockModes(algorithm, purpose, &response);

    if (response.error != KM_ERROR_OK)
        return response.error;

    *modes_length = response.results_length;
    *modes = reinterpret_cast<keymaster_block_mode_t*>(malloc(*modes_length * sizeof(**modes)));
    if (!*modes)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    std::copy(response.results, response.results + response.results_length, *modes);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::get_supported_padding_modes(
    const struct keymaster_device* dev, keymaster_algorithm_t algorithm,
    keymaster_purpose_t purpose, keymaster_padding_t** modes, size_t* modes_length) {
    if (!modes || !modes_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    SupportedResponse<keymaster_padding_t> response;
    convert_device(dev)->impl_->SupportedPaddingModes(algorithm, purpose, &response);

    if (response.error != KM_ERROR_OK)
        return response.error;

    *modes_length = response.results_length;
    *modes = reinterpret_cast<keymaster_padding_t*>(malloc(*modes_length * sizeof(**modes)));
    if (!*modes)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    std::copy(response.results, response.results + response.results_length, *modes);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::get_supported_digests(const struct keymaster_device* dev,
                                                             keymaster_algorithm_t algorithm,
                                                             keymaster_purpose_t purpose,
                                                             keymaster_digest_t** digests,
                                                             size_t* digests_length) {
    if (!digests || !digests_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    SupportedResponse<keymaster_digest_t> response;
    convert_device(dev)->impl_->SupportedDigests(algorithm, purpose, &response);

    if (response.error != KM_ERROR_OK)
        return response.error;

    *digests_length = response.results_length;
    *digests = reinterpret_cast<keymaster_digest_t*>(malloc(*digests_length * sizeof(**digests)));
    if (!*digests)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    std::copy(response.results, response.results + response.results_length, *digests);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::get_supported_import_formats(
    const struct keymaster_device* dev, keymaster_algorithm_t algorithm,
    keymaster_key_format_t** formats, size_t* formats_length) {
    if (!formats || !formats_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    SupportedResponse<keymaster_key_format_t> response;
    convert_device(dev)->impl_->SupportedImportFormats(algorithm, &response);

    if (response.error != KM_ERROR_OK)
        return response.error;

    *formats_length = response.results_length;
    *formats =
        reinterpret_cast<keymaster_key_format_t*>(malloc(*formats_length * sizeof(**formats)));
    if (!*formats)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    std::copy(response.results, response.results + response.results_length, *formats);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::get_supported_export_formats(
    const struct keymaster_device* dev, keymaster_algorithm_t algorithm,
    keymaster_key_format_t** formats, size_t* formats_length) {
    if (!formats || !formats_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    SupportedResponse<keymaster_key_format_t> response;
    convert_device(dev)->impl_->SupportedExportFormats(algorithm, &response);

    if (response.error != KM_ERROR_OK)
        return response.error;

    *formats_length = response.results_length;
    *formats =
        reinterpret_cast<keymaster_key_format_t*>(malloc(*formats_length * sizeof(**formats)));
    if (!*formats)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    std::copy(response.results, response.results + *formats_length, *formats);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::add_rng_entropy(const struct keymaster_device* /* dev */,
                                                       const uint8_t* /* data */,
                                                       size_t /* data_length */) {
    return KM_ERROR_UNIMPLEMENTED;
}

/* static */
keymaster_error_t SoftKeymasterDevice::generate_key(
    const struct keymaster_device* dev, const keymaster_key_param_t* params, size_t params_count,
    keymaster_key_blob_t* key_blob, keymaster_key_characteristics_t** characteristics) {

    if (!key_blob)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    GenerateKeyRequest request;
    request.key_description.Reinitialize(params, params_count);

    GenerateKeyResponse response;
    convert_device(dev)->impl_->GenerateKey(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    key_blob->key_material_size = response.key_blob.key_material_size;
    uint8_t* tmp = reinterpret_cast<uint8_t*>(malloc(key_blob->key_material_size));
    if (!tmp)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(tmp, response.key_blob.key_material, response.key_blob.key_material_size);
    key_blob->key_material = tmp;

    if (characteristics) {
        *characteristics = BuildCharacteristics(response.enforced, response.unenforced);
        if (!*characteristics)
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }

    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::get_key_characteristics(
    const struct keymaster_device* dev, const keymaster_key_blob_t* key_blob,
    const keymaster_blob_t* client_id, const keymaster_blob_t* app_data,
    keymaster_key_characteristics_t** characteristics) {
    if (!key_blob)
        return KM_ERROR_INVALID_KEY_BLOB;

    if (!characteristics)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    GetKeyCharacteristicsRequest request;
    request.SetKeyMaterial(*key_blob);
    AddClientAndAppData(client_id, app_data, &request);

    GetKeyCharacteristicsResponse response;
    convert_device(dev)->impl_->GetKeyCharacteristics(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    *characteristics = BuildCharacteristics(response.enforced, response.unenforced);
    if (!*characteristics)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::rescope(
    const struct keymaster_device* /* dev */, const keymaster_key_param_t* /* new_params */,
    size_t /* new_params_count */, const keymaster_key_blob_t* /* key_blob */,
    const keymaster_blob_t* /* client_id */, const keymaster_blob_t* /* app_data */,
    keymaster_key_blob_t* /* rescoped_key_blob */,
    keymaster_key_characteristics_t** /* characteristics */) {
    return KM_ERROR_UNIMPLEMENTED;
}

/* static */
keymaster_error_t SoftKeymasterDevice::import_key(
    const struct keymaster_device* dev, const keymaster_key_param_t* params, size_t params_count,
    keymaster_key_format_t key_format, const uint8_t* key_data, size_t key_data_length,
    keymaster_key_blob_t* key_blob, keymaster_key_characteristics_t** characteristics) {
    if (!params || !key_data)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!key_blob)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    *characteristics = NULL;

    ImportKeyRequest request;
    request.key_description.Reinitialize(params, params_count);
    request.key_format = key_format;
    request.SetKeyMaterial(key_data, key_data_length);

    ImportKeyResponse response;
    convert_device(dev)->impl_->ImportKey(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    key_blob->key_material_size = response.key_blob.key_material_size;
    key_blob->key_material = reinterpret_cast<uint8_t*>(malloc(key_blob->key_material_size));
    if (!key_blob->key_material)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(const_cast<uint8_t*>(key_blob->key_material), response.key_blob.key_material,
           response.key_blob.key_material_size);

    if (characteristics) {
        *characteristics = BuildCharacteristics(response.enforced, response.unenforced);
        if (!*characteristics)
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::export_key(
    const struct keymaster_device* dev, keymaster_key_format_t export_format,
    const keymaster_key_blob_t* key_to_export, const keymaster_blob_t* client_id,
    const keymaster_blob_t* app_data, uint8_t** export_data, size_t* export_data_length) {
    if (!key_to_export || !key_to_export->key_material)
        return KM_ERROR_INVALID_KEY_BLOB;

    if (!export_data || !export_data_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    *export_data = NULL;
    *export_data_length = 0;

    ExportKeyRequest request;
    request.key_format = export_format;
    request.SetKeyMaterial(*key_to_export);
    AddClientAndAppData(client_id, app_data, &request);

    ExportKeyResponse response;
    convert_device(dev)->impl_->ExportKey(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    *export_data_length = response.key_data_length;
    *export_data = reinterpret_cast<uint8_t*>(malloc(*export_data_length));
    if (!export_data)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(*export_data, response.key_data, *export_data_length);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t
SoftKeymasterDevice::begin(const struct keymaster_device* dev, keymaster_purpose_t purpose,
                           const keymaster_key_blob_t* key, const keymaster_key_param_t* params,
                           size_t params_count, keymaster_key_param_t** out_params,
                           size_t* out_params_count,
                           keymaster_operation_handle_t* operation_handle) {
    if (!key || !key->key_material)
        return KM_ERROR_INVALID_KEY_BLOB;

    if (!operation_handle || !out_params || !out_params_count)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    *out_params = NULL;
    *out_params_count = 0;

    BeginOperationRequest request;
    request.purpose = purpose;
    request.SetKeyMaterial(*key);
    request.additional_params.Reinitialize(params, params_count);

    BeginOperationResponse response;
    convert_device(dev)->impl_->BeginOperation(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    *operation_handle = response.op_handle;
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::update(const struct keymaster_device* dev,
                                              keymaster_operation_handle_t operation_handle,
                                              const keymaster_key_param_t* params,
                                              size_t params_count, const uint8_t* input,
                                              size_t input_length, size_t* input_consumed,
                                              uint8_t** output, size_t* output_length) {
    if (!input)
        return KM_ERROR_UNEXPECTED_NULL_POINTER;

    if (!input_consumed || !output || !output_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    UpdateOperationRequest request;
    request.op_handle = operation_handle;
    request.input.Reinitialize(input, input_length);
    request.additional_params.Reinitialize(params, params_count);

    UpdateOperationResponse response;
    convert_device(dev)->impl_->UpdateOperation(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    *input_consumed = response.input_consumed;
    *output_length = response.output.available_read();
    *output = reinterpret_cast<uint8_t*>(malloc(*output_length));
    if (!*output)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(*output, response.output.peek_read(), *output_length);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::finish(const struct keymaster_device* dev,
                                              keymaster_operation_handle_t operation_handle,
                                              const keymaster_key_param_t* params,
                                              size_t params_count, const uint8_t* signature,
                                              size_t signature_length, uint8_t** output,
                                              size_t* output_length) {
    if (!output || !output_length)
        return KM_ERROR_OUTPUT_PARAMETER_NULL;

    FinishOperationRequest request;
    request.op_handle = operation_handle;
    if (signature)
        request.signature.Reinitialize(signature, signature_length);
    request.additional_params.Reinitialize(params, params_count);

    FinishOperationResponse response;
    convert_device(dev)->impl_->FinishOperation(request, &response);
    if (response.error != KM_ERROR_OK)
        return response.error;

    *output_length = response.output.available_read();
    *output = reinterpret_cast<uint8_t*>(malloc(*output_length));
    if (!*output)
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    memcpy(*output, response.output.peek_read(), *output_length);
    return KM_ERROR_OK;
}

/* static */
keymaster_error_t SoftKeymasterDevice::abort(const struct keymaster_device* dev,
                                             keymaster_operation_handle_t operation_handle) {
    return convert_device(dev)->impl_->AbortOperation(operation_handle);
}

/* static */
keymaster_error_t SoftKeymasterDevice::ExtractSigningParams(const void* signing_params,
                                                            const uint8_t* key_blob,
                                                            size_t key_blob_length,
                                                            AuthorizationSet* auth_set) {
    KeyBlob blob(key_blob, key_blob_length);
    if (blob.error() != KM_ERROR_OK)
        return blob.error();

    switch (blob.algorithm()) {
    case KM_ALGORITHM_RSA: {
        const keymaster_rsa_sign_params_t* rsa_params =
            reinterpret_cast<const keymaster_rsa_sign_params_t*>(signing_params);
        if (rsa_params->digest_type != DIGEST_NONE)
            return KM_ERROR_UNSUPPORTED_DIGEST;
        if (rsa_params->padding_type != PADDING_NONE)
            return KM_ERROR_UNSUPPORTED_PADDING_MODE;
        if (!auth_set->push_back(TAG_DIGEST, DIGEST_NONE) ||
            !auth_set->push_back(TAG_PADDING, KM_PAD_NONE))
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    } break;
    case KM_ALGORITHM_DSA: {
        const keymaster_dsa_sign_params_t* dsa_params =
            reinterpret_cast<const keymaster_dsa_sign_params_t*>(signing_params);
        if (dsa_params->digest_type != DIGEST_NONE)
            return KM_ERROR_UNSUPPORTED_DIGEST;
        if (!auth_set->push_back(TAG_DIGEST, DIGEST_NONE))
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    } break;
    case KM_ALGORITHM_ECDSA: {
        const keymaster_ec_sign_params_t* ecdsa_params =
            reinterpret_cast<const keymaster_ec_sign_params_t*>(signing_params);
        if (ecdsa_params->digest_type != DIGEST_NONE)
            return KM_ERROR_UNSUPPORTED_DIGEST;
        if (!auth_set->push_back(TAG_DIGEST, DIGEST_NONE))
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    } break;
    default:
        return KM_ERROR_UNSUPPORTED_ALGORITHM;
    }
    return KM_ERROR_OK;
}

/* static */
void SoftKeymasterDevice::StoreDefaultNewKeyParams(AuthorizationSet* auth_set) {
    auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
    auth_set->push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);
    auth_set->push_back(TAG_ALL_USERS);
    auth_set->push_back(TAG_NO_AUTH_REQUIRED);
    uint64_t now = java_time(time(NULL));
    auth_set->push_back(TAG_CREATION_DATETIME, now);
    auth_set->push_back(TAG_ORIGINATION_EXPIRE_DATETIME, now + HUNDRED_YEARS);
    auth_set->push_back(TAG_DIGEST, DIGEST_NONE);
    auth_set->push_back(TAG_PADDING, KM_PAD_NONE);
}

}  // namespace keymaster
