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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>

#include <type_traits>

#include "authorization_set.h"
#include "google_keymaster_messages.h"
#include "google_keymaster_utils.h"
#include "trusty_keymaster_device.h"

extern "C" {
#include "trusty_keymaster_lib.h"
}

int main(void) {
    keymaster::TrustyKeymasterDevice device(NULL);
    keymaster_rsa_keygen_params_t params;
    params.public_exponent = 3;
    params.modulus_size = 256;
    uint8_t* ptr;
    size_t size;
    return device.generate_keypair(TYPE_RSA, &params, &ptr, &size);
}

namespace keymaster {

TrustyKeymasterDevice::TrustyKeymasterDevice(const hw_module_t* module) {
#if __cplusplus >= 201103L || defined(__GXX_EXPERIMENTAL_CXX0X__)
    static_assert(std::is_standard_layout<TrustyKeymasterDevice>::value,
                  "KeymasterOpenSsl must be standard layout");
    static_assert(offsetof(TrustyKeymasterDevice, device_) == 0,
                  "device_ must be the first member of KeymasterOpenSsl");
    static_assert(offsetof(TrustyKeymasterDevice, device_.common) == 0,
                  "common must be the first member of keymaster_device");
#else
    assert(reinterpret_cast<keymaster_device*>(this) == &device_);
    assert(reinterpret_cast<hw_device_t*>(this) == &(device_.common));
#endif
    memset(&device_, 0, sizeof(device_));

    device_.common.tag = HARDWARE_DEVICE_TAG;
    device_.common.version = 1;
    device_.common.module = const_cast<hw_module_t*>(module);
    device_.common.close = close_device;

    device_.flags = KEYMASTER_SOFTWARE_ONLY;

    device_.generate_keypair = generate_keypair;
    device_.import_keypair = import_keypair;
    device_.get_keypair_public = get_keypair_public;
    device_.delete_keypair = NULL;
    device_.delete_all = NULL;
    device_.sign_data = sign_data;
    device_.verify_data = verify_data;
    device_.get_supported_algorithms = NULL;
    device_.get_supported_block_modes = NULL;
    device_.get_supported_padding_modes = NULL;
    device_.get_supported_digests = NULL;
    device_.get_supported_import_formats = NULL;
    device_.get_supported_export_formats = NULL;
    device_.generate_key = NULL;
    device_.free_characteristics = NULL;

    device_.context = NULL;

    trusty_init(&trusty_session);
}

TrustyKeymasterDevice::~TrustyKeymasterDevice() {
    trusty_deinit(trusty_session);
}

const uint64_t HUNDRED_YEARS = 1000LL * 60 * 60 * 24 * 365 * 100;

int TrustyKeymasterDevice::generate_keypair(const keymaster_keypair_t key_type,
                                            const void* key_params, uint8_t** /* key_blob */,
                                            size_t* /* key_blob_length */) {
    UniquePtr<uint8_t[]> send_buf;
    uint32_t req_size, rsp_size;

    switch (key_type) {
    case TYPE_RSA: {
        GenerateKeyRequest req;
        AuthorizationSet& auth_set = req.key_description;
        auth_set.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN);
        auth_set.push_back(TAG_PURPOSE, KM_PURPOSE_VERIFY);
        auth_set.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        const keymaster_rsa_keygen_params_t* rsa_params =
            static_cast<const keymaster_rsa_keygen_params_t*>(key_params);
        auth_set.push_back(TAG_KEY_SIZE, rsa_params->modulus_size);
        auth_set.push_back(TAG_RSA_PUBLIC_EXPONENT, rsa_params->public_exponent);
        auth_set.push_back(TAG_ALL_USERS);
        auth_set.push_back(TAG_NO_AUTH_REQUIRED);
        auth_set.push_back(TAG_ORIGINATION_EXPIRE_DATETIME, java_time(time(NULL)) + HUNDRED_YEARS);

        req_size = req.SerializedSize();
        send_buf.reset(new uint8_t[req_size]);
        req.Serialize(send_buf.get(), send_buf.get() + req_size);
    } break;
    default:
        return -1;
    }

    // Send it somehow!
    uint8_t recv_buf[8192];
    rsp_size = 8192;
    trusty_call(trusty_session, GENERATE_KEY, send_buf.get(), req_size, recv_buf, &rsp_size);

    printf("AAAA %d AAAA \n", rsp_size);
    printf("BEGIN\n");
    for (unsigned int i = 0; i < rsp_size; i++) {
        printf("%d,", recv_buf[i]);
    }
    printf("END\n");

    return -1;
}

int TrustyKeymasterDevice::import_keypair(const uint8_t* /* key */, const size_t /* key_length */,
                                          uint8_t** /* key_blob */, size_t* /* key_blob_length */) {
    return -1;
}

int TrustyKeymasterDevice::get_keypair_public(const uint8_t* /* key_blob */,
                                              const size_t /* key_blob_length */,
                                              uint8_t** /* x509_data */,
                                              size_t* /* x509_data_length */) {
    return -1;
}

int TrustyKeymasterDevice::sign_data(const void* /* signing_params */,
                                     const uint8_t* /* key_blob */,
                                     const size_t /* key_blob_length */, const uint8_t* /* data */,
                                     const size_t /* data_length */, uint8_t** /* signed_data */,
                                     size_t* /* signed_data_length */) {
    return -1;
}

int TrustyKeymasterDevice::verify_data(const void* /* signing_params */,
                                       const uint8_t* /* key_blob */,
                                       const size_t /* key_blob_length */,
                                       const uint8_t* /* signed_data */,
                                       const size_t /* signed_data_length */,
                                       const uint8_t* /* signature */,
                                       const size_t /* signature_length */) {
    return -1;
}

keymaster_device* TrustyKeymasterDevice::device() {
    return &device_;
}

hw_device_t* TrustyKeymasterDevice::hw_device() {
    return &device_.common;
}

static inline TrustyKeymasterDevice* convert_device(const keymaster_device* dev) {
    return reinterpret_cast<TrustyKeymasterDevice*>(const_cast<keymaster_device*>(dev));
}

/* static */
int TrustyKeymasterDevice::close_device(hw_device_t* dev) {
    delete reinterpret_cast<TrustyKeymasterDevice*>(dev);
    return 0;
}

/* static */
int TrustyKeymasterDevice::generate_keypair(const keymaster_device_t* dev,
                                            const keymaster_keypair_t key_type,
                                            const void* key_params, uint8_t** keyBlob,
                                            size_t* keyBlobLength) {
    return convert_device(dev)->generate_keypair(key_type, key_params, keyBlob, keyBlobLength);
}

/* static */
int TrustyKeymasterDevice::import_keypair(const keymaster_device_t* dev, const uint8_t* key,
                                          const size_t key_length, uint8_t** key_blob,
                                          size_t* key_blob_length) {
    return convert_device(dev)->import_keypair(key, key_length, key_blob, key_blob_length);
}

/* static */
int TrustyKeymasterDevice::get_keypair_public(const struct keymaster_device* dev,
                                              const uint8_t* key_blob, const size_t key_blob_length,
                                              uint8_t** x509_data, size_t* x509_data_length) {
    return convert_device(dev)
        ->get_keypair_public(key_blob, key_blob_length, x509_data, x509_data_length);
}

/* static */
int TrustyKeymasterDevice::sign_data(const keymaster_device_t* dev, const void* params,
                                     const uint8_t* keyBlob, const size_t keyBlobLength,
                                     const uint8_t* data, const size_t dataLength,
                                     uint8_t** signedData, size_t* signedDataLength) {
    return convert_device(dev)
        ->sign_data(params, keyBlob, keyBlobLength, data, dataLength, signedData, signedDataLength);
}

/* static */
int TrustyKeymasterDevice::verify_data(const keymaster_device_t* dev, const void* params,
                                       const uint8_t* keyBlob, const size_t keyBlobLength,
                                       const uint8_t* signedData, const size_t signedDataLength,
                                       const uint8_t* signature, const size_t signatureLength) {
    return convert_device(dev)->verify_data(params, keyBlob, keyBlobLength, signedData,
                                            signedDataLength, signature, signatureLength);
}

}  // namespace keymaster
