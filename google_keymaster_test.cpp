/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <string>
#include <fstream>

#include <gtest/gtest.h>

#include <openssl/engine.h>

#include <keymaster/google_keymaster_utils.h>
#include <keymaster/keymaster_tags.h>

#include "google_keymaster_test_utils.h"
#include "soft_keymaster_device.h"

using std::string;
using std::ifstream;
using std::istreambuf_iterator;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    // Clean up stuff OpenSSL leaves around, so Valgrind doesn't complain.
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
    return result;
}

namespace keymaster {
namespace test {

// Note that these DSA generator, p and q values must match the values from dsa_privkey_pk8.der.
const uint8_t dsa_g[] = {
    0x19, 0x1C, 0x71, 0xFD, 0xE0, 0x03, 0x0C, 0x43, 0xD9, 0x0B, 0xF6, 0xCD, 0xD6, 0xA9, 0x70, 0xE7,
    0x37, 0x86, 0x3A, 0x78, 0xE9, 0xA7, 0x47, 0xA7, 0x47, 0x06, 0x88, 0xB1, 0xAF, 0xD7, 0xF3, 0xF1,
    0xA1, 0xD7, 0x00, 0x61, 0x28, 0x88, 0x31, 0x48, 0x60, 0xD8, 0x11, 0xEF, 0xA5, 0x24, 0x1A, 0x81,
    0xC4, 0x2A, 0xE2, 0xEA, 0x0E, 0x36, 0xD2, 0xD2, 0x05, 0x84, 0x37, 0xCF, 0x32, 0x7D, 0x09, 0xE6,
    0x0F, 0x8B, 0x0C, 0xC8, 0xC2, 0xA4, 0xB1, 0xDC, 0x80, 0xCA, 0x68, 0xDF, 0xAF, 0xD2, 0x90, 0xC0,
    0x37, 0x58, 0x54, 0x36, 0x8F, 0x49, 0xB8, 0x62, 0x75, 0x8B, 0x48, 0x47, 0xC0, 0xBE, 0xF7, 0x9A,
    0x92, 0xA6, 0x68, 0x05, 0xDA, 0x9D, 0xAF, 0x72, 0x9A, 0x67, 0xB3, 0xB4, 0x14, 0x03, 0xAE, 0x4F,
    0x4C, 0x76, 0xB9, 0xD8, 0x64, 0x0A, 0xBA, 0x3B, 0xA8, 0x00, 0x60, 0x4D, 0xAE, 0x81, 0xC3, 0xC5,
};
const uint8_t dsa_p[] = {
    0xA3, 0xF3, 0xE9, 0xB6, 0x7E, 0x7D, 0x88, 0xF6, 0xB7, 0xE5, 0xF5, 0x1F, 0x3B, 0xEE, 0xAC, 0xD7,
    0xAD, 0xBC, 0xC9, 0xD1, 0x5A, 0xF8, 0x88, 0xC4, 0xEF, 0x6E, 0x3D, 0x74, 0x19, 0x74, 0xE7, 0xD8,
    0xE0, 0x26, 0x44, 0x19, 0x86, 0xAF, 0x19, 0xDB, 0x05, 0xE9, 0x3B, 0x8B, 0x58, 0x58, 0xDE, 0xE5,
    0x4F, 0x48, 0x15, 0x01, 0xEA, 0xE6, 0x83, 0x52, 0xD7, 0xC1, 0x21, 0xDF, 0xB9, 0xB8, 0x07, 0x66,
    0x50, 0xFB, 0x3A, 0x0C, 0xB3, 0x85, 0xEE, 0xBB, 0x04, 0x5F, 0xC2, 0x6D, 0x6D, 0x95, 0xFA, 0x11,
    0x93, 0x1E, 0x59, 0x5B, 0xB1, 0x45, 0x8D, 0xE0, 0x3D, 0x73, 0xAA, 0xF2, 0x41, 0x14, 0x51, 0x07,
    0x72, 0x3D, 0xA2, 0xF7, 0x58, 0xCD, 0x11, 0xA1, 0x32, 0xCF, 0xDA, 0x42, 0xB7, 0xCC, 0x32, 0x80,
    0xDB, 0x87, 0x82, 0xEC, 0x42, 0xDB, 0x5A, 0x55, 0x24, 0x24, 0xA2, 0xD1, 0x55, 0x29, 0xAD, 0xEB,
};
const uint8_t dsa_q[] = {
    0xEB, 0xEA, 0x17, 0xD2, 0x09, 0xB3, 0xD7, 0x21, 0x9A, 0x21,
    0x07, 0x82, 0x8F, 0xAB, 0xFE, 0x88, 0x71, 0x68, 0xF7, 0xE3,
};

const uint64_t OP_HANDLE_SENTINEL = 0xFFFFFFFFFFFFFFFF;
class KeymasterTest : public testing::Test {
  protected:
    KeymasterTest()
        : device_(new StdoutLogger), out_params_(NULL), signature_(NULL), characteristics_(NULL) {
        blob_.key_material = NULL;
        RAND_seed("foobar", 6);
    }
    ~KeymasterTest() {
        FreeCharacteristics();
        FreeKeyBlob();
    }

    keymaster_device* device() { return reinterpret_cast<keymaster_device*>(device_.hw_device()); }

    void GenerateKey(AuthorizationSet* params) {
        FreeKeyBlob();
        FreeCharacteristics();
        AddClientParams(params);
        EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params->data(), params->size(),
                                                      &blob_, &characteristics_));
    }

    keymaster_error_t BeginOperation(keymaster_purpose_t purpose,
                                     const keymaster_key_blob_t& key_blob) {
        return device()->begin(device(), purpose, &key_blob, client_params_,
                               array_length(client_params_), &out_params_, &out_params_count_,
                               &op_handle_);
    }

    keymaster_error_t UpdateOperation(const void* message, size_t size, string* output,
                                      size_t* input_consumed) {
        uint8_t* out_tmp = NULL;
        size_t out_length;
        keymaster_error_t error =
            device()->update(device(), op_handle_, reinterpret_cast<const uint8_t*>(message), size,
                             input_consumed, &out_tmp, &out_length);
        if (out_tmp)
            output->append(reinterpret_cast<char*>(out_tmp), out_length);
        free(out_tmp);
        return error;
    }

    keymaster_error_t FinishOperation(string* output) {
        uint8_t* out_tmp = NULL;
        size_t out_length;
        keymaster_error_t error =
            device()->finish(device(), op_handle_, reinterpret_cast<const uint8_t*>(signature_),
                             signature_length_, &out_tmp, &out_length);
        if (out_tmp)
            output->append(reinterpret_cast<char*>(out_tmp), out_length);
        free(out_tmp);
        return error;
    }

    template <typename T> void ExpectContains(T val, T* vals, size_t len) {
        EXPECT_EQ(1U, len);
        EXPECT_EQ(val, vals[0]);
    }

    void FreeCharacteristics() {
        keymaster_free_characteristics(characteristics_);
        free(characteristics_);
        characteristics_ = NULL;
    }

    void FreeKeyBlob() {
        free(const_cast<uint8_t*>(blob_.key_material));
        blob_.key_material = NULL;
    }

    void AddClientParams(AuthorizationSet* set) { set->push_back(TAG_APPLICATION_ID, "app_id", 6); }

    const keymaster_key_blob_t& key_blob() { return blob_; }

    SoftKeymasterDevice device_;

    keymaster_blob_t client_id_ = {.data = reinterpret_cast<const uint8_t*>("app_id"),
                                   .data_length = 6};
    keymaster_key_param_t client_params_[1] = {
        Authorization(TAG_APPLICATION_ID, client_id_.data, client_id_.data_length)};

    keymaster_key_param_t* out_params_;
    size_t out_params_count_;
    uint64_t op_handle_;
    size_t input_consumed_;
    uint8_t* signature_;
    size_t signature_length_;

    AuthorizationSet params_;
    keymaster_key_blob_t blob_;
    keymaster_key_characteristics_t* characteristics_;
};

typedef KeymasterTest CheckSupported;
TEST_F(CheckSupported, SupportedAlgorithms) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_algorithms(device(), NULL, NULL));

    size_t len;
    keymaster_algorithm_t* algorithms;
    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_algorithms(device(), &algorithms, &len));
    ASSERT_EQ(4U, len);
    EXPECT_EQ(KM_ALGORITHM_RSA, algorithms[0]);
    EXPECT_EQ(KM_ALGORITHM_DSA, algorithms[1]);
    EXPECT_EQ(KM_ALGORITHM_ECDSA, algorithms[2]);
    EXPECT_EQ(KM_ALGORITHM_AES, algorithms[3]);

    free(algorithms);
}

TEST_F(CheckSupported, SupportedBlockModes) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_block_modes(device(), KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT,
                                                  NULL, NULL));

    size_t len;
    keymaster_block_mode_t* modes;
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE,
              device()->get_supported_block_modes(device(), KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT,
                                                  &modes, &len));

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE,
              device()->get_supported_block_modes(device(), KM_ALGORITHM_DSA, KM_PURPOSE_ENCRYPT,
                                                  &modes, &len));

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE,
              device()->get_supported_block_modes(device(), KM_ALGORITHM_ECDSA, KM_PURPOSE_ENCRYPT,
                                                  &modes, &len));

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE,
              device()->get_supported_block_modes(device(), KM_ALGORITHM_AES, KM_PURPOSE_ENCRYPT,
                                                  &modes, &len));
}

TEST_F(CheckSupported, SupportedPaddingModes) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_padding_modes(device(), KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT,
                                                    NULL, NULL));

    size_t len;
    keymaster_padding_t* modes;
    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_padding_modes(device(), KM_ALGORITHM_RSA,
                                                                 KM_PURPOSE_SIGN, &modes, &len));
    ExpectContains(KM_PAD_NONE, modes, len);
    free(modes);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_padding_modes(device(), KM_ALGORITHM_DSA,
                                                                 KM_PURPOSE_SIGN, &modes, &len));
    ExpectContains(KM_PAD_NONE, modes, len);
    free(modes);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_padding_modes(device(), KM_ALGORITHM_ECDSA,
                                                                 KM_PURPOSE_SIGN, &modes, &len));
    ExpectContains(KM_PAD_NONE, modes, len);
    free(modes);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_padding_modes(device(), KM_ALGORITHM_AES,
                                                                 KM_PURPOSE_SIGN, &modes, &len));
    EXPECT_EQ(0, len);
    free(modes);
}

TEST_F(CheckSupported, SupportedDigests) {
    EXPECT_EQ(
        KM_ERROR_OUTPUT_PARAMETER_NULL,
        device()->get_supported_digests(device(), KM_ALGORITHM_RSA, KM_PURPOSE_SIGN, NULL, NULL));

    size_t len;
    keymaster_digest_t* digests;
    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_digests(device(), KM_ALGORITHM_RSA,
                                                           KM_PURPOSE_SIGN, &digests, &len));
    ExpectContains(KM_DIGEST_NONE, digests, len);
    free(digests);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_digests(device(), KM_ALGORITHM_DSA,
                                                           KM_PURPOSE_SIGN, &digests, &len));
    ExpectContains(KM_DIGEST_NONE, digests, len);
    free(digests);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_digests(device(), KM_ALGORITHM_ECDSA,
                                                           KM_PURPOSE_SIGN, &digests, &len));
    ExpectContains(KM_DIGEST_NONE, digests, len);
    free(digests);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_digests(device(), KM_ALGORITHM_AES,
                                                           KM_PURPOSE_SIGN, &digests, &len));
    EXPECT_EQ(0, len);
    free(digests);
}

TEST_F(CheckSupported, SupportedImportFormats) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_RSA, NULL, NULL));

    size_t len;
    keymaster_key_format_t* formats;
    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_RSA, &formats, &len));
    ExpectContains(KM_KEY_FORMAT_PKCS8, formats, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_DSA, &formats, &len));
    ExpectContains(KM_KEY_FORMAT_PKCS8, formats, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_ECDSA, &formats, &len));
    ExpectContains(KM_KEY_FORMAT_PKCS8, formats, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_AES, &formats, &len));
    EXPECT_EQ(0, len);
    free(formats);
}

TEST_F(CheckSupported, SupportedExportFormats) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_RSA, NULL, NULL));

    size_t len;
    keymaster_key_format_t* formats;
    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_RSA, &formats, &len));
    ExpectContains(KM_KEY_FORMAT_X509, formats, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_DSA, &formats, &len));
    ExpectContains(KM_KEY_FORMAT_X509, formats, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_ECDSA, &formats, &len));
    ExpectContains(KM_KEY_FORMAT_X509, formats, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_AES, &formats, &len));
    EXPECT_EQ(0, len);
    free(formats);
}

keymaster_key_param_t key_generation_base_params[] = {
    Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
    Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
    Authorization(TAG_APPLICATION_ID, "app_id", 6),
    Authorization(TAG_APPLICATION_DATA, "app_data", 8), Authorization(TAG_AUTH_TIMEOUT, 300),
};

TEST_F(KeymasterTest, TestFlags) {
    EXPECT_TRUE(device()->flags & KEYMASTER_SOFTWARE_ONLY);
    EXPECT_TRUE(device()->flags & KEYMASTER_BLOBS_ARE_STANDALONE);
    EXPECT_FALSE(device()->flags & KEYMASTER_SUPPORTS_DSA);
    EXPECT_TRUE(device()->flags & KEYMASTER_SUPPORTS_EC);
}

typedef KeymasterTest OldKeyGeneration;

TEST_F(OldKeyGeneration, Rsa) {
    keymaster_rsa_keygen_params_t params = {.modulus_size = 256, .public_exponent = 3};
    uint8_t* key_blob;
    size_t key_blob_length;
    EXPECT_EQ(0,
              device()->generate_keypair(device(), TYPE_RSA, &params, &key_blob, &key_blob_length));
    EXPECT_GT(key_blob_length, 0);

    free(key_blob);
}

TEST_F(OldKeyGeneration, Ecdsa) {

    keymaster_ec_keygen_params_t params = {.field_size = 256};
    uint8_t* key_blob;
    size_t key_blob_length;
    EXPECT_EQ(0,
              device()->generate_keypair(device(), TYPE_EC, &params, &key_blob, &key_blob_length));
    EXPECT_GT(key_blob_length, 0);

    free(key_blob);
}

class NewKeyGeneration : public KeymasterTest {
  protected:
    NewKeyGeneration() {
        params_.Reinitialize(key_generation_base_params, array_length(key_generation_base_params));
    }

    void CheckBaseParams(const AuthorizationSet& auths) {
        EXPECT_TRUE(contains(auths, TAG_PURPOSE, KM_PURPOSE_SIGN));
        EXPECT_TRUE(contains(auths, TAG_PURPOSE, KM_PURPOSE_VERIFY));
        EXPECT_TRUE(contains(auths, TAG_USER_ID, 7));
        EXPECT_TRUE(contains(auths, TAG_USER_AUTH_ID, 8));
        EXPECT_TRUE(contains(auths, TAG_AUTH_TIMEOUT, 300));

        // Verify that App ID, App data and ROT are NOT included.
        EXPECT_FALSE(contains(auths, TAG_ROOT_OF_TRUST));
        EXPECT_FALSE(contains(auths, TAG_APPLICATION_ID));
        EXPECT_FALSE(contains(auths, TAG_APPLICATION_DATA));

        // Just for giggles, check that some unexpected tags/values are NOT present.
        EXPECT_FALSE(contains(auths, TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
        EXPECT_FALSE(contains(auths, TAG_PURPOSE, KM_PURPOSE_DECRYPT));
        EXPECT_FALSE(contains(auths, TAG_AUTH_TIMEOUT, 301));

        // Now check that unspecified, defaulted tags are correct.
        EXPECT_TRUE(contains(auths, TAG_ORIGIN, KM_ORIGIN_SOFTWARE));
        EXPECT_TRUE(contains(auths, KM_TAG_CREATION_DATETIME));
    }
};

struct ParamListDelete {
    void operator()(keymaster_key_param_set_t* p) { keymaster_free_param_set(p); }
};

typedef UniquePtr<keymaster_key_param_set_t, ParamListDelete> UniqueParamSetPtr;

TEST_F(NewKeyGeneration, Rsa) {
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA));
    params_.push_back(Authorization(TAG_KEY_SIZE, 256));
    params_.push_back(Authorization(TAG_RSA_PUBLIC_EXPONENT, 3));
    ASSERT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(), &blob_,
                                                  &characteristics_));
    EXPECT_EQ(0U, characteristics_->hw_enforced.length);
    AuthorizationSet auths(characteristics_->sw_enforced);
    CheckBaseParams(auths);

    // Check specified tags are all present in auths
    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_TRUE(contains(auths, TAG_KEY_SIZE, 256));
    EXPECT_TRUE(contains(auths, TAG_RSA_PUBLIC_EXPONENT, 3));
}

TEST_F(NewKeyGeneration, RsaDefaultSize) {
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA));
    ASSERT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(), &blob_,
                                                  &characteristics_));

    EXPECT_EQ(0U, characteristics_->hw_enforced.length);
    AuthorizationSet auths(characteristics_->sw_enforced);
    CheckBaseParams(auths);

    // Check specified tags are all present in auths
    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_RSA));

    // Now check that unspecified, defaulted tags are correct.
    EXPECT_TRUE(contains(auths, TAG_RSA_PUBLIC_EXPONENT, 65537));
    EXPECT_TRUE(contains(auths, TAG_KEY_SIZE, 2048));
}

TEST_F(NewKeyGeneration, Ecdsa) {
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    params_.push_back(Authorization(TAG_KEY_SIZE, 224));
    EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(), &blob_,
                                                  &characteristics_));

    EXPECT_EQ(0U, characteristics_->hw_enforced.length);
    AuthorizationSet auths(characteristics_->sw_enforced);
    CheckBaseParams(auths);

    // Check specified tags are all present in auths characteristics
    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    EXPECT_TRUE(contains(auths, TAG_KEY_SIZE, 224));
}

TEST_F(NewKeyGeneration, EcdsaDefaultSize) {
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(), &blob_,
                                                  &characteristics_));

    EXPECT_EQ(0U, characteristics_->hw_enforced.length);
    AuthorizationSet auths(characteristics_->sw_enforced);
    CheckBaseParams(auths);

    // Check specified tags are all present in auths
    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_ECDSA));

    // Now check that unspecified, defaulted tags are correct.
    EXPECT_TRUE(contains(auths, TAG_KEY_SIZE, 224));
}

TEST_F(NewKeyGeneration, EcdsaInvalidSize) {
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    params_.push_back(Authorization(TAG_KEY_SIZE, 190));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_KEY_SIZE,
              device()->generate_key(device(), params_.data(), params_.size(), &blob_,
                                     &characteristics_));
}

TEST_F(NewKeyGeneration, EcdsaAllValidSizes) {
    size_t valid_sizes[] = {224, 256, 384, 521};
    for (size_t size : valid_sizes) {
        params_.Reinitialize(key_generation_base_params, array_length(key_generation_base_params));
        params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
        params_.push_back(Authorization(TAG_KEY_SIZE, size));
        EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(),
                                                      &blob_, &characteristics_))
            << "Failed to generate size: " << size;

        FreeCharacteristics();
        FreeKeyBlob();
    }
}

TEST_F(NewKeyGeneration, AesOcb) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT),
        Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_AES), Authorization(TAG_KEY_SIZE, 128),
        Authorization(TAG_BLOCK_MODE, KM_MODE_OCB), Authorization(TAG_CHUNK_LENGTH, 4096),
        Authorization(TAG_MAC_LENGTH, 16), Authorization(TAG_PADDING, KM_PAD_NONE),
    };
    params_.Reinitialize(params, array_length(params));
    EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(), &blob_,
                                                  &characteristics_));
}

TEST_F(NewKeyGeneration, AesOcbInvalidKeySize) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT),
        Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_AES), Authorization(TAG_KEY_SIZE, 136),
        Authorization(TAG_BLOCK_MODE, KM_MODE_OCB), Authorization(TAG_CHUNK_LENGTH, 4096),
        Authorization(TAG_MAC_LENGTH, 16), Authorization(TAG_PADDING, KM_PAD_NONE),
    };
    params_.Reinitialize(params, array_length(params));
    EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(), &blob_,
                                                  &characteristics_));

    keymaster_key_param_t* out_params;
    size_t out_params_count;
    uint64_t op_handle;
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_KEY_SIZE,
              device()->begin(device(), KM_PURPOSE_ENCRYPT, &blob_, NULL, 0, &out_params,
                              &out_params_count, &op_handle));
    free(out_params);
}

TEST_F(NewKeyGeneration, AesOcbAllValidSizes) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT),
        Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_AES), Authorization(TAG_BLOCK_MODE, KM_MODE_OCB),
        Authorization(TAG_MAC_LENGTH, 16), Authorization(TAG_CHUNK_LENGTH, 4096),
        Authorization(TAG_PADDING, KM_PAD_NONE),
    };

    size_t valid_sizes[] = {128, 192, 256};
    for (size_t size : valid_sizes) {
        params_.Reinitialize(params, array_length(params));
        params_.push_back(Authorization(TAG_KEY_SIZE, size));
        FreeCharacteristics();
        FreeKeyBlob();

        EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(),
                                                      &blob_, &characteristics_))
            << "Failed to generate size: " << size;

        keymaster_key_param_t* out_params;
        size_t out_params_count;
        uint64_t op_handle;
        EXPECT_EQ(KM_ERROR_OK, device()->begin(device(), KM_PURPOSE_ENCRYPT, &blob_, NULL, 0,
                                               &out_params, &out_params_count, &op_handle))
            << "Unsupported key size: " << size;
        free(out_params);
    }
}

TEST_F(NewKeyGeneration, HmacSha256) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_HMAC), Authorization(TAG_KEY_SIZE, 128),
        Authorization(TAG_MAC_LENGTH, 16), Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256),
    };
    EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params, array_length(params), &blob_,
                                                  &characteristics_));
}

typedef KeymasterTest GetKeyCharacteristics;
TEST_F(GetKeyCharacteristics, SimpleRsa) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
    };

    ASSERT_EQ(KM_ERROR_OK, device()->generate_key(device(), params, array_length(params), &blob_,
                                                  &characteristics_));
    AuthorizationSet original(characteristics_->sw_enforced);
    FreeCharacteristics();

    keymaster_blob_t client_id = {.data = reinterpret_cast<const uint8_t*>("app_id"),
                                  .data_length = 6};
    ASSERT_EQ(KM_ERROR_OK,
              device()->get_key_characteristics(device(), &blob_, &client_id, NULL /* app_data */,
                                                &characteristics_));
    EXPECT_EQ(original, AuthorizationSet(characteristics_->sw_enforced));
}

/**
 * Test class that provides some infrastructure for generating keys and signing messages.
 */
class SigningOperationsTest : public KeymasterTest {
  protected:
    SigningOperationsTest() {}
    ~SigningOperationsTest() {
        // Clean up so (most) tests won't have to.
        FreeSignature();
    }

    // TODO(swillden): Refactor and move common test utils to KeymasterTest
    using KeymasterTest::GenerateKey;

    void GenerateKey(keymaster_algorithm_t algorithm, keymaster_digest_t digest,
                     keymaster_padding_t padding, uint32_t key_size) {
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN));
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY));
        params_.push_back(Authorization(TAG_ALGORITHM, algorithm));
        params_.push_back(Authorization(TAG_KEY_SIZE, key_size));
        params_.push_back(Authorization(TAG_USER_ID, 7));
        params_.push_back(Authorization(TAG_USER_AUTH_ID, 8));
        params_.push_back(Authorization(TAG_APPLICATION_ID, "app_id", 6));
        params_.push_back(Authorization(TAG_AUTH_TIMEOUT, 300));
        if (static_cast<int>(digest) != -1)
            params_.push_back(TAG_DIGEST, digest);
        if (static_cast<int>(padding) != -1)
            params_.push_back(TAG_PADDING, padding);

        EXPECT_EQ(KM_ERROR_OK, device()->generate_key(device(), params_.data(), params_.size(),
                                                      &blob_, &characteristics_));
    }

    void SignMessage(const void* message, size_t size) {
        EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_SIGN, blob_));
        string result;
        EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, size, &result, &input_consumed_));
        EXPECT_EQ(0, result.length());
        EXPECT_EQ(size, input_consumed_);

        EXPECT_EQ(KM_ERROR_OK,
                  device()->finish(device(), op_handle_, NULL /* signature to verify */,
                                   0 /* signature to verify length */, &signature_,
                                   &signature_length_));
        EXPECT_GT(signature_length_, 0);
    }

    void FreeSignature() {
        free(signature_);
        signature_ = NULL;
    }

    const keymaster_key_blob_t& key_blob() { return blob_; }

    void corrupt_key_blob() {
        uint8_t* tmp = const_cast<uint8_t*>(blob_.key_material);
        ++tmp[blob_.key_material_size / 2];
    }
};

TEST_F(SigningOperationsTest, RsaSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    const char message[] = "12345678901234567890123456789012";
    SignMessage(message, array_size(message) - 1);
}

TEST_F(SigningOperationsTest, EcdsaSuccess) {
    GenerateKey(KM_ALGORITHM_ECDSA, KM_DIGEST_NONE, KM_PAD_NONE, 224 /* key size */);
    const char message[] = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, array_size(message) - 1);
}

TEST_F(SigningOperationsTest, RsaAbort) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    ASSERT_EQ(KM_ERROR_OK, device()->begin(device(), KM_PURPOSE_SIGN, &blob_, client_params_,
                                           array_length(client_params_), &out_params_,
                                           &out_params_count_, &op_handle_));

    EXPECT_EQ(KM_ERROR_OK, device()->abort(device(), op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device()->abort(device(), op_handle_));
}

TEST_F(SigningOperationsTest, RsaUnsupportedDigest) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_SHA_2_256, KM_PAD_NONE, 256 /* key size */);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_DIGEST,
              device()->begin(device(), KM_PURPOSE_SIGN, &blob_, client_params_,
                              array_length(client_params_), &out_params_, &out_params_count_,
                              &op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device()->abort(device(), op_handle_));
}

TEST_F(SigningOperationsTest, RsaUnsupportedPadding) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_RSA_OAEP, 256 /* key size */);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE,
              device()->begin(device(), KM_PURPOSE_SIGN, &blob_, client_params_,
                              array_length(client_params_), &out_params_, &out_params_count_,
                              &op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device()->abort(device(), op_handle_));
}

TEST_F(SigningOperationsTest, RsaNoDigest) {
    GenerateKey(KM_ALGORITHM_RSA, static_cast<keymaster_digest_t>(-1), KM_PAD_NONE,
                256 /* key size */);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_DIGEST,
              device()->begin(device(), KM_PURPOSE_SIGN, &blob_, client_params_,
                              array_length(client_params_), &out_params_, &out_params_count_,
                              &op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device()->abort(device(), op_handle_));
}

TEST_F(SigningOperationsTest, RsaNoPadding) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, static_cast<keymaster_padding_t>(-1),
                256 /* key size */);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE,
              device()->begin(device(), KM_PURPOSE_SIGN, &blob_, client_params_,
                              array_length(client_params_), &out_params_, &out_params_count_,
                              &op_handle_));
    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device()->abort(device(), op_handle_));
}

TEST_F(SigningOperationsTest, HmacSha256Success) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_HMAC), Authorization(TAG_KEY_SIZE, 128),
        Authorization(TAG_MAC_LENGTH, 32), Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    params_.Reinitialize(params, array_length(params));
    GenerateKey(&params_);
    const char message[] = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, array_size(message) - 1);
    ASSERT_EQ(32, signature_length_);
}

// TODO(swillden): Add an HMACSHA256 test that validates against the test vectors from RFC4231.
//                 Doing that requires being able to import keys, rather than just generate them
//                 randomly.

TEST_F(SigningOperationsTest, HmacSha256NoTag) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_HMAC), Authorization(TAG_KEY_SIZE, 128),
        Authorization(TAG_MAC_LENGTH, 16), Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    params_.Reinitialize(params, array_length(params));
    GenerateKey(&params_);
    const char message[] = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, array_size(message) - 1);
}

TEST_F(SigningOperationsTest, HmacSha256TooLargeTag) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_HMAC), Authorization(TAG_KEY_SIZE, 128),
        Authorization(TAG_MAC_LENGTH, 33), Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    params_.Reinitialize(params, array_length(params));
    GenerateKey(&params_);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_MAC_LENGTH, BeginOperation(KM_PURPOSE_SIGN, key_blob()));
}

TEST_F(SigningOperationsTest, RsaTooShortMessage) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    ASSERT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_SIGN, key_blob()));

    const char message[] = "012345678901234567890123456789";
    string result;
    size_t input_consumed;
    ASSERT_EQ(KM_ERROR_OK,
              UpdateOperation(message, array_length(message), &result, &input_consumed));
    EXPECT_EQ(0U, result.size());
    EXPECT_EQ(31U, input_consumed);

    string signature;
    ASSERT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(&signature));
    EXPECT_EQ(0U, signature.length());
}

class VerificationOperationsTest : public SigningOperationsTest {
  protected:
    void VerifyMessage(const void* message, size_t message_len) {
        EXPECT_TRUE(signature_ != NULL);

        EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_VERIFY, blob_));
        string output;
        EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, message_len, &output, &input_consumed_));
        EXPECT_EQ(0U, output.size());
        EXPECT_EQ(message_len, input_consumed_);
        output.clear();
        EXPECT_EQ(KM_ERROR_OK, FinishOperation(&output));
        EXPECT_EQ(0U, output.size());

        EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device()->abort(device(), op_handle_));
    }
};

TEST_F(VerificationOperationsTest, RsaSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    const char message[] = "12345678901234567890123456789012";
    SignMessage(message, array_size(message) - 1);
    VerifyMessage(message, array_size(message) - 1);
}

TEST_F(VerificationOperationsTest, EcdsaSuccess) {
    GenerateKey(KM_ALGORITHM_ECDSA, KM_DIGEST_NONE, KM_PAD_NONE, 224 /* key size */);
    const char message[] = "123456789012345678901234567890123456789012345678";
    SignMessage(message, array_size(message) - 1);
    VerifyMessage(message, array_size(message) - 1);
}

TEST_F(VerificationOperationsTest, HmacSha256Success) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_HMAC), Authorization(TAG_KEY_SIZE, 128),
        Authorization(TAG_MAC_LENGTH, 16), Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    params_.Reinitialize(params, array_length(params));
    GenerateKey(&params_);
    const char message[] = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, array_size(message) - 1);
    VerifyMessage(message, array_size(message) - 1);
}

typedef VerificationOperationsTest ExportKeyTest;
TEST_F(ExportKeyTest, RsaSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);

    uint8_t* export_data;
    size_t export_data_length;
    ASSERT_EQ(KM_ERROR_OK,
              device()->export_key(device(), KM_KEY_FORMAT_X509, &blob_, &client_id_,
                                   NULL /* app_data */, &export_data, &export_data_length));
    EXPECT_TRUE(export_data != NULL);
    EXPECT_GT(export_data_length, 0);

    // TODO(swillden): Verify that the exported key is actually usable to verify signatures.
    free(export_data);
}

TEST_F(ExportKeyTest, EcdsaSuccess) {
    GenerateKey(KM_ALGORITHM_ECDSA, KM_DIGEST_NONE, KM_PAD_NONE, 224 /* key size */);

    uint8_t* export_data;
    size_t export_data_length;
    ASSERT_EQ(KM_ERROR_OK,
              device()->export_key(device(), KM_KEY_FORMAT_X509, &blob_, &client_id_,
                                   NULL /* app_data */, &export_data, &export_data_length));
    EXPECT_TRUE(export_data != NULL);
    EXPECT_GT(export_data_length, 0);

    // TODO(swillden): Verify that the exported key is actually usable to verify signatures.
    free(export_data);
}

TEST_F(ExportKeyTest, RsaUnsupportedKeyFormat) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256);

    uint8_t dummy[] = {1};
    uint8_t* export_data = dummy;  // So it's not NULL;
    size_t export_data_length;
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_KEY_FORMAT,
              device()->export_key(device(), KM_KEY_FORMAT_PKCS8, &blob_, &client_id_,
                                   NULL /* app_data */, &export_data, &export_data_length));
    ASSERT_TRUE(export_data == NULL);
}

TEST_F(ExportKeyTest, RsaCorruptedKeyBlob) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256);
    corrupt_key_blob();

    uint8_t dummy[] = {1};
    uint8_t* export_data = dummy;  // So it's not NULL
    size_t export_data_length;
    ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB,
              device()->export_key(device(), KM_KEY_FORMAT_X509, &blob_, &client_id_,
                                   NULL /* app_data */, &export_data, &export_data_length));
    ASSERT_TRUE(export_data == NULL);
}

static string read_file(const string& file_name) {
    ifstream file_stream(file_name, std::ios::binary);
    istreambuf_iterator<char> file_begin(file_stream);
    istreambuf_iterator<char> file_end;
    return string(file_begin, file_end);
}

class ImportKeyTest : public VerificationOperationsTest {
  protected:
    ImportKeyTest() {
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN));
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY));
        params_.push_back(Authorization(TAG_DIGEST, KM_DIGEST_NONE));
        params_.push_back(Authorization(TAG_PADDING, KM_PAD_NONE));
        params_.push_back(Authorization(TAG_USER_ID, 7));
        params_.push_back(Authorization(TAG_USER_AUTH_ID, 8));
        params_.push_back(Authorization(TAG_APPLICATION_ID, "app_id", 6));
        params_.push_back(Authorization(TAG_AUTH_TIMEOUT, 300));
    }
};

TEST_F(ImportKeyTest, RsaSuccess) {
    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_OK,
              device()->import_key(device(), params_.data(), params_.size(), KM_KEY_FORMAT_PKCS8,
                                   reinterpret_cast<const uint8_t*>(pk8_key.data()), pk8_key.size(),
                                   &blob_, &characteristics_));
    EXPECT_EQ(0U, characteristics_->hw_enforced.length);
    AuthorizationSet auths(characteristics_->sw_enforced);

    // Check values derived from the key.
    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_TRUE(contains(auths, TAG_KEY_SIZE, 1024));
    EXPECT_TRUE(contains(auths, TAG_RSA_PUBLIC_EXPONENT, 65537U));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(auths, TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(auths, KM_TAG_CREATION_DATETIME));

    size_t message_len = 1024 / 8;
    UniquePtr<uint8_t[]> message(new uint8_t[message_len]);
    std::fill(message.get(), message.get() + message_len, 'a');
    SignMessage(message.get(), message_len);
    VerifyMessage(message.get(), message_len);
}

TEST_F(ImportKeyTest, RsaKeySizeMismatch) {
    params_.push_back(Authorization(TAG_KEY_SIZE, 2048));  // Doesn't match key

    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH,
              device()->import_key(device(), params_.data(), params_.size(), KM_KEY_FORMAT_PKCS8,
                                   reinterpret_cast<const uint8_t*>(pk8_key.data()), pk8_key.size(),
                                   &blob_, &characteristics_));
}

TEST_F(ImportKeyTest, RsaPublicExponenMismatch) {
    params_.push_back(Authorization(TAG_RSA_PUBLIC_EXPONENT, 3));  // Doesn't match key

    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH,
              device()->import_key(device(), params_.data(), params_.size(), KM_KEY_FORMAT_PKCS8,
                                   reinterpret_cast<const uint8_t*>(pk8_key.data()), pk8_key.size(),
                                   &blob_, &characteristics_));
}

TEST_F(ImportKeyTest, EcdsaSuccess) {
    string pk8_key = read_file("ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_OK,
              device()->import_key(device(), params_.data(), params_.size(), KM_KEY_FORMAT_PKCS8,
                                   reinterpret_cast<const uint8_t*>(pk8_key.data()), pk8_key.size(),
                                   &blob_, &characteristics_));
    EXPECT_EQ(0U, characteristics_->hw_enforced.length);
    AuthorizationSet auths(characteristics_->sw_enforced);

    // Check values derived from the key.
    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    EXPECT_TRUE(contains(auths, TAG_KEY_SIZE, 256));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(auths, TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(auths, KM_TAG_CREATION_DATETIME));

    size_t message_len = 1024;
    UniquePtr<uint8_t[]> message(new uint8_t[message_len]);
    std::fill(message.get(), message.get() + message_len, 'a');
    SignMessage(message.get(), message_len);
    VerifyMessage(message.get(), message_len);
}

TEST_F(ImportKeyTest, EcdsaKeySizeMismatch) {
    params_.push_back(Authorization(TAG_KEY_SIZE, 224));  // Doesn't match key

    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH,
              device()->import_key(device(), params_.data(), params_.size(), KM_KEY_FORMAT_PKCS8,
                                   reinterpret_cast<const uint8_t*>(pk8_key.data()), pk8_key.size(),
                                   &blob_, &characteristics_));
}

typedef KeymasterTest VersionTest;
TEST_F(VersionTest, GetVersion) {
    GetVersionRequest req;
    GetVersionResponse rsp;
    device_.GetVersion(req, &rsp);
    EXPECT_EQ(KM_ERROR_OK, rsp.error);
    EXPECT_EQ(1, rsp.major_ver);
    EXPECT_EQ(0, rsp.minor_ver);
    EXPECT_EQ(0, rsp.subminor_ver);
}

/**
 * Test class that provides some infrastructure for generating keys and encrypting messages.
 */
class EncryptionOperationsTest : public KeymasterTest {
  protected:
    // TODO(swillden): Refactor and move common test utils to KeymasterTest
    using KeymasterTest::GenerateKey;

    void GenerateKey(keymaster_algorithm_t algorithm, keymaster_padding_t padding,
                     uint32_t key_size) {
        params_.Clear();
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT));
        params_.push_back(Authorization(TAG_ALGORITHM, algorithm));
        params_.push_back(Authorization(TAG_KEY_SIZE, key_size));
        params_.push_back(Authorization(TAG_USER_ID, 7));
        params_.push_back(Authorization(TAG_USER_AUTH_ID, 8));
        params_.push_back(Authorization(TAG_AUTH_TIMEOUT, 300));
        if (static_cast<int>(padding) != -1)
            params_.push_back(TAG_PADDING, padding);

        GenerateKey(&params_);
    }

    void GenerateSymmetricKey(keymaster_algorithm_t algorithm, uint32_t key_size,
                              keymaster_block_mode_t block_mode, uint32_t chunk_length) {
        params_.Clear();
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
        params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT));
        params_.push_back(Authorization(TAG_ALGORITHM, algorithm));
        params_.push_back(Authorization(TAG_BLOCK_MODE, block_mode));
        params_.push_back(Authorization(TAG_CHUNK_LENGTH, chunk_length));
        params_.push_back(Authorization(TAG_KEY_SIZE, key_size));
        params_.push_back(Authorization(TAG_MAC_LENGTH, 16));
        params_.push_back(Authorization(TAG_USER_ID, 7));
        params_.push_back(Authorization(TAG_USER_AUTH_ID, 8));
        params_.push_back(Authorization(TAG_AUTH_TIMEOUT, 300));

        GenerateKey(&params_);
    }

    string ProcessMessage(keymaster_purpose_t purpose, const keymaster_key_blob_t& key_blob,
                          const void* message, size_t size) {
        EXPECT_EQ(KM_ERROR_OK, BeginOperation(purpose, key_blob));

        string result;
        size_t input_consumed;
        EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, size, &result, &input_consumed));
        EXPECT_EQ(size, input_consumed);
        EXPECT_EQ(KM_ERROR_OK, FinishOperation(&result));
        EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device()->abort(device(), op_handle_));
        return result;
    }

    string EncryptMessage(const string& message) {
        return ProcessMessage(KM_PURPOSE_ENCRYPT, blob_, message.c_str(), message.length());
    }

    string DecryptMessage(const string& ciphertext) {
        return ProcessMessage(KM_PURPOSE_DECRYPT, blob_, ciphertext.c_str(), ciphertext.length());
    }

    const void corrupt_key_blob() {
        uint8_t* tmp = const_cast<uint8_t*>(blob_.key_material);
        ++tmp[blob_.key_material_size / 2];
    }

    keymaster_blob_t client_id_ = {.data = reinterpret_cast<const uint8_t*>("app_id"),
                                   .data_length = 6};
    keymaster_key_param_t client_params_[1] = {
        Authorization(TAG_APPLICATION_ID, client_id_.data, client_id_.data_length)};

    keymaster_key_param_t* out_params_;
    size_t out_params_count_;
};

TEST_F(EncryptionOperationsTest, RsaOaepSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "Hello World!";
    string ciphertext1 = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext1.size());

    string ciphertext2 = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext2.size());

    // OAEP randomizes padding so every result should be different.
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(EncryptionOperationsTest, RsaOaepRoundTrip) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, RsaOaepTooLarge) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "12345678901234567890123";
    string result;
    size_t input_consumed;

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT, blob_));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, array_size(message), &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(&result));
    EXPECT_EQ(0, result.size());
}

TEST_F(EncryptionOperationsTest, RsaOaepCorruptedDecrypt) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    // Corrupt the ciphertext
    ciphertext[512 / 8 / 2]++;

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, blob_));
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(ciphertext.data(), ciphertext.size(), &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(&result));
    EXPECT_EQ(0, result.size());
}

TEST_F(EncryptionOperationsTest, RsaPkcs1Success) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "Hello World!";
    string ciphertext1 = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext1.size());

    string ciphertext2 = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext2.size());

    // PKCS1 v1.5 randomizes padding so every result should be different.
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(EncryptionOperationsTest, RsaPkcs1RoundTrip) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, RsaPkcs1TooLarge) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "1234567890123456789012345678901234567890123456789012";
    string result;
    size_t input_consumed;

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT, blob_));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, array_size(message), &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(&result));
    EXPECT_EQ(0, result.size());
}

TEST_F(EncryptionOperationsTest, RsaPkcs1CorruptedDecrypt) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    // Corrupt the ciphertext
    ciphertext[512 / 8 / 2]++;

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, blob_));
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(ciphertext.data(), ciphertext.size(), &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(&result));
    EXPECT_EQ(0, result.size());
}

TEST_F(EncryptionOperationsTest, AesOcbSuccess) {
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    const char message[] = "Hello World!";
    string ciphertext1 = EncryptMessage(string(message));
    EXPECT_EQ(12 /* nonce */ + strlen(message) + 16 /* tag */, ciphertext1.size());

    string ciphertext2 = EncryptMessage(string(message));
    EXPECT_EQ(12 /* nonce */ + strlen(message) + 16 /* tag */, ciphertext2.size());

    // OCB uses a random nonce, so every output should be different
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(EncryptionOperationsTest, AesOcbRoundTripSuccess) {
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    string message = "Hello World!";
    string ciphertext = EncryptMessage(message);
    EXPECT_EQ(12 /* nonce */ + message.length() + 16 /* tag */, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, AesOcbRoundTripCorrupted) {
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(12 /* nonce */ + strlen(message) + 16 /* tag */, ciphertext.size());

    ciphertext[ciphertext.size() / 2]++;

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, key_blob()));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(ciphertext.c_str(), ciphertext.length(), &result, &input_consumed));
    EXPECT_EQ(ciphertext.length(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(&result));
}

TEST_F(EncryptionOperationsTest, AesDecryptGarbage) {
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    string ciphertext(128, 'a');
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, key_blob()));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(ciphertext.c_str(), ciphertext.length(), &result, &input_consumed));
    EXPECT_EQ(ciphertext.length(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(&result));
}

TEST_F(EncryptionOperationsTest, AesDecryptTooShort) {
    // Try decrypting garbage ciphertext that is too short to be valid (< nonce + tag).
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    string ciphertext(12 + 15, 'a');
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, key_blob()));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(ciphertext.c_str(), ciphertext.length(), &result, &input_consumed));
    EXPECT_EQ(ciphertext.length(), input_consumed);
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(&result));
}

TEST_F(EncryptionOperationsTest, AesOcbRoundTripEmptySuccess) {
    // Empty messages should work fine.
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    const char message[] = "";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(12 /* nonce */ + strlen(message) + 16 /* tag */, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, AesOcbRoundTripEmptyCorrupted) {
    // Should even detect corruption of empty messages.
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    const char message[] = "";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(12 /* nonce */ + strlen(message) + 16 /* tag */, ciphertext.size());

    ciphertext[ciphertext.size() / 2]++;

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, key_blob()));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(ciphertext.c_str(), ciphertext.length(), &result, &input_consumed));
    EXPECT_EQ(ciphertext.length(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(&result));
}

TEST_F(EncryptionOperationsTest, AesOcbFullChunk) {
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    string message(4096, 'a');
    string ciphertext = EncryptMessage(message);
    EXPECT_EQ(12 /* nonce */ + message.length() + 16 /* tag */, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, AesOcbVariousChunkLengths) {
    for (unsigned chunk_length = 1; chunk_length <= 128; ++chunk_length) {
        GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, chunk_length);
        string message(128, 'a');
        string ciphertext = EncryptMessage(message);
        int expected_tag_count = (message.length() + chunk_length - 1) / chunk_length;
        EXPECT_EQ(12 /* nonce */ + message.length() + 16 * expected_tag_count, ciphertext.size())
            << "Unexpected ciphertext size for chunk length " << chunk_length
            << " expected tag count was " << expected_tag_count
            << " but actual tag count was probably "
            << (ciphertext.size() - message.length() - 12) / 16;

        string plaintext = DecryptMessage(ciphertext);
        EXPECT_EQ(message, plaintext);
    }
}

TEST_F(EncryptionOperationsTest, AesOcbAbort) {
    GenerateSymmetricKey(KM_ALGORITHM_AES, 128, KM_MODE_OCB, 4096);
    const char message[] = "Hello";

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT, key_blob()));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, strlen(message), &result, &input_consumed));
    EXPECT_EQ(strlen(message), input_consumed);
    EXPECT_EQ(KM_ERROR_OK, device()->abort(device(), op_handle_));
}

TEST_F(EncryptionOperationsTest, AesOcbNoChunkLength) {
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT));
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_AES));
    params_.push_back(Authorization(TAG_KEY_SIZE, 128));
    params_.push_back(Authorization(TAG_MAC_LENGTH, 16));
    params_.push_back(Authorization(TAG_BLOCK_MODE, KM_MODE_OCB));
    params_.push_back(Authorization(TAG_PADDING, KM_PAD_NONE));

    GenerateKey(&params_);
    EXPECT_EQ(KM_ERROR_INVALID_ARGUMENT, BeginOperation(KM_PURPOSE_ENCRYPT, key_blob()));
}

TEST_F(EncryptionOperationsTest, AesEcbUnsupported) {
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
    params_.push_back(Authorization(TAG_MAC_LENGTH, 16));
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT));
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_AES));
    params_.push_back(Authorization(TAG_KEY_SIZE, 128));
    params_.push_back(Authorization(TAG_BLOCK_MODE, KM_MODE_ECB));
    params_.push_back(Authorization(TAG_PADDING, KM_PAD_NONE));

    GenerateKey(&params_);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE, BeginOperation(KM_PURPOSE_ENCRYPT, key_blob()));
}

TEST_F(EncryptionOperationsTest, AesOcbPaddingUnsupported) {
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT));
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_AES));
    params_.push_back(Authorization(TAG_KEY_SIZE, 128));
    params_.push_back(Authorization(TAG_MAC_LENGTH, 16));
    params_.push_back(Authorization(TAG_BLOCK_MODE, KM_MODE_OCB));
    params_.push_back(Authorization(TAG_CHUNK_LENGTH, 4096));
    params_.push_back(Authorization(TAG_PADDING, KM_PAD_ZERO));

    GenerateKey(&params_);
    uint64_t op_handle;
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE, BeginOperation(KM_PURPOSE_ENCRYPT, key_blob()));
}

TEST_F(EncryptionOperationsTest, AesOcbInvalidMacLength) {
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
    params_.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT));
    params_.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_AES));
    params_.push_back(Authorization(TAG_KEY_SIZE, 128));
    params_.push_back(Authorization(TAG_MAC_LENGTH, 17));
    params_.push_back(Authorization(TAG_BLOCK_MODE, KM_MODE_OCB));
    params_.push_back(Authorization(TAG_CHUNK_LENGTH, 4096));

    GenerateKey(&params_);
    uint64_t op_handle;
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, BeginOperation(KM_PURPOSE_ENCRYPT, key_blob()));
}

}  // namespace test
}  // namespace keymaster
