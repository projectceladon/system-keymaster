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
#include "google_softkeymaster.h"

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

class KeymasterTest : public testing::Test {
  protected:
    KeymasterTest() : device(5, new StdoutLogger) { RAND_seed("foobar", 6); }
    ~KeymasterTest() {}

    template <typename T> void ExpectEmptyResponse(const SupportedResponse<T>& response) {
        EXPECT_EQ(KM_ERROR_OK, response.error);
        EXPECT_EQ(0U, response.results_length);
    }

    template <typename T> void ExpectResponseContains(T val, const SupportedResponse<T>& response) {
        EXPECT_EQ(KM_ERROR_OK, response.error);
        EXPECT_EQ(1U, response.results_length);
        EXPECT_EQ(val, response.results[0]);
    }

    GoogleSoftKeymaster device;
};

typedef KeymasterTest CheckSupported;
TEST_F(CheckSupported, SupportedAlgorithms) {
    // Shouldn't blow up on NULL.
    device.SupportedAlgorithms(NULL);

    SupportedResponse<keymaster_algorithm_t> response;
    device.SupportedAlgorithms(&response);
    EXPECT_EQ(KM_ERROR_OK, response.error);
    EXPECT_EQ(3U, response.results_length);
    EXPECT_EQ(KM_ALGORITHM_RSA, response.results[0]);
    EXPECT_EQ(KM_ALGORITHM_DSA, response.results[1]);
    EXPECT_EQ(KM_ALGORITHM_ECDSA, response.results[2]);
}

TEST_F(CheckSupported, SupportedBlockModes) {
    // Shouldn't blow up on NULL.
    device.SupportedBlockModes(KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT, NULL);

    SupportedResponse<keymaster_block_mode_t> response;
    device.SupportedBlockModes(KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE, response.error);

    device.SupportedBlockModes(KM_ALGORITHM_DSA, KM_PURPOSE_ENCRYPT, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE, response.error);

    device.SupportedBlockModes(KM_ALGORITHM_ECDSA, KM_PURPOSE_ENCRYPT, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_BLOCK_MODE, response.error);

    device.SupportedBlockModes(KM_ALGORITHM_AES, KM_PURPOSE_ENCRYPT, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedPaddingModes) {
    // Shouldn't blow up on NULL.
    device.SupportedPaddingModes(KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT, NULL);

    SupportedResponse<keymaster_padding_t> response;
    device.SupportedPaddingModes(KM_ALGORITHM_RSA, KM_PURPOSE_SIGN, &response);
    ExpectResponseContains(KM_PAD_NONE, response);

    device.SupportedPaddingModes(KM_ALGORITHM_DSA, KM_PURPOSE_SIGN, &response);
    ExpectResponseContains(KM_PAD_NONE, response);

    device.SupportedPaddingModes(KM_ALGORITHM_ECDSA, KM_PURPOSE_SIGN, &response);
    ExpectResponseContains(KM_PAD_NONE, response);

    device.SupportedPaddingModes(KM_ALGORITHM_AES, KM_PURPOSE_SIGN, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedDigests) {
    // Shouldn't blow up on NULL.
    device.SupportedDigests(KM_ALGORITHM_RSA, KM_PURPOSE_SIGN, NULL);

    SupportedResponse<keymaster_digest_t> response;
    device.SupportedDigests(KM_ALGORITHM_RSA, KM_PURPOSE_SIGN, &response);
    ExpectResponseContains(KM_DIGEST_NONE, response);

    device.SupportedDigests(KM_ALGORITHM_DSA, KM_PURPOSE_SIGN, &response);
    ExpectResponseContains(KM_DIGEST_NONE, response);

    device.SupportedDigests(KM_ALGORITHM_ECDSA, KM_PURPOSE_SIGN, &response);
    ExpectResponseContains(KM_DIGEST_NONE, response);

    device.SupportedDigests(KM_ALGORITHM_AES, KM_PURPOSE_SIGN, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedImportFormats) {
    // Shouldn't blow up on NULL.
    device.SupportedImportFormats(KM_ALGORITHM_RSA, NULL);

    SupportedResponse<keymaster_key_format_t> response;
    device.SupportedImportFormats(KM_ALGORITHM_RSA, &response);
    ExpectResponseContains(KM_KEY_FORMAT_PKCS8, response);

    device.SupportedImportFormats(KM_ALGORITHM_DSA, &response);
    ExpectResponseContains(KM_KEY_FORMAT_PKCS8, response);

    device.SupportedImportFormats(KM_ALGORITHM_ECDSA, &response);
    ExpectResponseContains(KM_KEY_FORMAT_PKCS8, response);

    device.SupportedImportFormats(KM_ALGORITHM_AES, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedExportFormats) {
    // Shouldn't blow up on NULL.
    device.SupportedExportFormats(KM_ALGORITHM_RSA, NULL);

    SupportedResponse<keymaster_key_format_t> response;
    device.SupportedExportFormats(KM_ALGORITHM_RSA, &response);
    ExpectResponseContains(KM_KEY_FORMAT_X509, response);

    device.SupportedExportFormats(KM_ALGORITHM_DSA, &response);
    ExpectResponseContains(KM_KEY_FORMAT_X509, response);

    device.SupportedExportFormats(KM_ALGORITHM_ECDSA, &response);
    ExpectResponseContains(KM_KEY_FORMAT_X509, response);

    device.SupportedExportFormats(KM_ALGORITHM_AES, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

keymaster_key_param_t key_generation_base_params[] = {
    Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
    Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
    Authorization(TAG_APPLICATION_ID, "app_id", 6),
    Authorization(TAG_APPLICATION_DATA, "app_data", 8), Authorization(TAG_AUTH_TIMEOUT, 300),
};

class NewKeyGeneration : public KeymasterTest {
  protected:
    NewKeyGeneration() {
        req_.key_description.Reinitialize(key_generation_base_params,
                                          array_length(key_generation_base_params));
    }

    void CheckBaseParams(const GenerateKeyResponse& rsp) {
        ASSERT_EQ(KM_ERROR_OK, rsp.error);
        EXPECT_EQ(0U, rsp.enforced.size());
        EXPECT_EQ(12U, rsp.enforced.SerializedSize());
        EXPECT_GT(rsp.unenforced.SerializedSize(), 12U);

        EXPECT_TRUE(contains(rsp.unenforced, TAG_PURPOSE, KM_PURPOSE_SIGN));
        EXPECT_TRUE(contains(rsp.unenforced, TAG_PURPOSE, KM_PURPOSE_VERIFY));
        EXPECT_TRUE(contains(rsp.unenforced, TAG_USER_ID, 7));
        EXPECT_TRUE(contains(rsp.unenforced, TAG_USER_AUTH_ID, 8));
        EXPECT_TRUE(contains(rsp.unenforced, TAG_AUTH_TIMEOUT, 300));

        // Verify that App ID, App data and ROT are NOT included.
        EXPECT_FALSE(contains(rsp.unenforced, TAG_ROOT_OF_TRUST));
        EXPECT_FALSE(contains(rsp.unenforced, TAG_APPLICATION_ID));
        EXPECT_FALSE(contains(rsp.unenforced, TAG_APPLICATION_DATA));

        // Just for giggles, check that some unexpected tags/values are NOT present.
        EXPECT_FALSE(contains(rsp.unenforced, TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
        EXPECT_FALSE(contains(rsp.unenforced, TAG_PURPOSE, KM_PURPOSE_DECRYPT));
        EXPECT_FALSE(contains(rsp.unenforced, TAG_AUTH_TIMEOUT, 301));
        EXPECT_FALSE(contains(rsp.unenforced, TAG_RESCOPE_AUTH_TIMEOUT));

        // Now check that unspecified, defaulted tags are correct.
        EXPECT_TRUE(contains(rsp.unenforced, TAG_ORIGIN, KM_ORIGIN_SOFTWARE));
        EXPECT_TRUE(contains(rsp.unenforced, KM_TAG_CREATION_DATETIME));
    }

    GenerateKeyRequest req_;
    GenerateKeyResponse rsp_;
};

TEST_F(NewKeyGeneration, Rsa) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA));
    req_.key_description.push_back(Authorization(TAG_KEY_SIZE, 256));
    req_.key_description.push_back(Authorization(TAG_RSA_PUBLIC_EXPONENT, 3));
    device.GenerateKey(req_, &rsp_);

    CheckBaseParams(rsp_);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_KEY_SIZE, 256));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_RSA_PUBLIC_EXPONENT, 3));
}

TEST_F(NewKeyGeneration, RsaDefaultSize) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA));
    device.GenerateKey(req_, &rsp_);

    CheckBaseParams(rsp_);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_ALGORITHM, KM_ALGORITHM_RSA));

    // Now check that unspecified, defaulted tags are correct.
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_RSA_PUBLIC_EXPONENT, 65537));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_KEY_SIZE, 2048));
}

TEST_F(NewKeyGeneration, Dsa) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_DSA));
    req_.key_description.push_back(Authorization(TAG_KEY_SIZE, 256));
    device.GenerateKey(req_, &rsp_);

    CheckBaseParams(rsp_);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_ALGORITHM, KM_ALGORITHM_DSA));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_KEY_SIZE, 256));

    // Generator should have created DSA params.
    keymaster_blob_t g, p, q;
    EXPECT_TRUE(rsp_.unenforced.GetTagValue(TAG_DSA_GENERATOR, &g));
    EXPECT_TRUE(rsp_.unenforced.GetTagValue(TAG_DSA_P, &p));
    EXPECT_TRUE(rsp_.unenforced.GetTagValue(TAG_DSA_Q, &q));
    EXPECT_TRUE(g.data_length >= 63 && g.data_length <= 64);
    EXPECT_EQ(64U, p.data_length);
    EXPECT_EQ(20U, q.data_length);
}

TEST_F(NewKeyGeneration, DsaDefaultSize) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_DSA));
    device.GenerateKey(req_, &rsp_);

    CheckBaseParams(rsp_);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_ALGORITHM, KM_ALGORITHM_DSA));

    // Now check that unspecified, defaulted tags are correct.
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_KEY_SIZE, 2048));
    keymaster_blob_t g, p, q;
    EXPECT_TRUE(rsp_.unenforced.GetTagValue(TAG_DSA_GENERATOR, &g));
    EXPECT_TRUE(rsp_.unenforced.GetTagValue(TAG_DSA_P, &p));
    EXPECT_TRUE(rsp_.unenforced.GetTagValue(TAG_DSA_Q, &q));
    EXPECT_TRUE(g.data_length >= 255 && g.data_length <= 256);
    EXPECT_EQ(256U, p.data_length);
    EXPECT_EQ(32U, q.data_length);
}

TEST_F(NewKeyGeneration, Dsa_ParamsSpecified) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_DSA));
    req_.key_description.push_back(Authorization(TAG_KEY_SIZE, 256));
    req_.key_description.push_back(Authorization(TAG_DSA_GENERATOR, dsa_g, array_size(dsa_g)));
    req_.key_description.push_back(Authorization(TAG_DSA_P, dsa_p, array_size(dsa_p)));
    req_.key_description.push_back(Authorization(TAG_DSA_Q, dsa_q, array_size(dsa_q)));
    device.GenerateKey(req_, &rsp_);

    CheckBaseParams(rsp_);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_ALGORITHM, KM_ALGORITHM_DSA));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_KEY_SIZE, 256));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_DSA_GENERATOR,
                         std::string(reinterpret_cast<const char*>(dsa_g), array_size(dsa_g))));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_DSA_P,
                         std::string(reinterpret_cast<const char*>(dsa_p), array_size(dsa_p))));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_DSA_Q,
                         std::string(reinterpret_cast<const char*>(dsa_q), array_size(dsa_q))));
}

TEST_F(NewKeyGeneration, Dsa_SomeParamsSpecified) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_DSA));
    req_.key_description.push_back(Authorization(TAG_KEY_SIZE, 256));
    req_.key_description.push_back(Authorization(TAG_DSA_P, dsa_p, array_size(dsa_p)));
    req_.key_description.push_back(Authorization(TAG_DSA_Q, dsa_q, array_size(dsa_q)));
    device.GenerateKey(req_, &rsp_);

    ASSERT_EQ(KM_ERROR_INVALID_DSA_PARAMS, rsp_.error);
}

TEST_F(NewKeyGeneration, Ecdsa) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    req_.key_description.push_back(Authorization(TAG_KEY_SIZE, 224));
    device.GenerateKey(req_, &rsp_);

    CheckBaseParams(rsp_);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_KEY_SIZE, 224));
}

TEST_F(NewKeyGeneration, EcdsaDefaultSize) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    device.GenerateKey(req_, &rsp_);

    CheckBaseParams(rsp_);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_ALGORITHM, KM_ALGORITHM_ECDSA));

    // Now check that unspecified, defaulted tags are correct.
    EXPECT_TRUE(contains(rsp_.unenforced, TAG_KEY_SIZE, 224));
}

TEST_F(NewKeyGeneration, EcdsaInvalidSize) {
    req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    req_.key_description.push_back(Authorization(TAG_KEY_SIZE, 190));
    device.GenerateKey(req_, &rsp_);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_KEY_SIZE, rsp_.error);
}

TEST_F(NewKeyGeneration, EcdsaAllValidSizes) {
    size_t valid_sizes[] = {224, 256, 384, 521};
    for (size_t size : valid_sizes) {
        GenerateKeyResponse rsp;
        req_.key_description.Reinitialize(key_generation_base_params,
                                          array_length(key_generation_base_params));
        req_.key_description.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
        req_.key_description.push_back(Authorization(TAG_KEY_SIZE, size));
        device.GenerateKey(req_, &rsp);
        EXPECT_EQ(KM_ERROR_OK, rsp.error) << "Failed to generate size: " << size;
    }
}

typedef KeymasterTest GetKeyCharacteristics;
TEST_F(GetKeyCharacteristics, SimpleRsa) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
    };

    GenerateKeyRequest gen_req;
    gen_req.key_description.Reinitialize(params, array_length(params));
    GenerateKeyResponse gen_rsp;

    device.GenerateKey(gen_req, &gen_rsp);
    ASSERT_EQ(KM_ERROR_OK, gen_rsp.error);

    GetKeyCharacteristicsRequest req;
    req.SetKeyMaterial(gen_rsp.key_blob);
    req.additional_params.push_back(TAG_APPLICATION_ID, "app_id", 6);

    GetKeyCharacteristicsResponse rsp;
    device.GetKeyCharacteristics(req, &rsp);
    ASSERT_EQ(KM_ERROR_OK, rsp.error);

    EXPECT_EQ(gen_rsp.enforced, rsp.enforced);
    EXPECT_EQ(gen_rsp.unenforced, rsp.unenforced);
}

/**
 * Test class that provides some infrastructure for generating keys and signing messages.
 */
class SigningOperationsTest : public KeymasterTest {
  protected:
    void GenerateKey(keymaster_algorithm_t algorithm, keymaster_digest_t digest,
                     keymaster_padding_t padding, uint32_t key_size) {
        keymaster_key_param_t params[] = {
            Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
            Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY), Authorization(TAG_ALGORITHM, algorithm),
            Authorization(TAG_KEY_SIZE, key_size), Authorization(TAG_USER_ID, 7),
            Authorization(TAG_USER_AUTH_ID, 8), Authorization(TAG_APPLICATION_ID, "app_id", 6),
            Authorization(TAG_AUTH_TIMEOUT, 300),
        };
        GenerateKeyRequest generate_request;
        generate_request.key_description.Reinitialize(params, array_length(params));
        if (static_cast<int>(digest) != -1)
            generate_request.key_description.push_back(TAG_DIGEST, digest);
        if (static_cast<int>(padding) != -1)
            generate_request.key_description.push_back(TAG_PADDING, padding);
        device.GenerateKey(generate_request, &generate_response_);
        EXPECT_EQ(KM_ERROR_OK, generate_response_.error);
    }

    void SignMessage(const void* message, size_t size) {
        SignMessage(generate_response_.key_blob, message, size);
    }

    void SignMessage(const keymaster_key_blob_t& key_blob, const void* message, size_t size) {
        BeginOperationRequest begin_request;
        BeginOperationResponse begin_response;
        begin_request.SetKeyMaterial(key_blob);
        begin_request.purpose = KM_PURPOSE_SIGN;
        AddClientParams(&begin_request.additional_params);

        device.BeginOperation(begin_request, &begin_response);
        ASSERT_EQ(KM_ERROR_OK, begin_response.error);

        UpdateOperationRequest update_request;
        UpdateOperationResponse update_response;
        update_request.op_handle = begin_response.op_handle;
        update_request.input.Reinitialize(message, size);
        EXPECT_EQ(size, update_request.input.available_read());

        device.UpdateOperation(update_request, &update_response);
        ASSERT_EQ(KM_ERROR_OK, update_response.error);
        EXPECT_EQ(0U, update_response.output.available_read());

        FinishOperationRequest finish_request;
        finish_request.op_handle = begin_response.op_handle;
        device.FinishOperation(finish_request, &finish_response_);
        ASSERT_EQ(KM_ERROR_OK, finish_response_.error);
        EXPECT_GT(finish_response_.output.available_read(), 0U);
    }

    void AddClientParams(AuthorizationSet* set) { set->push_back(TAG_APPLICATION_ID, "app_id", 6); }

    const keymaster_key_blob_t& key_blob() { return generate_response_.key_blob; }

    const keymaster_key_blob_t& corrupt_key_blob() {
        uint8_t* tmp = const_cast<uint8_t*>(generate_response_.key_blob.key_material);
        ++tmp[generate_response_.key_blob.key_material_size / 2];
        return generate_response_.key_blob;
    }

    Buffer* signature() {
        if (finish_response_.error == KM_ERROR_OK)
            return &finish_response_.output;
        return NULL;
    }

    GenerateKeyResponse generate_response_;
    FinishOperationResponse finish_response_;
};

TEST_F(SigningOperationsTest, RsaSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    const char message[] = "12345678901234567890123456789012";
    SignMessage(message, array_size(message) - 1);
}

TEST_F(SigningOperationsTest, DsaSuccess) {
    GenerateKey(KM_ALGORITHM_DSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    const char message[] = "123456789012345678901234567890123456789012345678";
    SignMessage(message, array_size(message) - 1);
}

TEST_F(SigningOperationsTest, EcdsaSuccess) {
    GenerateKey(KM_ALGORITHM_ECDSA, KM_DIGEST_NONE, KM_PAD_NONE, 224 /* key size */);
    const char message[] = "123456789012345678901234567890123456789012345678";
    SignMessage(message, array_size(message) - 1);
}

TEST_F(SigningOperationsTest, RsaAbort) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);

    BeginOperationRequest begin_request;
    BeginOperationResponse begin_response;
    begin_request.SetKeyMaterial(key_blob());
    begin_request.purpose = KM_PURPOSE_SIGN;
    AddClientParams(&begin_request.additional_params);

    device.BeginOperation(begin_request, &begin_response);
    ASSERT_EQ(KM_ERROR_OK, begin_response.error);

    EXPECT_EQ(KM_ERROR_OK, device.AbortOperation(begin_response.op_handle));

    // Another abort should fail
    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device.AbortOperation(begin_response.op_handle));
}

TEST_F(SigningOperationsTest, RsaUnsupportedDigest) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_SHA_2_256, KM_PAD_NONE, 256 /* key size */);

    BeginOperationRequest begin_request;
    BeginOperationResponse begin_response;
    begin_request.purpose = KM_PURPOSE_SIGN;
    begin_request.SetKeyMaterial(key_blob());
    AddClientParams(&begin_request.additional_params);

    device.BeginOperation(begin_request, &begin_response);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_DIGEST, begin_response.error);

    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device.AbortOperation(begin_response.op_handle));
}

TEST_F(SigningOperationsTest, RsaUnsupportedPadding) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_RSA_OAEP, 256 /* key size */);

    BeginOperationRequest begin_request;
    BeginOperationResponse begin_response;
    begin_request.purpose = KM_PURPOSE_SIGN;
    begin_request.SetKeyMaterial(key_blob());
    AddClientParams(&begin_request.additional_params);

    device.BeginOperation(begin_request, &begin_response);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE, begin_response.error);

    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device.AbortOperation(begin_response.op_handle));
}

TEST_F(SigningOperationsTest, RsaNoDigest) {
    GenerateKey(KM_ALGORITHM_RSA, static_cast<keymaster_digest_t>(-1), KM_PAD_NONE,
                256 /* key size */);

    BeginOperationRequest begin_request;
    BeginOperationResponse begin_response;
    begin_request.purpose = KM_PURPOSE_SIGN;
    begin_request.SetKeyMaterial(key_blob());
    AddClientParams(&begin_request.additional_params);

    device.BeginOperation(begin_request, &begin_response);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_DIGEST, begin_response.error);

    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device.AbortOperation(begin_response.op_handle));
}

TEST_F(SigningOperationsTest, RsaNoPadding) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, static_cast<keymaster_padding_t>(-1),
                256 /* key size */);

    BeginOperationRequest begin_request;
    BeginOperationResponse begin_response;
    begin_request.purpose = KM_PURPOSE_SIGN;
    begin_request.SetKeyMaterial(key_blob());
    AddClientParams(&begin_request.additional_params);

    device.BeginOperation(begin_request, &begin_response);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE, begin_response.error);

    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device.AbortOperation(begin_response.op_handle));
}

TEST_F(SigningOperationsTest, RsaTooShortMessage) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);

    BeginOperationRequest begin_request;
    BeginOperationResponse begin_response;
    begin_request.SetKeyMaterial(key_blob());
    begin_request.purpose = KM_PURPOSE_SIGN;
    AddClientParams(&begin_request.additional_params);

    device.BeginOperation(begin_request, &begin_response);
    ASSERT_EQ(KM_ERROR_OK, begin_response.error);

    UpdateOperationRequest update_request;
    UpdateOperationResponse update_response;
    update_request.op_handle = begin_response.op_handle;
    update_request.input.Reinitialize("01234567890123456789012345678901", 31);
    EXPECT_EQ(31U, update_request.input.available_read());

    device.UpdateOperation(update_request, &update_response);
    ASSERT_EQ(KM_ERROR_OK, update_response.error);
    EXPECT_EQ(0U, update_response.output.available_read());

    FinishOperationRequest finish_request;
    finish_request.op_handle = begin_response.op_handle;
    FinishOperationResponse finish_response;
    device.FinishOperation(finish_request, &finish_response);
    ASSERT_EQ(KM_ERROR_UNKNOWN_ERROR, finish_response.error);
    EXPECT_EQ(0U, finish_response.output.available_read());

    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, device.AbortOperation(begin_response.op_handle));
}

class VerificationOperationsTest : public SigningOperationsTest {
  protected:
    void VerifyMessage(const void* message, size_t message_len) {
        VerifyMessage(generate_response_.key_blob, message, message_len);
    }

    void VerifyMessage(const keymaster_key_blob_t& key_blob, const void* message,
                       size_t message_len) {
        ASSERT_TRUE(signature() != NULL);

        BeginOperationRequest begin_request;
        BeginOperationResponse begin_response;
        begin_request.SetKeyMaterial(key_blob);
        begin_request.purpose = KM_PURPOSE_VERIFY;
        AddClientParams(&begin_request.additional_params);

        device.BeginOperation(begin_request, &begin_response);
        ASSERT_EQ(KM_ERROR_OK, begin_response.error);

        UpdateOperationRequest update_request;
        UpdateOperationResponse update_response;
        update_request.op_handle = begin_response.op_handle;
        update_request.input.Reinitialize(message, message_len);
        EXPECT_EQ(message_len, update_request.input.available_read());

        device.UpdateOperation(update_request, &update_response);
        ASSERT_EQ(KM_ERROR_OK, update_response.error);
        EXPECT_EQ(0U, update_response.output.available_read());

        FinishOperationRequest finish_request;
        finish_request.op_handle = begin_response.op_handle;
        finish_request.signature.Reinitialize(*signature());
        FinishOperationResponse finish_response;
        device.FinishOperation(finish_request, &finish_response);
        ASSERT_EQ(KM_ERROR_OK, finish_response.error);
        EXPECT_EQ(0U, finish_response.output.available_read());

        EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE,
                  device.AbortOperation(begin_response.op_handle));
    }
};

TEST_F(VerificationOperationsTest, RsaSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    const char message[] = "12345678901234567890123456789012";
    SignMessage(message, array_size(message) - 1);
    VerifyMessage(message, array_size(message) - 1);
}

TEST_F(VerificationOperationsTest, DsaSuccess) {
    GenerateKey(KM_ALGORITHM_DSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);
    const char message[] = "123456789012345678901234567890123456789012345678";
    SignMessage(message, array_size(message) - 1);
    VerifyMessage(message, array_size(message) - 1);
}

TEST_F(VerificationOperationsTest, EcdsaSuccess) {
    GenerateKey(KM_ALGORITHM_ECDSA, KM_DIGEST_NONE, KM_PAD_NONE, 224 /* key size */);
    const char message[] = "123456789012345678901234567890123456789012345678";
    SignMessage(message, array_size(message) - 1);
    VerifyMessage(message, array_size(message) - 1);
}

typedef SigningOperationsTest ExportKeyTest;
TEST_F(ExportKeyTest, RsaSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256 /* key size */);

    ExportKeyRequest request;
    ExportKeyResponse response;
    AddClientParams(&request.additional_params);
    request.key_format = KM_KEY_FORMAT_X509;
    request.SetKeyMaterial(key_blob());

    device.ExportKey(request, &response);
    ASSERT_EQ(KM_ERROR_OK, response.error);
    EXPECT_TRUE(response.key_data != NULL);

    // TODO(swillden): Verify that the exported key is actually usable to verify signatures.
}

TEST_F(ExportKeyTest, DsaSuccess) {
    GenerateKey(KM_ALGORITHM_DSA, KM_DIGEST_NONE, KM_PAD_NONE, 1024 /* key size */);

    ExportKeyRequest request;
    ExportKeyResponse response;
    AddClientParams(&request.additional_params);
    request.key_format = KM_KEY_FORMAT_X509;
    request.SetKeyMaterial(key_blob());

    device.ExportKey(request, &response);
    ASSERT_EQ(KM_ERROR_OK, response.error);
    EXPECT_TRUE(response.key_data != NULL);

    // TODO(swillden): Verify that the exported key is actually usable to verify signatures.
}

TEST_F(ExportKeyTest, EcdsaSuccess) {
    GenerateKey(KM_ALGORITHM_ECDSA, KM_DIGEST_NONE, KM_PAD_NONE, 224 /* key size */);

    ExportKeyRequest request;
    ExportKeyResponse response;
    AddClientParams(&request.additional_params);
    request.key_format = KM_KEY_FORMAT_X509;
    request.SetKeyMaterial(key_blob());

    device.ExportKey(request, &response);
    ASSERT_EQ(KM_ERROR_OK, response.error);
    EXPECT_TRUE(response.key_data != NULL);

    // TODO(swillden): Verify that the exported key is actually usable to verify signatures.
}

TEST_F(ExportKeyTest, RsaUnsupportedKeyFormat) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256);

    ExportKeyRequest request;
    ExportKeyResponse response;
    AddClientParams(&request.additional_params);

    /* We have no other defined export formats defined. */
    request.key_format = KM_KEY_FORMAT_PKCS8;
    request.SetKeyMaterial(key_blob());

    device.ExportKey(request, &response);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_KEY_FORMAT, response.error);
    EXPECT_TRUE(response.key_data == NULL);
}

TEST_F(ExportKeyTest, RsaCorruptedKeyBlob) {
    GenerateKey(KM_ALGORITHM_RSA, KM_DIGEST_NONE, KM_PAD_NONE, 256);

    ExportKeyRequest request;
    ExportKeyResponse response;
    AddClientParams(&request.additional_params);
    request.key_format = KM_KEY_FORMAT_X509;
    request.SetKeyMaterial(corrupt_key_blob());

    device.ExportKey(request, &response);
    ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, response.error);
    ASSERT_TRUE(response.key_data == NULL);
}

static string read_file(const string& file_name) {
    ifstream file_stream(file_name, std::ios::binary);
    istreambuf_iterator<char> file_begin(file_stream);
    istreambuf_iterator<char> file_end;
    return string(file_begin, file_end);
}

typedef VerificationOperationsTest ImportKeyTest;
TEST_F(ImportKeyTest, RsaSuccess) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
    };

    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_OK, import_response.error);
    EXPECT_EQ(0U, import_response.enforced.size());
    EXPECT_GT(import_response.unenforced.size(), 0U);

    // Check values derived from the key.
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_TRUE(contains(import_response.unenforced, TAG_KEY_SIZE, 1024));
    EXPECT_TRUE(contains(import_response.unenforced, TAG_RSA_PUBLIC_EXPONENT, 65537U));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(import_response.unenforced, KM_TAG_CREATION_DATETIME));

    size_t message_len = 1024 / 8;
    UniquePtr<uint8_t[]> message(new uint8_t[message_len]);
    std::fill(message.get(), message.get() + message_len, 'a');
    SignMessage(import_response.key_blob, message.get(), message_len);
    ASSERT_TRUE(signature() != NULL);
    VerifyMessage(import_response.key_blob, message.get(), message_len);
}

TEST_F(ImportKeyTest, RsaKeySizeMismatch) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_KEY_SIZE, 2048),  // Doesn't match key
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
    };

    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH, import_response.error);
}

TEST_F(ImportKeyTest, RsaPublicExponenMismatch) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_RSA_PUBLIC_EXPONENT, 3), Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8), Authorization(TAG_APPLICATION_ID, "app_id", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };

    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH, import_response.error);
}

TEST_F(ImportKeyTest, DsaSuccess) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
    };

    string pk8_key = read_file("dsa_privkey_pk8.der");
    ASSERT_EQ(335U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_OK, import_response.error);
    EXPECT_EQ(0U, import_response.enforced.size());
    EXPECT_GT(import_response.unenforced.size(), 0U);

    // Check values derived from the key.
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ALGORITHM, KM_ALGORITHM_DSA));
    EXPECT_TRUE(contains(import_response.unenforced, TAG_KEY_SIZE, 1024));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(import_response.unenforced, KM_TAG_CREATION_DATETIME));

    size_t message_len = 48;
    UniquePtr<uint8_t[]> message(new uint8_t[message_len]);
    std::fill(message.get(), message.get() + message_len, 'a');
    SignMessage(import_response.key_blob, message.get(), message_len);
    ASSERT_TRUE(signature() != NULL);
    VerifyMessage(import_response.key_blob, message.get(), message_len);
}

TEST_F(ImportKeyTest, DsaParametersMatch) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
        Authorization(TAG_KEY_SIZE, 1024),
        Authorization(TAG_DSA_GENERATOR, dsa_g, array_size(dsa_g)),
        Authorization(TAG_DSA_P, dsa_p, array_size(dsa_p)),
        Authorization(TAG_DSA_Q, dsa_q, array_size(dsa_q)),
    };

    string pk8_key = read_file("dsa_privkey_pk8.der");
    ASSERT_EQ(335U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_OK, import_response.error);
    EXPECT_EQ(0U, import_response.enforced.size());
    EXPECT_GT(import_response.unenforced.size(), 0U);

    // Check values derived from the key.
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ALGORITHM, KM_ALGORITHM_DSA));
    EXPECT_TRUE(contains(import_response.unenforced, TAG_KEY_SIZE, 1024));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(import_response.unenforced, KM_TAG_CREATION_DATETIME));

    size_t message_len = 48;
    UniquePtr<uint8_t[]> message(new uint8_t[message_len]);
    std::fill(message.get(), message.get() + message_len, 'a');
    SignMessage(import_response.key_blob, message.get(), message_len);
    ASSERT_TRUE(signature() != NULL);
    VerifyMessage(import_response.key_blob, message.get(), message_len);
}

uint8_t dsa_wrong_q[] = {
    0xC0, 0x66, 0x64, 0xF9, 0x05, 0x38, 0x64, 0x38, 0x4A, 0x17,
    0x66, 0x79, 0xDD, 0x7F, 0x6E, 0x55, 0x22, 0x2A, 0xDF, 0xC5,
};

TEST_F(ImportKeyTest, DsaParameterMismatch) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
        Authorization(TAG_KEY_SIZE, 1024),
        Authorization(TAG_DSA_Q, dsa_wrong_q, array_size(dsa_wrong_q)),
    };

    string pk8_key = read_file("dsa_privkey_pk8.der");
    ASSERT_EQ(335U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH, import_response.error);
}

TEST_F(ImportKeyTest, DsaKeySizeMismatch) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
        Authorization(TAG_KEY_SIZE, 2048),
    };

    string pk8_key = read_file("dsa_privkey_pk8.der");
    ASSERT_EQ(335U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH, import_response.error);
}

TEST_F(ImportKeyTest, EcdsaSuccess) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
    };

    string pk8_key = read_file("ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_OK, import_response.error);
    EXPECT_EQ(0U, import_response.enforced.size());
    EXPECT_GT(import_response.unenforced.size(), 0U);

    // Check values derived from the key.
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    EXPECT_TRUE(contains(import_response.unenforced, TAG_KEY_SIZE, 256));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(import_response.unenforced, KM_TAG_CREATION_DATETIME));

    size_t message_len = 1024 / 8;
    UniquePtr<uint8_t[]> message(new uint8_t[message_len]);
    std::fill(message.get(), message.get() + message_len, 'a');
    SignMessage(import_response.key_blob, message.get(), message_len);
    ASSERT_TRUE(signature() != NULL);
    VerifyMessage(import_response.key_blob, message.get(), message_len);
}

TEST_F(ImportKeyTest, EcdsaSizeSpecified) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
        Authorization(TAG_KEY_SIZE, 256),
    };

    string pk8_key = read_file("ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_OK, import_response.error);
    EXPECT_EQ(0U, import_response.enforced.size());
    EXPECT_GT(import_response.unenforced.size(), 0U);

    // Check values derived from the key.
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    EXPECT_TRUE(contains(import_response.unenforced, TAG_KEY_SIZE, 256));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(import_response.unenforced, TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(import_response.unenforced, KM_TAG_CREATION_DATETIME));

    size_t message_len = 1024 / 8;
    UniquePtr<uint8_t[]> message(new uint8_t[message_len]);
    std::fill(message.get(), message.get() + message_len, 'a');
    SignMessage(import_response.key_blob, message.get(), message_len);
    ASSERT_TRUE(signature() != NULL);
    VerifyMessage(import_response.key_blob, message.get(), message_len);
}

TEST_F(ImportKeyTest, EcdsaSizeMismatch) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_DIGEST, KM_DIGEST_NONE), Authorization(TAG_PADDING, KM_PAD_NONE),
        Authorization(TAG_USER_ID, 7), Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6), Authorization(TAG_AUTH_TIMEOUT, 300),
        Authorization(TAG_KEY_SIZE, 224),
    };

    string pk8_key = read_file("ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());

    ImportKeyRequest import_request;
    import_request.key_description.Reinitialize(params, array_length(params));
    import_request.key_format = KM_KEY_FORMAT_PKCS8;
    import_request.SetKeyMaterial(pk8_key.data(), pk8_key.size());

    ImportKeyResponse import_response;
    device.ImportKey(import_request, &import_response);
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH, import_response.error);
}

/**
 * Test class that provides some infrastructure for generating keys and encrypting messages.
 */
class EncryptionOperationsTest : public KeymasterTest {
  protected:
    void GenerateKey(keymaster_algorithm_t algorithm, keymaster_padding_t padding,
                     uint32_t key_size) {
        keymaster_key_param_t params[] = {
            Authorization(TAG_PURPOSE, KM_PURPOSE_ENCRYPT),
            Authorization(TAG_PURPOSE, KM_PURPOSE_DECRYPT), Authorization(TAG_ALGORITHM, algorithm),
            Authorization(TAG_KEY_SIZE, key_size), Authorization(TAG_USER_ID, 7),
            Authorization(TAG_USER_AUTH_ID, 8), Authorization(TAG_APPLICATION_ID, "app_id", 6),
            Authorization(TAG_AUTH_TIMEOUT, 300),
        };
        GenerateKeyRequest generate_request;
        generate_request.key_description.Reinitialize(params, array_length(params));
        if (static_cast<int>(padding) != -1)
            generate_request.key_description.push_back(TAG_PADDING, padding);
        device.GenerateKey(generate_request, &generate_response_);
        EXPECT_EQ(KM_ERROR_OK, generate_response_.error);
    }

    keymaster_error_t BeginOperation(keymaster_purpose_t purpose,
                                     const keymaster_key_blob_t& key_blob, uint64_t* op_handle) {
        BeginOperationRequest begin_request;
        begin_request.SetKeyMaterial(key_blob);
        begin_request.purpose = purpose;
        AddClientParams(&begin_request.additional_params);

        BeginOperationResponse begin_response;
        device.BeginOperation(begin_request, &begin_response);
        *op_handle = begin_response.op_handle;
        return begin_response.error;
    }

    keymaster_error_t UpdateOperation(uint64_t op_handle, const void* message, size_t size,
                                      string* output) {
        UpdateOperationRequest update_request;
        update_request.op_handle = op_handle;
        update_request.input.Reinitialize(message, size);

        UpdateOperationResponse update_response;
        device.UpdateOperation(update_request, &update_response);
        if (update_response.error == KM_ERROR_OK)
            output->append(reinterpret_cast<const char*>(update_response.output.peek_read()),
                           update_response.output.available_read());
        return update_response.error;
    }

    keymaster_error_t FinishOperation(uint64_t op_handle, string* output) {
        FinishOperationRequest finish_request;
        finish_request.op_handle = op_handle;
        FinishOperationResponse finish_response;
        device.FinishOperation(finish_request, &finish_response);
        if (finish_response.error == KM_ERROR_OK)
            output->append(reinterpret_cast<const char*>(finish_response.output.peek_read()),
                           finish_response.output.available_read());
        return finish_response.error;
    }

    string ProcessMessage(keymaster_purpose_t purpose, const keymaster_key_blob_t& key_blob,
                          const void* message, size_t size) {
        uint64_t op_handle;
        EXPECT_EQ(KM_ERROR_OK, BeginOperation(purpose, key_blob, &op_handle));

        string result;
        EXPECT_EQ(KM_ERROR_OK, UpdateOperation(op_handle, message, size, &result));
        EXPECT_EQ(KM_ERROR_OK, FinishOperation(op_handle, &result));
        return result;
    }

    string EncryptMessage(const void* message, size_t size) {
        return ProcessMessage(KM_PURPOSE_ENCRYPT, generate_response_.key_blob, message, size);
    }

    string DecryptMessage(const void* ciphertext, size_t size) {
        return ProcessMessage(KM_PURPOSE_DECRYPT, generate_response_.key_blob, ciphertext, size);
    }

    void AddClientParams(AuthorizationSet* set) { set->push_back(TAG_APPLICATION_ID, "app_id", 6); }

    const keymaster_key_blob_t& key_blob() { return generate_response_.key_blob; }

    const keymaster_key_blob_t& corrupt_key_blob() {
        uint8_t* tmp = const_cast<uint8_t*>(generate_response_.key_blob.key_material);
        ++tmp[generate_response_.key_blob.key_material_size / 2];
        return generate_response_.key_blob;
    }

  protected:
    GenerateKeyResponse generate_response_;
};

TEST_F(EncryptionOperationsTest, RsaOaepSuccess) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "Hello World!";
    string ciphertext1 = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext1.size());

    string ciphertext2 = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext2.size());

    // OAEP randomizes padding so every result should be different.
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(EncryptionOperationsTest, RsaOaepRoundTrip) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext.data(), ciphertext.size());
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, RsaOaepTooLarge) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "12345678901234567890123";
    uint64_t op_handle;
    string result;

    EXPECT_EQ(KM_ERROR_OK,
              BeginOperation(KM_PURPOSE_ENCRYPT, generate_response_.key_blob, &op_handle));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(op_handle, message, array_size(message), &result));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(op_handle, &result));
    EXPECT_EQ(0, result.size());
}

TEST_F(EncryptionOperationsTest, RsaOaepCorruptedDecrypt) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_OAEP, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    // Corrupt the ciphertext
    ciphertext[512 / 8 / 2]++;

    uint64_t op_handle;
    string result;
    EXPECT_EQ(KM_ERROR_OK,
              BeginOperation(KM_PURPOSE_DECRYPT, generate_response_.key_blob, &op_handle));
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(op_handle, ciphertext.data(), ciphertext.size(), &result));
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(op_handle, &result));
    EXPECT_EQ(0, result.size());
}

TEST_F(EncryptionOperationsTest, RsaPkcs1Success) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "Hello World!";
    string ciphertext1 = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext1.size());

    string ciphertext2 = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext2.size());

    // PKCS1 v1.5 randomizes padding so every result should be different.
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(EncryptionOperationsTest, RsaPkcs1RoundTrip) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext.data(), ciphertext.size());
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, RsaPkcs1TooLarge) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "1234567890123456789012345678901234567890123456789012";
    uint64_t op_handle;
    string result;

    EXPECT_EQ(KM_ERROR_OK,
              BeginOperation(KM_PURPOSE_ENCRYPT, generate_response_.key_blob, &op_handle));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(op_handle, message, array_size(message), &result));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(op_handle, &result));
    EXPECT_EQ(0, result.size());
}

TEST_F(EncryptionOperationsTest, RsaPkcs1CorruptedDecrypt) {
    GenerateKey(KM_ALGORITHM_RSA, KM_PAD_RSA_PKCS1_1_5_ENCRYPT, 512);
    const char message[] = "Hello World!";
    string ciphertext = EncryptMessage(message, strlen(message));
    EXPECT_EQ(512 / 8, ciphertext.size());

    // Corrupt the ciphertext
    ciphertext[512 / 8 / 2]++;

    uint64_t op_handle;
    string result;
    EXPECT_EQ(KM_ERROR_OK,
              BeginOperation(KM_PURPOSE_DECRYPT, generate_response_.key_blob, &op_handle));
    EXPECT_EQ(KM_ERROR_OK,
              UpdateOperation(op_handle, ciphertext.data(), ciphertext.size(), &result));
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(op_handle, &result));
    EXPECT_EQ(0, result.size());
}

}  // namespace test
}  // namespace keymaster
