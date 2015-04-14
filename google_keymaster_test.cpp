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

#include <fstream>
#include <string>
#include <vector>

#include <openssl/engine.h>

#include <hardware/keymaster0.h>

#include <keymaster/google_keymaster_utils.h>
#include <keymaster/keymaster_tags.h>
#include <keymaster/soft_keymaster_device.h>

#include "google_keymaster_test_utils.h"

using std::ifstream;
using std::istreambuf_iterator;
using std::string;
using std::vector;

template <typename T> std::ostream& operator<<(std::ostream& os, const std::vector<T>& vec) {
    os << "{ ";
    bool first = true;
    for (T t : vec) {
        os << (first ? "" : ", ") << t;
        if (first)
            first = false;
    }
    os << " }";
    return os;
}

namespace keymaster {
namespace test {

StdoutLogger logger;

class KeymasterTest : public Keymaster1Test {
  protected:
    KeymasterTest() {
        SoftKeymasterDevice* device = new SoftKeymasterDevice;
        init(device->keymaster_device());
    }
};

typedef KeymasterTest CheckSupported;
TEST_F(CheckSupported, SupportedAlgorithms) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_algorithms(device(), NULL, NULL));

    size_t len;
    keymaster_algorithm_t* algorithms;
    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_algorithms(device(), &algorithms, &len));
    EXPECT_TRUE(ResponseContains(
        {KM_ALGORITHM_RSA, KM_ALGORITHM_EC, KM_ALGORITHM_AES, KM_ALGORITHM_HMAC}, algorithms, len));
    free(algorithms);
}

TEST_F(CheckSupported, SupportedBlockModes) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_block_modes(device(), KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT,
                                                  NULL, NULL));

    size_t len;
    keymaster_block_mode_t* modes;
    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_block_modes(device(), KM_ALGORITHM_RSA,
                                                               KM_PURPOSE_ENCRYPT, &modes, &len));
    EXPECT_EQ(0U, len);
    free(modes);

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE,
              device()->get_supported_block_modes(device(), KM_ALGORITHM_EC, KM_PURPOSE_ENCRYPT,
                                                  &modes, &len));

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_block_modes(device(), KM_ALGORITHM_AES,
                                                               KM_PURPOSE_ENCRYPT, &modes, &len));
    EXPECT_TRUE(ResponseContains({KM_MODE_ECB, KM_MODE_CBC, KM_MODE_CTR}, modes, len));
    free(modes);
}

TEST_F(CheckSupported, SupportedPaddingModes) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_padding_modes(device(), KM_ALGORITHM_RSA, KM_PURPOSE_ENCRYPT,
                                                    NULL, NULL));

    size_t len;
    keymaster_padding_t* modes;
    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_padding_modes(device(), KM_ALGORITHM_RSA,
                                                                 KM_PURPOSE_SIGN, &modes, &len));
    EXPECT_TRUE(
        ResponseContains({KM_PAD_NONE, KM_PAD_RSA_PKCS1_1_5_SIGN, KM_PAD_RSA_PSS}, modes, len));
    free(modes);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_padding_modes(device(), KM_ALGORITHM_RSA,
                                                                 KM_PURPOSE_ENCRYPT, &modes, &len));
    EXPECT_TRUE(ResponseContains({KM_PAD_RSA_OAEP, KM_PAD_RSA_PKCS1_1_5_ENCRYPT}, modes, len));
    free(modes);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_padding_modes(device(), KM_ALGORITHM_EC,
                                                                 KM_PURPOSE_SIGN, &modes, &len));
    EXPECT_EQ(0U, len);
    free(modes);

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE,
              device()->get_supported_padding_modes(device(), KM_ALGORITHM_AES, KM_PURPOSE_SIGN,
                                                    &modes, &len));
}

TEST_F(CheckSupported, SupportedDigests) {
    EXPECT_EQ(
        KM_ERROR_OUTPUT_PARAMETER_NULL,
        device()->get_supported_digests(device(), KM_ALGORITHM_RSA, KM_PURPOSE_SIGN, NULL, NULL));

    size_t len;
    keymaster_digest_t* digests;
    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_digests(device(), KM_ALGORITHM_RSA,
                                                           KM_PURPOSE_SIGN, &digests, &len));
    EXPECT_TRUE(ResponseContains({KM_DIGEST_NONE, KM_DIGEST_SHA_2_256}, digests, len));
    free(digests);

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_digests(device(), KM_ALGORITHM_EC,
                                                           KM_PURPOSE_SIGN, &digests, &len));
    EXPECT_TRUE(ResponseContains({KM_DIGEST_NONE}, digests, len));
    free(digests);

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE,
              device()->get_supported_digests(device(), KM_ALGORITHM_AES, KM_PURPOSE_SIGN, &digests,
                                              &len));

    EXPECT_EQ(KM_ERROR_OK, device()->get_supported_digests(device(), KM_ALGORITHM_HMAC,
                                                           KM_PURPOSE_SIGN, &digests, &len));
    EXPECT_TRUE(ResponseContains({KM_DIGEST_SHA_2_224, KM_DIGEST_SHA_2_256, KM_DIGEST_SHA_2_384,
                                  KM_DIGEST_SHA_2_512, KM_DIGEST_SHA1},
                                 digests, len));
    free(digests);
}

TEST_F(CheckSupported, SupportedImportFormats) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_RSA, NULL, NULL));

    size_t len;
    keymaster_key_format_t* formats;
    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_RSA, &formats, &len));
    EXPECT_TRUE(ResponseContains(KM_KEY_FORMAT_PKCS8, formats, len));
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_AES, &formats, &len));
    EXPECT_TRUE(ResponseContains(KM_KEY_FORMAT_RAW, formats, len));
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_import_formats(device(), KM_ALGORITHM_HMAC, &formats, &len));
    EXPECT_TRUE(ResponseContains(KM_KEY_FORMAT_RAW, formats, len));
    free(formats);
}

TEST_F(CheckSupported, SupportedExportFormats) {
    EXPECT_EQ(KM_ERROR_OUTPUT_PARAMETER_NULL,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_RSA, NULL, NULL));

    size_t len;
    keymaster_key_format_t* formats;
    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_RSA, &formats, &len));
    EXPECT_TRUE(ResponseContains(KM_KEY_FORMAT_X509, formats, len));
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_EC, &formats, &len));
    EXPECT_TRUE(ResponseContains(KM_KEY_FORMAT_X509, formats, len));
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_AES, &formats, &len));
    EXPECT_EQ(0U, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_AES, &formats, &len));
    EXPECT_EQ(0U, len);
    free(formats);

    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_export_formats(device(), KM_ALGORITHM_HMAC, &formats, &len));
    EXPECT_EQ(0U, len);
    free(formats);
}

class NewKeyGeneration : public KeymasterTest {
  protected:
    void CheckBaseParams() {
        EXPECT_EQ(0U, hw_enforced().size());
        EXPECT_EQ(12U, hw_enforced().SerializedSize());

        AuthorizationSet auths = sw_enforced();
        EXPECT_GT(auths.SerializedSize(), 12U);

        EXPECT_TRUE(contains(auths, TAG_PURPOSE, KM_PURPOSE_SIGN));
        EXPECT_TRUE(contains(auths, TAG_PURPOSE, KM_PURPOSE_VERIFY));
        EXPECT_TRUE(contains(auths, TAG_USER_ID, 7));
        EXPECT_TRUE(contains(auths, TAG_USER_AUTH_TYPE, HW_AUTH_PASSWORD));
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
        EXPECT_TRUE(contains(auths, TAG_ORIGIN, KM_ORIGIN_GENERATED));
        EXPECT_TRUE(contains(auths, KM_TAG_CREATION_DATETIME));
    }
};

TEST_F(NewKeyGeneration, Rsa) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    CheckBaseParams();

    // Check specified tags are all present in auths
    AuthorizationSet auths(sw_enforced());
    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_TRUE(contains(auths, TAG_KEY_SIZE, 256));
    EXPECT_TRUE(contains(auths, TAG_RSA_PUBLIC_EXPONENT, 3));
}

TEST_F(NewKeyGeneration, RsaDefaultSize) {
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_KEY_SIZE,
              GenerateKey(AuthorizationSetBuilder()
                              .Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA)
                              .Authorization(TAG_RSA_PUBLIC_EXPONENT, 3)
                              .SigningKey()));
}

TEST_F(NewKeyGeneration, Ecdsa) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().EcdsaSigningKey(224, KM_DIGEST_NONE)));
    CheckBaseParams();

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(sw_enforced(), TAG_ALGORITHM, KM_ALGORITHM_EC));
    EXPECT_TRUE(contains(sw_enforced(), TAG_KEY_SIZE, 224));
}

TEST_F(NewKeyGeneration, EcdsaDefaultSize) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().EcdsaSigningKey(224, KM_DIGEST_NONE)));
    CheckBaseParams();

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(sw_enforced(), TAG_ALGORITHM, KM_ALGORITHM_EC));

    // Now check that unspecified, defaulted tags are correct.
    EXPECT_TRUE(contains(sw_enforced(), TAG_KEY_SIZE, 224));
}

TEST_F(NewKeyGeneration, EcdsaInvalidSize) {
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_KEY_SIZE,
              GenerateKey(AuthorizationSetBuilder().EcdsaSigningKey(190, KM_DIGEST_NONE)));
}

TEST_F(NewKeyGeneration, EcdsaAllValidSizes) {
    size_t valid_sizes[] = {224, 256, 384, 521};
    for (size_t size : valid_sizes) {
        EXPECT_EQ(KM_ERROR_OK,
                  GenerateKey(AuthorizationSetBuilder().EcdsaSigningKey(size, KM_DIGEST_NONE)))
            << "Failed to generate size: " << size;
    }
}

TEST_F(NewKeyGeneration, HmacSha256) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_256, 16)));
}

typedef KeymasterTest GetKeyCharacteristics;
TEST_F(GetKeyCharacteristics, SimpleRsa) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    AuthorizationSet original(sw_enforced());

    ASSERT_EQ(KM_ERROR_OK, GetCharacteristics());
    EXPECT_EQ(original, sw_enforced());
}

typedef KeymasterTest SigningOperationsTest;
TEST_F(SigningOperationsTest, RsaSuccess) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    string message = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, &signature);
}

TEST_F(SigningOperationsTest, RsaSha256DigestSuccess) {
    // Note that without padding, key size must exactly match digest size.
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_SHA_2_256, KM_PAD_NONE)));
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
}

TEST_F(SigningOperationsTest, RsaPssSha256Success) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               512, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PSS)));
    // Use large message, which won't work without digesting.
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
}

TEST_F(SigningOperationsTest, RsaPkcs1Sha256Success) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               512, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PKCS1_1_5_SIGN)));
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
}

TEST_F(SigningOperationsTest, RsaPssSha256TooSmallKey) {
    // Key must be at least 10 bytes larger than hash, to provide minimal random salt, so verify
    // that 9 bytes larger than hash won't work.
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256 + 9 * 8, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PSS)));
    string message(1024, 'a');
    string signature;

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_SIGN));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_INCOMPATIBLE_DIGEST, FinishOperation(signature, &result));
}

TEST_F(SigningOperationsTest, EcdsaSuccess) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().EcdsaSigningKey(224, KM_DIGEST_NONE)));
    string message = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, &signature);
}

TEST_F(SigningOperationsTest, RsaAbort) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    AuthorizationSet input_params, output_params;
    ASSERT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_SIGN));
    EXPECT_EQ(KM_ERROR_OK, AbortOperation());
    // Another abort should fail
    EXPECT_EQ(KM_ERROR_INVALID_OPERATION_HANDLE, AbortOperation());
}

TEST_F(SigningOperationsTest, RsaUnsupportedDigest) {
    GenerateKey(AuthorizationSetBuilder().RsaSigningKey(256, 3, KM_DIGEST_MD5,
                                                        KM_PAD_RSA_PSS /* supported padding */));
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_DIGEST, BeginOperation(KM_PURPOSE_SIGN));
}

TEST_F(SigningOperationsTest, RsaUnsupportedPadding) {
    GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
        256, 3, KM_DIGEST_SHA_2_256 /* supported digest */, KM_PAD_PKCS7));
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE, BeginOperation(KM_PURPOSE_SIGN));
}

TEST_F(SigningOperationsTest, RsaNoDigest) {
    // Digest must be specified.
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaKey(256, 3).SigningKey()));
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_DIGEST, BeginOperation(KM_PURPOSE_SIGN));
    // PSS requires a digest.
    GenerateKey(AuthorizationSetBuilder().RsaSigningKey(256, 3, KM_DIGEST_NONE, KM_PAD_RSA_PSS));
    ASSERT_EQ(KM_ERROR_INCOMPATIBLE_DIGEST, BeginOperation(KM_PURPOSE_SIGN));
}

TEST_F(SigningOperationsTest, RsaNoPadding) {
    // Padding must be specified
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().RsaKey(256, 3).SigningKey().Authorization(
                  TAG_DIGEST, KM_DIGEST_NONE)));
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE, BeginOperation(KM_PURPOSE_SIGN));
}

TEST_F(SigningOperationsTest, HmacSha1Success) {
    GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA1, 20));
    string message = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, &signature);
    ASSERT_EQ(20U, signature.size());
}

TEST_F(SigningOperationsTest, HmacSha224Success) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_224, 28)));
    string message = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, &signature);
    ASSERT_EQ(28U, signature.size());
}

TEST_F(SigningOperationsTest, HmacSha256Success) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_256, 32)));
    string message = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, &signature);
    ASSERT_EQ(32U, signature.size());
}

TEST_F(SigningOperationsTest, HmacSha384Success) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_384, 48)));
    string message = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, &signature);
    ASSERT_EQ(48U, signature.size());
}

TEST_F(SigningOperationsTest, HmacSha512Success) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_512, 64)));
    string message = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, &signature);
    ASSERT_EQ(64U, signature.size());
}

TEST_F(SigningOperationsTest, HmacRfc4231TestCase1) {
    uint8_t key_data[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    };
    string message = "Hi There";
    uint8_t sha_224_expected[] = {
        0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19, 0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d,
        0xf3, 0x3f, 0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f, 0x53, 0x68, 0x4b, 0x22,
    };
    uint8_t sha_256_expected[] = {
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf,
        0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83,
        0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    uint8_t sha_384_expected[] = {
        0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4,
        0xab, 0x46, 0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
        0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9,
        0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6,
    };
    uint8_t sha_512_expected[] = {
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a,
        0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0,
        0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7,
        0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e,
        0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
    };

    string key = make_string(key_data);

    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_224, make_string(sha_224_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_256, make_string(sha_256_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_384, make_string(sha_384_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_512, make_string(sha_512_expected));
}

TEST_F(SigningOperationsTest, HmacRfc4231TestCase2) {
    string key = "Jefe";
    string message = "what do ya want for nothing?";
    uint8_t sha_224_expected[] = {
        0xa3, 0x0e, 0x01, 0x09, 0x8b, 0xc6, 0xdb, 0xbf, 0x45, 0x69, 0x0f, 0x3a, 0x7e, 0x9e,
        0x6d, 0x0f, 0x8b, 0xbe, 0xa2, 0xa3, 0x9e, 0x61, 0x48, 0x00, 0x8f, 0xd0, 0x5e, 0x44,
    };
    uint8_t sha_256_expected[] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24,
        0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27,
        0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    uint8_t sha_384_expected[] = {
        0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2,
        0xb5, 0x8a, 0x6b, 0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47,
        0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22, 0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca,
        0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32, 0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49,
    };
    uint8_t sha_512_expected[] = {
        0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b,
        0x56, 0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27,
        0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99,
        0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3,
        0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37,
    };

    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_224, make_string(sha_224_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_256, make_string(sha_256_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_384, make_string(sha_384_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_512, make_string(sha_512_expected));
}

TEST_F(SigningOperationsTest, HmacRfc4231TestCase3) {
    string key(20, 0xaa);
    string message(50, 0xdd);
    uint8_t sha_224_expected[] = {
        0x7f, 0xb3, 0xcb, 0x35, 0x88, 0xc6, 0xc1, 0xf6, 0xff, 0xa9, 0x69, 0x4d, 0x7d, 0x6a,
        0xd2, 0x64, 0x93, 0x65, 0xb0, 0xc1, 0xf6, 0x5d, 0x69, 0xd1, 0xec, 0x83, 0x33, 0xea,
    };
    uint8_t sha_256_expected[] = {
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8,
        0xeb, 0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8,
        0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe,
    };
    uint8_t sha_384_expected[] = {
        0x88, 0x06, 0x26, 0x08, 0xd3, 0xe6, 0xad, 0x8a, 0x0a, 0xa2, 0xac, 0xe0,
        0x14, 0xc8, 0xa8, 0x6f, 0x0a, 0xa6, 0x35, 0xd9, 0x47, 0xac, 0x9f, 0xeb,
        0xe8, 0x3e, 0xf4, 0xe5, 0x59, 0x66, 0x14, 0x4b, 0x2a, 0x5a, 0xb3, 0x9d,
        0xc1, 0x38, 0x14, 0xb9, 0x4e, 0x3a, 0xb6, 0xe1, 0x01, 0xa3, 0x4f, 0x27,
    };
    uint8_t sha_512_expected[] = {
        0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75, 0x6c,
        0x89, 0x0b, 0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36, 0x55, 0xf8,
        0x3e, 0x33, 0xb2, 0x27, 0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82, 0x79, 0xa7, 0x22,
        0xc8, 0x06, 0xb4, 0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07, 0xb9, 0x46, 0xa3, 0x37,
        0xbe, 0xe8, 0x94, 0x26, 0x74, 0x27, 0x88, 0x59, 0xe1, 0x32, 0x92, 0xfb,
    };

    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_224, make_string(sha_224_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_256, make_string(sha_256_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_384, make_string(sha_384_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_512, make_string(sha_512_expected));
}

TEST_F(SigningOperationsTest, HmacRfc4231TestCase4) {
    uint8_t key_data[25] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    };
    string key = make_string(key_data);
    string message(50, 0xcd);
    uint8_t sha_224_expected[] = {
        0x6c, 0x11, 0x50, 0x68, 0x74, 0x01, 0x3c, 0xac, 0x6a, 0x2a, 0xbc, 0x1b, 0xb3, 0x82,
        0x62, 0x7c, 0xec, 0x6a, 0x90, 0xd8, 0x6e, 0xfc, 0x01, 0x2d, 0xe7, 0xaf, 0xec, 0x5a,
    };
    uint8_t sha_256_expected[] = {
        0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81,
        0x98, 0x99, 0xf2, 0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78,
        0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b,
    };
    uint8_t sha_384_expected[] = {
        0x3e, 0x8a, 0x69, 0xb7, 0x78, 0x3c, 0x25, 0x85, 0x19, 0x33, 0xab, 0x62,
        0x90, 0xaf, 0x6c, 0xa7, 0x7a, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9c,
        0xc5, 0x57, 0x7c, 0x6e, 0x1f, 0x57, 0x3b, 0x4e, 0x68, 0x01, 0xdd, 0x23,
        0xc4, 0xa7, 0xd6, 0x79, 0xcc, 0xf8, 0xa3, 0x86, 0xc6, 0x74, 0xcf, 0xfb,
    };
    uint8_t sha_512_expected[] = {
        0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69, 0x90, 0xe5, 0xa8, 0xc5, 0xf6,
        0x1d, 0x4a, 0xf7, 0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d, 0xe7, 0x6f,
        0x80, 0x50, 0x36, 0x1e, 0xe3, 0xdb, 0xa9, 0x1c, 0xa5, 0xc1, 0x1a, 0xa2, 0x5e,
        0xb4, 0xd6, 0x79, 0x27, 0x5c, 0xc5, 0x78, 0x80, 0x63, 0xa5, 0xf1, 0x97, 0x41,
        0x12, 0x0c, 0x4f, 0x2d, 0xe2, 0xad, 0xeb, 0xeb, 0x10, 0xa2, 0x98, 0xdd,
    };

    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_224, make_string(sha_224_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_256, make_string(sha_256_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_384, make_string(sha_384_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_512, make_string(sha_512_expected));
}

TEST_F(SigningOperationsTest, HmacRfc4231TestCase5) {
    string key(20, 0x0c);
    string message = "Test With Truncation";

    uint8_t sha_224_expected[] = {
        0x0e, 0x2a, 0xea, 0x68, 0xa9, 0x0c, 0x8d, 0x37,
        0xc9, 0x88, 0xbc, 0xdb, 0x9f, 0xca, 0x6f, 0xa8,
    };
    uint8_t sha_256_expected[] = {
        0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10, 0x0e, 0xe0,
        0x6e, 0x0c, 0x79, 0x6c, 0x29, 0x55, 0x55, 0x2b,
    };
    uint8_t sha_384_expected[] = {
        0x3a, 0xbf, 0x34, 0xc3, 0x50, 0x3b, 0x2a, 0x23,
        0xa4, 0x6e, 0xfc, 0x61, 0x9b, 0xae, 0xf8, 0x97,
    };
    uint8_t sha_512_expected[] = {
        0x41, 0x5f, 0xad, 0x62, 0x71, 0x58, 0x0a, 0x53,
        0x1d, 0x41, 0x79, 0xbc, 0x89, 0x1d, 0x87, 0xa6,
    };

    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_224, make_string(sha_224_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_256, make_string(sha_256_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_384, make_string(sha_384_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_512, make_string(sha_512_expected));
}

TEST_F(SigningOperationsTest, HmacRfc4231TestCase6) {
    string key(131, 0xaa);
    string message = "Test Using Larger Than Block-Size Key - Hash Key First";

    uint8_t sha_224_expected[] = {
        0x95, 0xe9, 0xa0, 0xdb, 0x96, 0x20, 0x95, 0xad, 0xae, 0xbe, 0x9b, 0x2d, 0x6f, 0x0d,
        0xbc, 0xe2, 0xd4, 0x99, 0xf1, 0x12, 0xf2, 0xd2, 0xb7, 0x27, 0x3f, 0xa6, 0x87, 0x0e,
    };
    uint8_t sha_256_expected[] = {
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26,
        0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28,
        0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54,
    };
    uint8_t sha_384_expected[] = {
        0x4e, 0xce, 0x08, 0x44, 0x85, 0x81, 0x3e, 0x90, 0x88, 0xd2, 0xc6, 0x3a,
        0x04, 0x1b, 0xc5, 0xb4, 0x4f, 0x9e, 0xf1, 0x01, 0x2a, 0x2b, 0x58, 0x8f,
        0x3c, 0xd1, 0x1f, 0x05, 0x03, 0x3a, 0xc4, 0xc6, 0x0c, 0x2e, 0xf6, 0xab,
        0x40, 0x30, 0xfe, 0x82, 0x96, 0x24, 0x8d, 0xf1, 0x63, 0xf4, 0x49, 0x52,
    };
    uint8_t sha_512_expected[] = {
        0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1, 0xdd,
        0x7b, 0xe8, 0xb4, 0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1, 0x12, 0x1b,
        0x01, 0x37, 0x83, 0xf8, 0xf3, 0x52, 0x6b, 0x56, 0xd0, 0x37, 0xe0, 0x5f, 0x25,
        0x98, 0xbd, 0x0f, 0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52, 0x95, 0xe6, 0x4f, 0x73,
        0xf6, 0x3f, 0x0a, 0xec, 0x8b, 0x91, 0x5a, 0x98, 0x5d, 0x78, 0x65, 0x98,
    };

    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_224, make_string(sha_224_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_256, make_string(sha_256_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_384, make_string(sha_384_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_512, make_string(sha_512_expected));
}

TEST_F(SigningOperationsTest, HmacRfc4231TestCase7) {
    string key(131, 0xaa);
    string message = "This is a test using a larger than block-size key and a larger than "
                     "block-size data. The key needs to be hashed before being used by the HMAC "
                     "algorithm.";

    uint8_t sha_224_expected[] = {
        0x3a, 0x85, 0x41, 0x66, 0xac, 0x5d, 0x9f, 0x02, 0x3f, 0x54, 0xd5, 0x17, 0xd0, 0xb3,
        0x9d, 0xbd, 0x94, 0x67, 0x70, 0xdb, 0x9c, 0x2b, 0x95, 0xc9, 0xf6, 0xf5, 0x65, 0xd1,
    };
    uint8_t sha_256_expected[] = {
        0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f,
        0xbc, 0xd5, 0xb0, 0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07,
        0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2,
    };
    uint8_t sha_384_expected[] = {
        0x66, 0x17, 0x17, 0x8e, 0x94, 0x1f, 0x02, 0x0d, 0x35, 0x1e, 0x2f, 0x25,
        0x4e, 0x8f, 0xd3, 0x2c, 0x60, 0x24, 0x20, 0xfe, 0xb0, 0xb8, 0xfb, 0x9a,
        0xdc, 0xce, 0xbb, 0x82, 0x46, 0x1e, 0x99, 0xc5, 0xa6, 0x78, 0xcc, 0x31,
        0xe7, 0x99, 0x17, 0x6d, 0x38, 0x60, 0xe6, 0x11, 0x0c, 0x46, 0x52, 0x3e,
    };
    uint8_t sha_512_expected[] = {
        0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba, 0xa4, 0xdf, 0xa9, 0xf9, 0x6e,
        0x5e, 0x3f, 0xfd, 0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86, 0x5d, 0xf5,
        0xa3, 0x2d, 0x20, 0xcd, 0xc9, 0x44, 0xb6, 0x02, 0x2c, 0xac, 0x3c, 0x49, 0x82,
        0xb1, 0x0d, 0x5e, 0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15, 0x13, 0x46, 0x76, 0xfb,
        0x6d, 0xe0, 0x44, 0x60, 0x65, 0xc9, 0x74, 0x40, 0xfa, 0x8c, 0x6a, 0x58,
    };

    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_224, make_string(sha_224_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_256, make_string(sha_256_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_384, make_string(sha_384_expected));
    CheckHmacTestVector(key, message, KM_DIGEST_SHA_2_512, make_string(sha_512_expected));
}

TEST_F(SigningOperationsTest, HmacSha256NoMacLength) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .Authorization(TAG_ALGORITHM, KM_ALGORITHM_HMAC)
                                           .Authorization(TAG_KEY_SIZE, 128)
                                           .SigningKey()
                                           .Authorization(TAG_DIGEST, KM_DIGEST_SHA_2_256)));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_MAC_LENGTH, BeginOperation(KM_PURPOSE_SIGN));
}

TEST_F(SigningOperationsTest, HmacSha256TooLargeMacLength) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_256, 33)));
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_MAC_LENGTH, BeginOperation(KM_PURPOSE_SIGN));
}

TEST_F(SigningOperationsTest, RsaTooShortMessage) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    ASSERT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_SIGN));

    string message = "1234567890123456789012345678901";
    string result;
    size_t input_consumed;
    ASSERT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(0U, result.size());
    EXPECT_EQ(31U, input_consumed);

    string signature;
    ASSERT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(&signature));
    EXPECT_EQ(0U, signature.length());
}

// TODO(swillden): Add more verification failure tests.

typedef KeymasterTest VerificationOperationsTest;
TEST_F(VerificationOperationsTest, RsaSuccess) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    string message = "12345678901234567890123456789012";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, RsaSha256DigestSuccess) {
    // Note that without padding, key size must exactly match digest size.
    GenerateKey(AuthorizationSetBuilder().RsaSigningKey(256, 3, KM_DIGEST_SHA_2_256, KM_PAD_NONE));
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, RsaSha256CorruptSignature) {
    GenerateKey(AuthorizationSetBuilder().RsaSigningKey(256, 3, KM_DIGEST_SHA_2_256, KM_PAD_NONE));
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    ++signature[signature.size() / 2];

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_VERIFY));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(signature, &result));
}

TEST_F(VerificationOperationsTest, RsaPssSha256Success) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               512, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PSS)));
    // Use large message, which won't work without digesting.
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, RsaPssSha256CorruptSignature) {
    GenerateKey(
        AuthorizationSetBuilder().RsaSigningKey(512, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PSS));
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    ++signature[signature.size() / 2];

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_VERIFY));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(signature, &result));
}

TEST_F(VerificationOperationsTest, RsaPssSha256CorruptInput) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               512, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PSS)));
    // Use large message, which won't work without digesting.
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    ++message[message.size() / 2];

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_VERIFY));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(signature, &result));
}

TEST_F(VerificationOperationsTest, RsaPkcs1Sha256Success) {
    GenerateKey(AuthorizationSetBuilder().RsaSigningKey(512, 3, KM_DIGEST_SHA_2_256,
                                                        KM_PAD_RSA_PKCS1_1_5_SIGN));
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, RsaPkcs1Sha256CorruptSignature) {
    GenerateKey(AuthorizationSetBuilder().RsaSigningKey(512, 3, KM_DIGEST_SHA_2_256,
                                                        KM_PAD_RSA_PKCS1_1_5_SIGN));
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    ++signature[signature.size() / 2];

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_VERIFY));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(signature, &result));
}

TEST_F(VerificationOperationsTest, RsaPkcs1Sha256CorruptInput) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               512, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PKCS1_1_5_SIGN)));
    // Use large message, which won't work without digesting.
    string message(1024, 'a');
    string signature;
    SignMessage(message, &signature);
    ++message[message.size() / 2];

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_VERIFY));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_VERIFICATION_FAILED, FinishOperation(signature, &result));
}

template <typename T> vector<T> make_vector(const T* array, size_t len) {
    return vector<T>(array, array + len);
}

TEST_F(VerificationOperationsTest, RsaAllDigestAndPadCombinations) {
    // Get all supported digests and padding modes.
    size_t digests_len;
    keymaster_digest_t* digests;
    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_digests(device(), KM_ALGORITHM_RSA, KM_PURPOSE_SIGN, &digests,
                                              &digests_len));

    size_t padding_modes_len;
    keymaster_padding_t* padding_modes;
    EXPECT_EQ(KM_ERROR_OK,
              device()->get_supported_padding_modes(device(), KM_ALGORITHM_RSA, KM_PURPOSE_SIGN,
                                                    &padding_modes, &padding_modes_len));

    // Try them.
    for (keymaster_padding_t padding_mode : make_vector(padding_modes, padding_modes_len)) {
        for (keymaster_digest_t digest : make_vector(digests, digests_len)) {
            // Compute key & message size that will work.
            size_t key_bits = 256;
            size_t message_len = 1000;
            switch (digest) {
            case KM_DIGEST_NONE:
                switch (padding_mode) {
                case KM_PAD_NONE:
                    // Match key size.
                    message_len = key_bits / 8;
                    break;
                case KM_PAD_RSA_PKCS1_1_5_SIGN:
                    message_len = key_bits / 8 - 11;
                    break;
                case KM_PAD_RSA_PSS:
                    // PSS requires a digest.
                    continue;
                default:
                    FAIL() << "Missing padding";
                    break;
                }
                break;

            case KM_DIGEST_SHA_2_256:
                switch (padding_mode) {
                case KM_PAD_NONE:
                    // Key size matches digest size
                    break;
                case KM_PAD_RSA_PKCS1_1_5_SIGN:
                    key_bits += 8 * 11;
                    break;
                case KM_PAD_RSA_PSS:
                    key_bits += 8 * 10;
                    break;
                default:
                    FAIL() << "Missing padding";
                    break;
                }
                break;
            default:
                FAIL() << "Missing digest";
            }

            GenerateKey(AuthorizationSetBuilder().RsaSigningKey(key_bits, 3, digest, padding_mode));
            string message(message_len, 'a');
            string signature;
            SignMessage(message, &signature);
            VerifyMessage(message, signature);
        }
    }

    free(padding_modes);
    free(digests);
}

TEST_F(VerificationOperationsTest, EcdsaSuccess) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().EcdsaSigningKey(256, KM_DIGEST_NONE)));
    string message = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, HmacSha1Success) {
    GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA1, 16));
    string message = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, HmacSha224Success) {
    GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_224, 16));
    string message = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, HmacSha256Success) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_256, 16)));
    string message = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, HmacSha384Success) {
    GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_384, 16));
    string message = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(VerificationOperationsTest, HmacSha512Success) {
    GenerateKey(AuthorizationSetBuilder().HmacKey(128, KM_DIGEST_SHA_2_512, 16));
    string message = "123456789012345678901234567890123456789012345678";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

typedef VerificationOperationsTest ExportKeyTest;
TEST_F(ExportKeyTest, RsaSuccess) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    string export_data;
    ASSERT_EQ(KM_ERROR_OK, ExportKey(KM_KEY_FORMAT_X509, &export_data));
    EXPECT_GT(export_data.length(), 0U);

    // TODO(swillden): Verify that the exported key is actually usable to verify signatures.
}

TEST_F(ExportKeyTest, EcdsaSuccess) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().EcdsaSigningKey(224, KM_DIGEST_NONE)));
    string export_data;
    ASSERT_EQ(KM_ERROR_OK, ExportKey(KM_KEY_FORMAT_X509, &export_data));
    EXPECT_GT(export_data.length(), 0U);

    // TODO(swillden): Verify that the exported key is actually usable to verify signatures.
}

TEST_F(ExportKeyTest, RsaUnsupportedKeyFormat) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    string export_data;
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_KEY_FORMAT, ExportKey(KM_KEY_FORMAT_PKCS8, &export_data));
}

TEST_F(ExportKeyTest, RsaCorruptedKeyBlob) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaSigningKey(
                               256, 3, KM_DIGEST_NONE, KM_PAD_NONE)));
    corrupt_key_blob();
    string export_data;
    ASSERT_EQ(KM_ERROR_INVALID_KEY_BLOB, ExportKey(KM_KEY_FORMAT_X509, &export_data));
}

TEST_F(ExportKeyTest, AesKeyExportFails) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128)));
    string export_data;

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_KEY_FORMAT, ExportKey(KM_KEY_FORMAT_X509, &export_data));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_KEY_FORMAT, ExportKey(KM_KEY_FORMAT_PKCS8, &export_data));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_KEY_FORMAT, ExportKey(KM_KEY_FORMAT_RAW, &export_data));
}

static string read_file(const string& file_name) {
    ifstream file_stream(file_name, std::ios::binary);
    istreambuf_iterator<char> file_begin(file_stream);
    istreambuf_iterator<char> file_end;
    return string(file_begin, file_end);
}

typedef VerificationOperationsTest ImportKeyTest;
TEST_F(ImportKeyTest, RsaSuccess) {
    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_OK, ImportKey(AuthorizationSetBuilder().RsaSigningKey(
                                         1024, 65537, KM_DIGEST_NONE, KM_PAD_NONE),
                                     KM_KEY_FORMAT_PKCS8, pk8_key));

    // Check values derived from the key.
    EXPECT_TRUE(contains(sw_enforced(), TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_TRUE(contains(sw_enforced(), TAG_KEY_SIZE, 1024));
    EXPECT_TRUE(contains(sw_enforced(), TAG_RSA_PUBLIC_EXPONENT, 65537U));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(sw_enforced(), TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(sw_enforced(), KM_TAG_CREATION_DATETIME));

    string message(1024 / 8, 'a');
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(ImportKeyTest, OldApiRsaSuccess) {
    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());

    // NOTE: This will break when the keymaster0 APIs are removed from keymaster1.  But at that
    // point softkeymaster will no longer support keymaster0 APIs anyway.
    uint8_t* key_blob;
    size_t key_blob_length;
    ASSERT_EQ(0,
              device()->import_keypair(device(), reinterpret_cast<const uint8_t*>(pk8_key.data()),
                                       pk8_key.size(), &key_blob, &key_blob_length));
    set_key_blob(key_blob, key_blob_length);

    string message(1024 / 8, 'a');
    string signature;
    SignMessage(message, &signature, false /* use_client_params */);
    VerifyMessage(message, signature, false /* use_client_params */);
}

TEST_F(ImportKeyTest, RsaKeySizeMismatch) {
    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH,
              ImportKey(AuthorizationSetBuilder().RsaSigningKey(2048 /* Doesn't match key */, 3,
                                                                KM_DIGEST_NONE, KM_PAD_NONE),
                        KM_KEY_FORMAT_PKCS8, pk8_key));
}

TEST_F(ImportKeyTest, RsaPublicExponenMismatch) {
    string pk8_key = read_file("rsa_privkey_pk8.der");
    ASSERT_EQ(633U, pk8_key.size());
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH,
              ImportKey(AuthorizationSetBuilder().RsaSigningKey(256, 3 /* Doesnt' match key */,
                                                                KM_DIGEST_NONE, KM_PAD_NONE),
                        KM_KEY_FORMAT_PKCS8, pk8_key));
}

TEST_F(ImportKeyTest, EcdsaSuccess) {
    string pk8_key = read_file("ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_OK, ImportKey(AuthorizationSetBuilder().EcdsaSigningKey(256, KM_DIGEST_NONE),
                                     KM_KEY_FORMAT_PKCS8, pk8_key));

    // Check values derived from the key.
    EXPECT_TRUE(contains(sw_enforced(), TAG_ALGORITHM, KM_ALGORITHM_EC));
    EXPECT_TRUE(contains(sw_enforced(), TAG_KEY_SIZE, 256));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(sw_enforced(), TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(sw_enforced(), KM_TAG_CREATION_DATETIME));

    string message(1024 / 8, 'a');
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(ImportKeyTest, EcdsaSizeSpecified) {
    string pk8_key = read_file("ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());

    ASSERT_EQ(KM_ERROR_OK, ImportKey(AuthorizationSetBuilder().EcdsaSigningKey(256, KM_DIGEST_NONE),
                                     KM_KEY_FORMAT_PKCS8, pk8_key));

    // Check values derived from the key.
    EXPECT_TRUE(contains(sw_enforced(), TAG_ALGORITHM, KM_ALGORITHM_EC));
    EXPECT_TRUE(contains(sw_enforced(), TAG_KEY_SIZE, 256));

    // And values provided by GoogleKeymaster
    EXPECT_TRUE(contains(sw_enforced(), TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(sw_enforced(), KM_TAG_CREATION_DATETIME));

    string message(1024 / 8, 'a');
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

TEST_F(ImportKeyTest, EcdsaSizeMismatch) {
    string pk8_key = read_file("ec_privkey_pk8.der");
    ASSERT_EQ(138U, pk8_key.size());
    ASSERT_EQ(KM_ERROR_IMPORT_PARAMETER_MISMATCH,
              ImportKey(AuthorizationSetBuilder().EcdsaSigningKey(
                            224, KM_DIGEST_NONE),  // Size does not match key
                        KM_KEY_FORMAT_PKCS8,
                        pk8_key));
}

TEST_F(ImportKeyTest, AesKeySuccess) {
    char key_data[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    string key(key_data, sizeof(key_data));
    ASSERT_EQ(KM_ERROR_OK,
              ImportKey(AuthorizationSetBuilder().AesEncryptionKey(128).EcbMode().Authorization(
                            TAG_PADDING, KM_PAD_PKCS7),
                        KM_KEY_FORMAT_RAW, key));

    EXPECT_TRUE(contains(sw_enforced(), TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(sw_enforced(), KM_TAG_CREATION_DATETIME));

    string message = "Hello World!";
    string ciphertext = EncryptMessage(message);
    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(ImportKeyTest, HmacSha256KeySuccess) {
    char key_data[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    string key(key_data, sizeof(key_data));
    ASSERT_EQ(KM_ERROR_OK, ImportKey(AuthorizationSetBuilder().HmacKey(sizeof(key_data) * 8,
                                                                       KM_DIGEST_SHA_2_256, 32),
                                     KM_KEY_FORMAT_RAW, key));

    EXPECT_TRUE(contains(sw_enforced(), TAG_ORIGIN, KM_ORIGIN_IMPORTED));
    EXPECT_TRUE(contains(sw_enforced(), KM_TAG_CREATION_DATETIME));

    string message = "Hello World!";
    string signature;
    SignMessage(message, &signature);
    VerifyMessage(message, signature);
}

typedef KeymasterTest EncryptionOperationsTest;
TEST_F(EncryptionOperationsTest, RsaOaepSuccess) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(512, 3, KM_PAD_RSA_OAEP)));

    string message = "Hello World!";
    string ciphertext1 = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext1.size());

    string ciphertext2 = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext2.size());

    // OAEP randomizes padding so every result should be different.
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(EncryptionOperationsTest, RsaOaepRoundTrip) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(512, 3, KM_PAD_RSA_OAEP)));
    string message = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, RsaOaepTooLarge) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(512, 3, KM_PAD_RSA_OAEP)));
    string message = "12345678901234567890123";
    string result;
    size_t input_consumed;

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(&result));
    EXPECT_EQ(0U, result.size());
}

TEST_F(EncryptionOperationsTest, RsaOaepCorruptedDecrypt) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(512, 3, KM_PAD_RSA_OAEP)));
    string message = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext.size());

    // Corrupt the ciphertext
    ciphertext[512 / 8 / 2]++;

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(ciphertext, &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(&result));
    EXPECT_EQ(0U, result.size());
}

TEST_F(EncryptionOperationsTest, RsaPkcs1Success) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(
                               512, 3, KM_PAD_RSA_PKCS1_1_5_ENCRYPT)));
    string message = "Hello World!";
    string ciphertext1 = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext1.size());

    string ciphertext2 = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext2.size());

    // PKCS1 v1.5 randomizes padding so every result should be different.
    EXPECT_NE(ciphertext1, ciphertext2);
}

TEST_F(EncryptionOperationsTest, RsaPkcs1RoundTrip) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(
                               512, 3, KM_PAD_RSA_PKCS1_1_5_ENCRYPT)));
    string message = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext.size());

    string plaintext = DecryptMessage(ciphertext);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, RsaPkcs1TooLarge) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(
                               512, 3, KM_PAD_RSA_PKCS1_1_5_ENCRYPT)));
    string message = "12345678901234567890123456789012345678901234567890123";
    string result;
    size_t input_consumed;

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(&result));
    EXPECT_EQ(0U, result.size());
}

TEST_F(EncryptionOperationsTest, RsaPkcs1CorruptedDecrypt) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder().RsaEncryptionKey(
                               512, 3, KM_PAD_RSA_PKCS1_1_5_ENCRYPT)));
    string message = "Hello World!";
    string ciphertext = EncryptMessage(string(message));
    EXPECT_EQ(512U / 8, ciphertext.size());

    // Corrupt the ciphertext
    ciphertext[512 / 8 / 2]++;

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT));
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(ciphertext, &result, &input_consumed));
    EXPECT_EQ(KM_ERROR_UNKNOWN_ERROR, FinishOperation(&result));
    EXPECT_EQ(0U, result.size());
}

TEST_F(EncryptionOperationsTest, AesEcbRoundTripSuccess) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128).Authorization(
                  TAG_BLOCK_MODE, KM_MODE_ECB)));
    // Two-block message.
    string message = "12345678901234567890123456789012";
    string ciphertext1 = EncryptMessage(message);
    EXPECT_EQ(message.size(), ciphertext1.size());

    string ciphertext2 = EncryptMessage(string(message));
    EXPECT_EQ(message.size(), ciphertext2.size());

    // ECB is deterministic.
    EXPECT_EQ(ciphertext1, ciphertext2);

    string plaintext = DecryptMessage(ciphertext1);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, AesEcbNoPaddingWrongInputSize) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128).Authorization(
                  TAG_BLOCK_MODE, KM_MODE_ECB)));
    // Message is slightly shorter than two blocks.
    string message = "1234567890123456789012345678901";

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT));
    string ciphertext;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &ciphertext, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_INVALID_INPUT_LENGTH, FinishOperation(&ciphertext));
}

TEST_F(EncryptionOperationsTest, AesEcbPkcs7Padding) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .AesEncryptionKey(128)
                                           .Authorization(TAG_BLOCK_MODE, KM_MODE_ECB)
                                           .Authorization(TAG_PADDING, KM_PAD_PKCS7)));

    // Try various message lengths; all should work.
    for (size_t i = 0; i < 32; ++i) {
        string message(i, 'a');
        string ciphertext = EncryptMessage(message);
        EXPECT_EQ(i + 16 - (i % 16), ciphertext.size());
        string plaintext = DecryptMessage(ciphertext);
        EXPECT_EQ(message, plaintext);
    }
}

TEST_F(EncryptionOperationsTest, AesEcbPkcs7PaddingCorrupted) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .AesEncryptionKey(128)
                                           .Authorization(TAG_BLOCK_MODE, KM_MODE_ECB)
                                           .Authorization(TAG_PADDING, KM_PAD_PKCS7)));

    string message = "a";
    string ciphertext = EncryptMessage(message);
    EXPECT_EQ(16U, ciphertext.size());
    EXPECT_NE(ciphertext, message);
    ++ciphertext[ciphertext.size() / 2];

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT));
    string plaintext;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(ciphertext, &plaintext, &input_consumed));
    EXPECT_EQ(ciphertext.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_INVALID_ARGUMENT, FinishOperation(&plaintext));
}

TEST_F(EncryptionOperationsTest, AesCtrRoundTripSuccess) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128).Authorization(
                  TAG_BLOCK_MODE, KM_MODE_CTR)));
    string message = "123";
    string iv1;
    string ciphertext1 = EncryptMessage(message, &iv1);
    EXPECT_EQ(message.size(), ciphertext1.size());
    EXPECT_EQ(16U, iv1.size());

    string iv2;
    string ciphertext2 = EncryptMessage(message, &iv2);
    EXPECT_EQ(message.size(), ciphertext2.size());
    EXPECT_EQ(16U, iv2.size());

    // IVs should be random, so ciphertexts should differ.
    EXPECT_NE(iv1, iv2);
    EXPECT_NE(ciphertext1, ciphertext2);

    string plaintext = DecryptMessage(ciphertext1, iv1);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, AesCtrIncremental) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128).Authorization(
                  TAG_BLOCK_MODE, KM_MODE_CTR)));

    int increment = 15;
    string message(239, 'a');
    AuthorizationSet input_params;
    AuthorizationSet output_params;
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT, input_params, &output_params));

    string ciphertext;
    size_t input_consumed;
    for (size_t i = 0; i < message.size(); i += increment)
        EXPECT_EQ(KM_ERROR_OK,
                  UpdateOperation(message.substr(i, increment), &ciphertext, &input_consumed));
    EXPECT_EQ(KM_ERROR_OK, FinishOperation(&ciphertext));
    EXPECT_EQ(message.size(), ciphertext.size());

    // Move TAG_NONCE into input_params
    input_params.Reinitialize(output_params);
    output_params.Clear();

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, input_params, &output_params));
    string plaintext;
    for (size_t i = 0; i < ciphertext.size(); i += increment)
        EXPECT_EQ(KM_ERROR_OK,
                  UpdateOperation(ciphertext.substr(i, increment), &plaintext, &input_consumed));
    EXPECT_EQ(KM_ERROR_OK, FinishOperation(&plaintext));
    EXPECT_EQ(ciphertext.size(), plaintext.size());
    EXPECT_EQ(message, plaintext);
}

struct AesCtrSp80038aTestVector {
    const char* key;
    const char* nonce;
    const char* plaintext;
    const char* ciphertext;
};

// These test vectors are taken from
// http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf, section F.5.
static const AesCtrSp80038aTestVector kAesCtrSp80038aTestVectors[] = {
    // AES-128
    {
        "2b7e151628aed2a6abf7158809cf4f3c", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    },
    // AES-192
    {
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94"
        "1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
    },
    // AES-256
    {
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
    },
};

TEST_F(EncryptionOperationsTest, AesCtrSp80038aTestVector) {
    for (size_t i = 0; i < 3; i++) {
        const AesCtrSp80038aTestVector& test(kAesCtrSp80038aTestVectors[i]);
        const string key = hex2str(test.key);
        const string nonce = hex2str(test.nonce);
        const string plaintext = hex2str(test.plaintext);
        const string ciphertext = hex2str(test.ciphertext);
        CheckAesCtrTestVector(key, nonce, plaintext, ciphertext);
    }
}

TEST_F(EncryptionOperationsTest, AesCtrInvalidPaddingMode) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .AesEncryptionKey(128)
                                           .Authorization(TAG_BLOCK_MODE, KM_MODE_CTR)
                                           .Authorization(TAG_PADDING, KM_PAD_PKCS7)));

    EXPECT_EQ(KM_ERROR_UNSUPPORTED_PADDING_MODE, BeginOperation(KM_PURPOSE_ENCRYPT));
}

TEST_F(EncryptionOperationsTest, AesCtrInvalidCallerNonce) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .AesEncryptionKey(128)
                                           .Authorization(TAG_BLOCK_MODE, KM_MODE_CTR)
                                           .Authorization(TAG_CALLER_NONCE)));

    AuthorizationSet input_params;
    input_params.push_back(TAG_NONCE, "123", 3);
    EXPECT_EQ(KM_ERROR_INVALID_NONCE, BeginOperation(KM_PURPOSE_ENCRYPT, input_params));
}

TEST_F(EncryptionOperationsTest, AesCbcRoundTripSuccess) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128).Authorization(
                  TAG_BLOCK_MODE, KM_MODE_CBC)));
    // Two-block message.
    string message = "12345678901234567890123456789012";
    string iv1;
    string ciphertext1 = EncryptMessage(message, &iv1);
    EXPECT_EQ(message.size(), ciphertext1.size());

    string iv2;
    string ciphertext2 = EncryptMessage(message, &iv2);
    EXPECT_EQ(message.size(), ciphertext2.size());

    // IVs should be random, so ciphertexts should differ.
    EXPECT_NE(iv1, iv2);
    EXPECT_NE(ciphertext1, ciphertext2);

    string plaintext = DecryptMessage(ciphertext1, iv1);
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, AesCbcIncrementalNoPadding) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128).Authorization(
                  TAG_BLOCK_MODE, KM_MODE_CBC)));

    int increment = 15;
    string message(240, 'a');
    AuthorizationSet input_params;
    AuthorizationSet output_params;
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_ENCRYPT, input_params, &output_params));

    string ciphertext;
    size_t input_consumed;
    for (size_t i = 0; i < message.size(); i += increment)
        EXPECT_EQ(KM_ERROR_OK,
                  UpdateOperation(message.substr(i, increment), &ciphertext, &input_consumed));
    EXPECT_EQ(KM_ERROR_OK, FinishOperation(&ciphertext));
    EXPECT_EQ(message.size(), ciphertext.size());

    // Move TAG_NONCE into input_params
    input_params.Reinitialize(output_params);
    output_params.Clear();

    EXPECT_EQ(KM_ERROR_OK, BeginOperation(KM_PURPOSE_DECRYPT, input_params, &output_params));
    string plaintext;
    for (size_t i = 0; i < ciphertext.size(); i += increment)
        EXPECT_EQ(KM_ERROR_OK,
                  UpdateOperation(ciphertext.substr(i, increment), &plaintext, &input_consumed));
    EXPECT_EQ(KM_ERROR_OK, FinishOperation(&plaintext));
    EXPECT_EQ(ciphertext.size(), plaintext.size());
    EXPECT_EQ(message, plaintext);
}

TEST_F(EncryptionOperationsTest, AesCbcPkcs7Padding) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .AesEncryptionKey(128)
                                           .Authorization(TAG_BLOCK_MODE, KM_MODE_CBC)
                                           .Authorization(TAG_PADDING, KM_PAD_PKCS7)));

    // Try various message lengths; all should work.
    for (size_t i = 0; i < 32; ++i) {
        string message(i, 'a');
        string iv;
        string ciphertext = EncryptMessage(message, &iv);
        EXPECT_EQ(i + 16 - (i % 16), ciphertext.size());
        string plaintext = DecryptMessage(ciphertext, iv);
        EXPECT_EQ(message, plaintext);
    }
}

typedef KeymasterTest AddEntropyTest;
TEST_F(AddEntropyTest, AddEntropy) {
    // There's no obvious way to test that entropy is actually added, but we can test that the API
    // doesn't blow up or return an error.
    EXPECT_EQ(KM_ERROR_OK,
              device()->add_rng_entropy(device(), reinterpret_cast<const uint8_t*>("foo"), 3));
}

typedef KeymasterTest RescopingTest;
TEST_F(RescopingTest, KeyWithRescopingNotUsable) {
    ASSERT_EQ(KM_ERROR_OK,
              GenerateKey(AuthorizationSetBuilder().AesEncryptionKey(128).EcbMode().Authorization(
                  TAG_RESCOPING_ADD, KM_TAG_PURPOSE)));
    // TODO(swillden): Add a better error code for this.
    EXPECT_EQ(KM_ERROR_RESCOPABLE_KEY_NOT_USABLE, BeginOperation(KM_PURPOSE_ENCRYPT));
}

TEST_F(RescopingTest, RescopeSymmetric) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .AesEncryptionKey(128)
                                           .EcbMode()
                                           .Authorization(TAG_RESCOPING_ADD, KM_TAG_PURPOSE)
                                           .Authorization(TAG_RESCOPING_DEL, KM_TAG_PURPOSE)));
    EXPECT_FALSE(contains(sw_enforced(), TAG_PURPOSE, KM_PURPOSE_SIGN));
    EXPECT_TRUE(contains(sw_enforced(), TAG_PURPOSE, KM_PURPOSE_ENCRYPT));

    keymaster_key_blob_t rescoped_blob;
    keymaster_key_characteristics_t* rescoped_characteristics;
    AuthorizationSet new_params =
        AuthorizationSetBuilder().AesKey(128).Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN).build();

    ASSERT_EQ(KM_ERROR_OK, Rescope(new_params, &rescoped_blob, &rescoped_characteristics));
    ASSERT_TRUE(rescoped_characteristics != NULL);

    EXPECT_EQ(0U, rescoped_characteristics->hw_enforced.length);
    AuthorizationSet auths(rescoped_characteristics->sw_enforced);
    keymaster_free_characteristics(rescoped_characteristics);
    free(rescoped_characteristics);
    free(const_cast<uint8_t*>(rescoped_blob.key_material));

    EXPECT_TRUE(contains(auths, TAG_ALGORITHM, KM_ALGORITHM_AES));
    EXPECT_TRUE(contains(auths, TAG_PURPOSE, KM_PURPOSE_SIGN));
    EXPECT_FALSE(contains(auths, TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
}

TEST_F(RescopingTest, RescopeRsa) {
    ASSERT_EQ(KM_ERROR_OK, GenerateKey(AuthorizationSetBuilder()
                                           .RsaEncryptionKey(256, 3, KM_PAD_RSA_OAEP)
                                           .Authorization(TAG_RESCOPING_ADD, KM_TAG_PURPOSE)
                                           .Authorization(TAG_RESCOPING_DEL, KM_TAG_PURPOSE)));
    EXPECT_TRUE(contains(sw_enforced(), TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
    EXPECT_TRUE(contains(sw_enforced(), TAG_PURPOSE, KM_PURPOSE_DECRYPT));
    EXPECT_FALSE(contains(sw_enforced(), TAG_PURPOSE, KM_PURPOSE_SIGN));
    EXPECT_FALSE(contains(sw_enforced(), TAG_PURPOSE, KM_PURPOSE_VERIFY));

    keymaster_key_blob_t rescoped_blob;
    keymaster_key_characteristics_t* rescoped_characteristics;
    AuthorizationSet new_params = AuthorizationSetBuilder()
                                      .RsaSigningKey(256, 3, KM_DIGEST_SHA_2_256, KM_PAD_RSA_PSS)
                                      .build();

    ASSERT_EQ(KM_ERROR_OK, Rescope(new_params, &rescoped_blob, &rescoped_characteristics));
    ASSERT_TRUE(rescoped_characteristics != NULL);

    EXPECT_EQ(0U, rescoped_characteristics->hw_enforced.length);
    AuthorizationSet auths(rescoped_characteristics->sw_enforced);
    keymaster_free_characteristics(rescoped_characteristics);
    free(rescoped_characteristics);
    free(const_cast<uint8_t*>(rescoped_blob.key_material));

    EXPECT_FALSE(contains(auths, TAG_PURPOSE, KM_PURPOSE_ENCRYPT));
    EXPECT_FALSE(contains(auths, TAG_PURPOSE, KM_PURPOSE_DECRYPT));
    EXPECT_TRUE(contains(auths, TAG_PURPOSE, KM_PURPOSE_SIGN));
    EXPECT_TRUE(contains(auths, TAG_PURPOSE, KM_PURPOSE_VERIFY));
}

// TODO(swillden): When adding rescoping enforcement, include tests that verify that tags
// corresponding to intrinsic attributes of keys, like RSA public exponent, or symmetric key size,
// may not be changed.

}  // namespace test
}  // namespace keymaster
