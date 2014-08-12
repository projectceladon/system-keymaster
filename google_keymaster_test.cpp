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

#include <gtest/gtest.h>
#include <openssl/engine.h>

#define KEYMASTER_NAME_TAGS
#include "keymaster_tags.h"
#include "google_keymaster_utils.h"
#include "google_softkeymaster.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    // Clean up stuff OpenSSL leaves around, so Valgrind doesn't complain.
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return result;
}

namespace keymaster {
namespace test {

class KeymasterTest : public testing::Test {
  protected:
    KeymasterTest() {
    }
    ~KeymasterTest() {
    }

    GoogleSoftKeymaster device;
};

template <keymaster_tag_t Tag, typename KeymasterEnum>
bool contains(const AuthorizationSet& set, TypedEnumTag<KM_ENUM, Tag, KeymasterEnum> tag,
              KeymasterEnum val) {
    int pos = set.find(tag);
    return pos != -1 && set[pos].enumerated == val;
}

template <keymaster_tag_t Tag, typename KeymasterEnum>
bool contains(const AuthorizationSet& set, TypedEnumTag<KM_ENUM_REP, Tag, KeymasterEnum> tag,
              KeymasterEnum val) {
    int pos = -1;
    while ((pos = set.find(tag, pos)) != -1)
        if (set[pos].enumerated == val)
            return true;
    return false;
}

template <keymaster_tag_t Tag>
bool contains(const AuthorizationSet& set, TypedTag<KM_INT, Tag> tag, uint32_t val) {
    int pos = set.find(tag);
    return pos != -1 && set[pos].integer == val;
}

template <keymaster_tag_t Tag>
bool contains(const AuthorizationSet& set, TypedTag<KM_INT_REP, Tag> tag, uint32_t val) {
    int pos = -1;
    while ((pos = set.find(tag, pos)) != -1)
        if (set[pos].integer == val)
            return true;
    return false;
}

template <keymaster_tag_t Tag>
bool contains(const AuthorizationSet& set, TypedTag<KM_LONG, Tag> tag, uint64_t val) {
    int pos = set.find(tag);
    return pos != -1 && set[pos].long_integer == val;
}

template <keymaster_tag_t Tag>
bool contains(const AuthorizationSet& set, TypedTag<KM_BYTES, Tag> tag, const std::string& val) {
    int pos = set.find(tag);
    return pos != -1 &&
           std::string(reinterpret_cast<const char*>(set[pos].blob.data),
                       set[pos].blob.data_length) == val;
}

inline bool contains(const AuthorizationSet& set, keymaster_tag_t tag) {
    return set.find(tag) != -1;
}

typedef KeymasterTest CheckSupported;
TEST_F(CheckSupported, SupportedAlgorithms) {
    // Shouldn't blow up on NULL.
    device.SupportedAlgorithms(NULL);

    SupportedResponse<keymaster_algorithm_t> response;
    device.SupportedAlgorithms(&response);
    EXPECT_EQ(KM_ERROR_OK, response.error);
    EXPECT_EQ(1U, response.results_length);
    EXPECT_EQ(KM_ALGORITHM_RSA, response.results[0]);
}

TEST_F(CheckSupported, SupportedBlockModes) {
    // Shouldn't blow up on NULL.
    device.SupportedBlockModes(KM_ALGORITHM_RSA, NULL);

    SupportedResponse<keymaster_block_mode_t> response;
    device.SupportedBlockModes(KM_ALGORITHM_RSA, &response);
    EXPECT_EQ(KM_ERROR_OK, response.error);
    EXPECT_EQ(0U, response.results_length);

    device.SupportedBlockModes(KM_ALGORITHM_DSA, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedPaddingModes) {
    // Shouldn't blow up on NULL.
    device.SupportedPaddingModes(KM_ALGORITHM_RSA, NULL);

    SupportedResponse<keymaster_padding_t> response;
    device.SupportedPaddingModes(KM_ALGORITHM_RSA, &response);
    EXPECT_EQ(KM_ERROR_OK, response.error);
    EXPECT_EQ(1U, response.results_length);
    EXPECT_EQ(KM_PAD_NONE, response.results[0]);

    device.SupportedPaddingModes(KM_ALGORITHM_DSA, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedDigests) {
    // Shouldn't blow up on NULL.
    device.SupportedDigests(KM_ALGORITHM_RSA, NULL);

    SupportedResponse<keymaster_digest_t> response;
    device.SupportedDigests(KM_ALGORITHM_RSA, &response);
    EXPECT_EQ(KM_ERROR_OK, response.error);
    EXPECT_EQ(1U, response.results_length);
    EXPECT_EQ(KM_DIGEST_NONE, response.results[0]);

    device.SupportedDigests(KM_ALGORITHM_DSA, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedImportFormats) {
    // Shouldn't blow up on NULL.
    device.SupportedImportFormats(KM_ALGORITHM_RSA, NULL);

    SupportedResponse<keymaster_key_format_t> response;
    device.SupportedImportFormats(KM_ALGORITHM_RSA, &response);
    EXPECT_EQ(KM_ERROR_OK, response.error);
    EXPECT_EQ(1U, response.results_length);
    EXPECT_EQ(KM_KEY_FORMAT_PKCS8, response.results[0]);

    device.SupportedImportFormats(KM_ALGORITHM_DSA, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

TEST_F(CheckSupported, SupportedExportFormats) {
    // Shouldn't blow up on NULL.
    device.SupportedExportFormats(KM_ALGORITHM_RSA, NULL);

    SupportedResponse<keymaster_key_format_t> response;
    device.SupportedExportFormats(KM_ALGORITHM_RSA, &response);
    EXPECT_EQ(KM_ERROR_OK, response.error);
    EXPECT_EQ(1U, response.results_length);
    EXPECT_EQ(KM_KEY_FORMAT_X509, response.results[0]);

    device.SupportedExportFormats(KM_ALGORITHM_DSA, &response);
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, response.error);
}

typedef KeymasterTest NewKeyGeneration;
TEST_F(NewKeyGeneration, Rsa) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, reinterpret_cast<const uint8_t*>("app_id"), 6),
        Authorization(TAG_APPLICATION_DATA, reinterpret_cast<const uint8_t*>("app_data"), 8),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    GenerateKeyRequest req;
    req.key_description.Reinitialize(params, array_length(params));
    GenerateKeyResponse rsp;

    device.GenerateKey(req, &rsp);

    ASSERT_EQ(KM_ERROR_OK, rsp.error);
    EXPECT_EQ(0U, rsp.enforced.size());
    EXPECT_EQ(12U, rsp.enforced.SerializedSize());
    EXPECT_GT(rsp.unenforced.SerializedSize(), 12U);

    // Check specified tags are all present in unenforced characteristics
    EXPECT_TRUE(contains(rsp.unenforced, TAG_PURPOSE, KM_PURPOSE_SIGN));
    EXPECT_TRUE(contains(rsp.unenforced, TAG_PURPOSE, KM_PURPOSE_VERIFY));

    EXPECT_TRUE(contains(rsp.unenforced, TAG_ALGORITHM, KM_ALGORITHM_RSA));

    EXPECT_TRUE(contains(rsp.unenforced, TAG_USER_ID, 7));
    EXPECT_TRUE(contains(rsp.unenforced, TAG_USER_AUTH_ID, 8));
    EXPECT_TRUE(contains(rsp.unenforced, TAG_KEY_SIZE, 2048));
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
    EXPECT_TRUE(contains(rsp.unenforced, TAG_RSA_PUBLIC_EXPONENT, 65537));
    EXPECT_TRUE(contains(rsp.unenforced, TAG_ORIGIN, KM_ORIGIN_SOFTWARE));
    EXPECT_TRUE(contains(rsp.unenforced, KM_TAG_CREATION_DATETIME));
}

}  // namespace test
}  // namespace keymaster
