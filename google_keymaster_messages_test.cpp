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

#include <UniquePtr.h>

#include <gtest/gtest.h>

#define KEYMASTER_NAME_TAGS
#include "keymaster_tags.h"
#include "google_keymaster_utils.h"
#include "google_softkeymaster.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}

namespace keymaster {
namespace test {

TEST(GenerateKeyRequest, RoundTrip) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    GenerateKeyRequest req;
    req.key_description.Reinitialize(params, array_length(params));

    size_t size = req.SerializedSize();
    EXPECT_EQ(182U, size);

    UniquePtr<uint8_t[]> buf(new uint8_t[size]);
    EXPECT_EQ(buf.get() + size, req.Serialize(buf.get()));

    GenerateKeyRequest deserialized1;
    uint8_t* p = buf.get();
    EXPECT_TRUE(deserialized1.DeserializeInPlace(&p, p + size));
    EXPECT_EQ(7U, deserialized1.key_description.size());

    // Check a few entries.
    keymaster_purpose_t purpose;
    EXPECT_TRUE(deserialized1.key_description.GetTagValue(TAG_PURPOSE, 0, &purpose));
    EXPECT_EQ(KM_PURPOSE_SIGN, purpose);
    keymaster_blob_t blob;
    EXPECT_TRUE(deserialized1.key_description.GetTagValue(TAG_APPLICATION_ID, &blob));
    EXPECT_EQ(6U, blob.data_length);
    EXPECT_EQ(0, memcmp(blob.data, "app_id", 6));
    uint32_t val;
    EXPECT_TRUE(deserialized1.key_description.GetTagValue(TAG_USER_ID, &val));
    EXPECT_EQ(7U, val);

    GenerateKeyRequest deserialized2;
    const uint8_t* p2 = buf.get();
    EXPECT_TRUE(deserialized2.DeserializeToCopy(&p2, p2 + size));
    EXPECT_EQ(7U, deserialized2.key_description.size());

    // Check a few entries.
    EXPECT_TRUE(deserialized2.key_description.GetTagValue(TAG_PURPOSE, 0, &purpose));
    EXPECT_EQ(KM_PURPOSE_SIGN, purpose);
    EXPECT_TRUE(deserialized2.key_description.GetTagValue(TAG_APPLICATION_ID, &blob));
    EXPECT_EQ(6U, blob.data_length);
    EXPECT_EQ(0, memcmp(blob.data, "app_id", 6));
    EXPECT_TRUE(deserialized2.key_description.GetTagValue(TAG_USER_ID, &val));
    EXPECT_EQ(7U, val);
}

uint8_t TEST_DATA[] = "a key blob";

TEST(GenerateKeyResponse, RoundTrip) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    GenerateKeyResponse rsp;
    rsp.error = KM_ERROR_OK;
    rsp.key_blob.key_material = dup_array(TEST_DATA);
    rsp.key_blob.key_material_size = array_length(TEST_DATA);
    rsp.enforced.Reinitialize(params, array_length(params));

    size_t size = rsp.SerializedSize();
    EXPECT_EQ(217U, size);

    UniquePtr<uint8_t[]> buf(new uint8_t[size]);
    EXPECT_EQ(buf.get() + size, rsp.Serialize(buf.get()));

    GenerateKeyResponse deserialized;
    uint8_t* p = buf.get();

    // DeserializeInPlace is not implemented.
    EXPECT_FALSE(deserialized.DeserializeInPlace(&p, p + size));

    const uint8_t* p2 = buf.get();
    EXPECT_TRUE(deserialized.DeserializeToCopy(&p2, p2 + size));
    EXPECT_EQ(7U, deserialized.enforced.size());

    EXPECT_EQ(0U, deserialized.unenforced.size());
    EXPECT_EQ(KM_ERROR_OK, deserialized.error);

    // Check a few entries of enforced.
    keymaster_purpose_t purpose;
    EXPECT_TRUE(deserialized.enforced.GetTagValue(TAG_PURPOSE, 0, &purpose));
    EXPECT_EQ(KM_PURPOSE_SIGN, purpose);
    keymaster_blob_t blob;
    EXPECT_TRUE(deserialized.enforced.GetTagValue(TAG_APPLICATION_ID, &blob));
    EXPECT_EQ(6U, blob.data_length);
    EXPECT_EQ(0, memcmp(blob.data, "app_id", 6));
    uint32_t val;
    EXPECT_TRUE(deserialized.enforced.GetTagValue(TAG_USER_ID, &val));
    EXPECT_EQ(7U, val);
}

TEST(GenerateKeyResponse, Error) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "app_id", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    GenerateKeyResponse rsp;
    rsp.error = KM_ERROR_UNSUPPORTED_ALGORITHM;
    rsp.key_blob.key_material = dup_array(TEST_DATA);
    rsp.key_blob.key_material_size = array_length(TEST_DATA);
    rsp.enforced.Reinitialize(params, array_length(params));

    size_t size = rsp.SerializedSize();
    EXPECT_EQ(4U, size);

    UniquePtr<uint8_t[]> buf(new uint8_t[size]);
    EXPECT_EQ(buf.get() + size, rsp.Serialize(buf.get()));

    GenerateKeyResponse deserialized;
    const uint8_t* p = buf.get();
    EXPECT_TRUE(deserialized.DeserializeToCopy(&p, p + size));
    EXPECT_EQ(KM_ERROR_UNSUPPORTED_ALGORITHM, deserialized.error);
    EXPECT_EQ(0U, deserialized.enforced.size());
    EXPECT_EQ(0U, deserialized.unenforced.size());
    EXPECT_EQ(0U, deserialized.key_blob.key_material_size);
}

}  // namespace test
}  // namespace keymaster
