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

#include "authorization_set.h"
#include "google_keymaster_utils.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}

namespace keymaster {
namespace test {

TEST(Construction, ListProvided) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));
    EXPECT_EQ(8U, set.size());
}

TEST(Lookup, NonRepeated) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));
    EXPECT_EQ(8U, set.size());

    int pos = set.find(TAG_ALGORITHM);
    ASSERT_NE(-1, pos);
    EXPECT_EQ(KM_TAG_ALGORITHM, set[pos].tag);
    EXPECT_EQ(KM_ALGORITHM_RSA, set[pos].enumerated);

    pos = set.find(TAG_MAC_LENGTH);
    EXPECT_EQ(-1, pos);

    uint32_t int_val = 0;
    EXPECT_TRUE(set.GetTagValue(TAG_USER_ID, &int_val));
    EXPECT_EQ(7U, int_val);

    keymaster_blob_t blob_val;
    EXPECT_TRUE(set.GetTagValue(TAG_APPLICATION_ID, &blob_val));
    EXPECT_EQ(6U, blob_val.data_length);
    EXPECT_EQ(0, memcmp(blob_val.data, "my_app", 6));
}

TEST(Lookup, Repeated) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));
    EXPECT_EQ(8U, set.size());

    int pos = set.find(TAG_PURPOSE);
    ASSERT_FALSE(pos == -1);
    EXPECT_EQ(KM_TAG_PURPOSE, set[pos].tag);
    EXPECT_EQ(KM_PURPOSE_SIGN, set[pos].enumerated);

    pos = set.find(TAG_PURPOSE, pos);
    EXPECT_EQ(KM_TAG_PURPOSE, set[pos].tag);
    EXPECT_EQ(KM_PURPOSE_VERIFY, set[pos].enumerated);

    EXPECT_EQ(-1, set.find(TAG_PURPOSE, pos));
}

TEST(Lookup, Indexed) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));
    EXPECT_EQ(8U, set.size());

    EXPECT_EQ(KM_TAG_PURPOSE, set[0].tag);
    EXPECT_EQ(KM_PURPOSE_SIGN, set[0].enumerated);

    // Lookup beyond end doesn't work, just returns zeros, but doens't blow up either (verify by
    // running under valgrind).
    EXPECT_EQ(KM_TAG_INVALID, set[10].tag);
}

TEST(Serialization, RoundTrip) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    size_t size = set.SerializedSize();
    EXPECT_TRUE(size > 0);

    UniquePtr<uint8_t[]> buf(new uint8_t[size]);
    EXPECT_EQ(buf.get() + size, set.Serialize(buf.get()));
    AuthorizationSet deserialized(buf.get(), size);

    EXPECT_EQ(AuthorizationSet::OK_FULL, deserialized.is_valid());

    EXPECT_EQ(set.size(), deserialized.size());
    for (size_t i = 0; i < set.size(); ++i) {
        EXPECT_EQ(set[i].tag, deserialized[i].tag);
    }

    int pos = deserialized.find(TAG_APPLICATION_ID);
    ASSERT_NE(-1, pos);
    EXPECT_EQ(KM_TAG_APPLICATION_ID, deserialized[pos].tag);
    EXPECT_EQ(6U, deserialized[pos].blob.data_length);
    EXPECT_EQ(0, memcmp(deserialized[pos].blob.data, "my_app", 6));
}

TEST(Deserialization, DeserializeToCopy) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    size_t size = set.SerializedSize();
    EXPECT_TRUE(size > 0);

    UniquePtr<uint8_t[]> buf(new uint8_t[size]);
    EXPECT_EQ(buf.get() + size, set.Serialize(buf.get()));
    AuthorizationSet deserialized;
    const uint8_t* p = buf.get();
    EXPECT_TRUE(deserialized.DeserializeToCopy(&p, p + size));
    EXPECT_EQ(p, buf.get() + size);

    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, deserialized.is_valid());

    EXPECT_EQ(set.size(), deserialized.size());
    for (size_t i = 0; i < set.size(); ++i) {
        EXPECT_EQ(set[i].tag, deserialized[i].tag);
    }

    int pos = deserialized.find(TAG_APPLICATION_ID);
    ASSERT_NE(-1, pos);
    EXPECT_EQ(KM_TAG_APPLICATION_ID, deserialized[pos].tag);
    EXPECT_EQ(6U, deserialized[pos].blob.data_length);
    EXPECT_EQ(0, memcmp(deserialized[pos].blob.data, "my_app", 6));
}

TEST(Deserialization, TooShortBuffer) {
    uint8_t buf[] = {0, 0, 0};
    AuthorizationSet deserialized(buf, array_length(buf));
    EXPECT_EQ(AuthorizationSet::MALFORMED_DATA, deserialized.is_valid());

    const uint8_t* p = buf;
    EXPECT_FALSE(deserialized.DeserializeToCopy(&p, p + array_length(buf)));
    EXPECT_EQ(AuthorizationSet::MALFORMED_DATA, deserialized.is_valid());
}

TEST(Deserialization, InvalidLengthField) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_KEY_SIZE, 256),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    size_t size = set.SerializedSize();
    EXPECT_TRUE(size > 0);

    UniquePtr<uint8_t[]> buf(new uint8_t[size]);
    EXPECT_EQ(buf.get() + size, set.Serialize(buf.get()));
    *reinterpret_cast<uint32_t*>(buf.get()) = 9;

    AuthorizationSet deserialized(buf.get(), size);
    EXPECT_EQ(AuthorizationSet::MALFORMED_DATA, deserialized.is_valid());

    const uint8_t* p = buf.get();
    EXPECT_FALSE(deserialized.DeserializeToCopy(&p, p + size));
    EXPECT_EQ(AuthorizationSet::MALFORMED_DATA, deserialized.is_valid());
}

TEST(Deserialization, MalformedIndirectData) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_APPLICATION_DATA, "foo", 3),
    };
    AuthorizationSet set(params, array_length(params));
    size_t size = set.SerializedSize();

    UniquePtr<uint8_t[]> buf(new uint8_t[size]);
    EXPECT_EQ(buf.get() + size, set.Serialize(buf.get()));

    keymaster_key_param_t* ptr =
        reinterpret_cast<keymaster_key_param_t*>(buf.get() + sizeof(uint32_t));

    // Check that the offsets we expect are present.
    EXPECT_EQ(0, ptr[0].blob.data);
    EXPECT_EQ(6U, ptr[0].blob.data_length);
    EXPECT_EQ(6, reinterpret_cast<ptrdiff_t>(ptr[1].blob.data));
    EXPECT_EQ(3U, ptr[1].blob.data_length);
    EXPECT_EQ(9U, size - sizeof(uint32_t) * 2 - sizeof(*ptr) * 2);

    // Check that deserialization works.
    AuthorizationSet deserialized1(buf.get(), size);
    EXPECT_EQ(AuthorizationSet::OK_FULL, deserialized1.is_valid());

    const uint8_t* p = buf.get();
    EXPECT_TRUE(deserialized1.DeserializeToCopy(&p, p + size));
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, deserialized1.is_valid());

    //
    // Now mess them up in various ways:
    //

    // Make one point past the end.
    (*reinterpret_cast<long*>(&(ptr[1].blob.data)))++;
    AuthorizationSet deserialized2;
    p = buf.get();
    deserialized2.DeserializeInPlace(const_cast<uint8_t**>(&p), p + size);
    EXPECT_EQ(AuthorizationSet::BOUNDS_CHECKING_FAILURE, deserialized2.is_valid());

    p = buf.get();
    EXPECT_FALSE(deserialized2.DeserializeToCopy(&p, p + size));
    EXPECT_EQ(AuthorizationSet::BOUNDS_CHECKING_FAILURE, deserialized2.is_valid());

    (*reinterpret_cast<long*>(&(ptr[1].blob.data)))--;

    // Make a gap between the blobs.
    ptr[0].blob.data_length--;
    AuthorizationSet deserialized3(buf.get(), size);
    EXPECT_EQ(AuthorizationSet::MALFORMED_DATA, deserialized3.is_valid());

    p = buf.get();
    deserialized3.DeserializeToCopy(&p, p + size);
    EXPECT_EQ(AuthorizationSet::MALFORMED_DATA, deserialized3.is_valid());

    ptr[0].blob.data_length++;

    // Make them overlap.  We don't currently detect this.  We should.
    ptr[0].blob.data_length++;
    (*reinterpret_cast<long*>(&(ptr[1].blob.data)))--;
    ptr[1].blob.data_length--;
    AuthorizationSet deserialized4(buf.get(), size);
    EXPECT_EQ(AuthorizationSet::OK_FULL, deserialized4.is_valid());
}

TEST(InPlaceGrowable, SuccessfulRoundTrip) {
    keymaster_key_param_t elems_buf[20];
    uint8_t data_buf[200];

    AuthorizationSet growable(elems_buf, array_length(elems_buf), data_buf, array_length(data_buf));
    EXPECT_TRUE(growable.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_EQ(1U, growable.size());

    EXPECT_TRUE(growable.push_back(TAG_SINGLE_USE_PER_BOOT));
    EXPECT_EQ(2U, growable.size());

    EXPECT_TRUE(growable.push_back(TAG_PURPOSE, KM_PURPOSE_SIGN));
    EXPECT_EQ(3U, growable.size());

    EXPECT_TRUE(growable.push_back(TAG_APPLICATION_ID, "data", 4));
    EXPECT_EQ(4U, growable.size());

    size_t serialize_size = growable.SerializedSize();
    UniquePtr<uint8_t[]> serialized(new uint8_t[serialize_size]);
    EXPECT_EQ(serialized.get() + serialize_size, growable.Serialize(serialized.get()));
}

TEST(InplaceGrowable, InsufficientElemBuf) {
    keymaster_key_param_t elems_buf[1];
    uint8_t data_buf[200];

    AuthorizationSet growable(elems_buf, array_length(elems_buf), data_buf, array_length(data_buf));
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    // First insertion fits, but set is now full.
    EXPECT_TRUE(growable.push_back(TAG_USER_ID, 10));
    EXPECT_EQ(1U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_FULL, growable.is_valid());

    // Second does not.
    EXPECT_FALSE(growable.push_back(Authorization(TAG_RSA_PUBLIC_EXPONENT, 3)));
    EXPECT_EQ(1U, growable.size());
}

TEST(InplaceGrowable, InsufficientIndirectBuf) {
    keymaster_key_param_t elems_buf[3];
    uint8_t data_buf[10];

    AuthorizationSet growable(elems_buf, array_length(elems_buf), data_buf, array_length(data_buf));
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA)));
    EXPECT_EQ(1U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_APPLICATION_ID, "1234567890", 10)));
    EXPECT_EQ(2U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    // Adding more indirect data should fail, even a single byte, though the set isn't full.
    EXPECT_FALSE(growable.push_back(Authorization(TAG_APPLICATION_DATA, "1", 1)));
    EXPECT_EQ(2U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    // Can still add another entry without indirect data.  Now it's full.
    EXPECT_TRUE(growable.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN)));
    EXPECT_EQ(3U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_FULL, growable.is_valid());
}

TEST(Growable, SuccessfulRoundTrip) {
    keymaster_key_param_t elems_buf[20];
    uint8_t data_buf[200];

    AuthorizationSet growable;
    EXPECT_TRUE(growable.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA)));
    EXPECT_EQ(1U, growable.size());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY)));
    EXPECT_EQ(2U, growable.size());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN)));
    EXPECT_EQ(3U, growable.size());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_APPLICATION_ID, "data", 4)));
    EXPECT_EQ(4U, growable.size());

    size_t serialize_size = growable.SerializedSize();
    UniquePtr<uint8_t[]> serialized(new uint8_t[serialize_size]);
    EXPECT_EQ(serialized.get() + serialize_size, growable.Serialize(serialized.get()));
}

TEST(Growable, InsufficientElemBuf) {
    keymaster_key_param_t elems_buf[1];
    uint8_t data_buf[200];

    AuthorizationSet growable;
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    // First insertion fits.
    EXPECT_TRUE(growable.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA)));
    EXPECT_EQ(1U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    // Second does too.
    EXPECT_TRUE(growable.push_back(Authorization(TAG_RSA_PUBLIC_EXPONENT, 3)));
    EXPECT_EQ(2U, growable.size());
}

TEST(Growable, InsufficientIndirectBuf) {
    keymaster_key_param_t elems_buf[3];
    uint8_t data_buf[10];

    AuthorizationSet growable;
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA)));
    EXPECT_EQ(1U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_APPLICATION_ID, "1234567890", 10)));
    EXPECT_EQ(2U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    EXPECT_TRUE(growable.push_back(Authorization(TAG_APPLICATION_DATA, "1", 1)));
    EXPECT_EQ(3U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());

    // Can still add another entry without indirect data.  Now it's full.
    EXPECT_TRUE(growable.push_back(Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN)));
    EXPECT_EQ(4U, growable.size());
    EXPECT_EQ(AuthorizationSet::OK_GROWABLE, growable.is_valid());
}

TEST(GetValue, GetInt) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    uint32_t val;
    EXPECT_TRUE(set.GetTagValue(TAG_USER_ID, &val));
    EXPECT_EQ(7U, val);

    // Find one that isn't there
    EXPECT_FALSE(set.GetTagValue(TAG_KEY_SIZE, &val));
}

TEST(GetValue, GetIntRep) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    uint32_t val;
    EXPECT_TRUE(set.GetTagValue(TAG_USER_AUTH_ID, 0, &val));
    EXPECT_EQ(8U, val);

    // Find one that isn't there
    EXPECT_FALSE(set.GetTagValue(TAG_USER_AUTH_ID, 1, &val));
}

TEST(GetValue, GetLong) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        keymaster_param_long(TAG_RSA_PUBLIC_EXPONENT, 3),
    };
    AuthorizationSet set1(params1, array_length(params1));

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
    };
    AuthorizationSet set2(params2, array_length(params2));

    uint64_t val;
    EXPECT_TRUE(set1.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &val));
    EXPECT_EQ(3U, val);

    // Find one that isn't there
    EXPECT_FALSE(set2.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &val));
}

TEST(GetValue, GetEnum) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    keymaster_algorithm_t val;
    EXPECT_TRUE(set.GetTagValue(TAG_ALGORITHM, &val));
    EXPECT_EQ(KM_ALGORITHM_RSA, val);

    // Find one that isn't there
    keymaster_padding_t val2;
    EXPECT_FALSE(set.GetTagValue(TAG_PADDING, &val2));
}

TEST(GetValue, GetEnumRep) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    keymaster_purpose_t val;
    EXPECT_TRUE(set.GetTagValue(TAG_PURPOSE, 0, &val));
    EXPECT_EQ(KM_PURPOSE_SIGN, val);
    EXPECT_TRUE(set.GetTagValue(TAG_PURPOSE, 1, &val));
    EXPECT_EQ(KM_PURPOSE_VERIFY, val);

    // Find one that isn't there
    EXPECT_FALSE(set.GetTagValue(TAG_PURPOSE, 2, &val));
}

TEST(GetValue, GetDate) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_ACTIVE_DATETIME, 10),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    uint64_t val;
    EXPECT_TRUE(set.GetTagValue(TAG_ACTIVE_DATETIME, &val));
    EXPECT_EQ(10U, val);

    // Find one that isn't there
    EXPECT_FALSE(set.GetTagValue(TAG_USAGE_EXPIRE_DATETIME, &val));
}

TEST(GetValue, GetBlob) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_ACTIVE_DATETIME, 10),
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 7),
        Authorization(TAG_USER_AUTH_ID, 8),
        Authorization(TAG_APPLICATION_ID, "my_app", 6),
        Authorization(TAG_AUTH_TIMEOUT, 300),
    };
    AuthorizationSet set(params, array_length(params));

    keymaster_blob_t val;
    EXPECT_TRUE(set.GetTagValue(TAG_APPLICATION_ID, &val));
    EXPECT_EQ(6U, val.data_length);
    EXPECT_EQ(0, memcmp(val.data, "my_app", 6));

    // Find one that isn't there
    EXPECT_FALSE(set.GetTagValue(TAG_APPLICATION_DATA, &val));
}

}  // namespace test
}  // namespace keymaster
