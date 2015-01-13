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

#include <errno.h>
#include <keymaster/authorization_set.h>
#include <keymaster/google_keymaster.h>
#include <stdio.h>
#include <time.h>

#include "keymaster_enforcement.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    return result;
}

namespace keymaster {
namespace test {

class KeymasterBaseTest : public ::testing::Test {
  protected:
    KeymasterBaseTest() {
        past_time = 0;

        time_t t = time(NULL);
        future_tm = localtime(&t);
        future_tm->tm_year += 1;
        future_time = mktime(future_tm);
        sign_param = Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN);
    }
    virtual ~KeymasterBaseTest() {}

    tm past_tm;
    tm* future_tm;
    time_t past_time;
    time_t future_time;
    static const km_id_t key_id = 0xa;
    static const uid_t uid = 0xf;
    keymaster_key_param_t sign_param;
    keymaster_blob_t def_app_id;
    size_t def_app_id_size;

    static const uint32_t valid_user_id = 25;
    static const uint32_t invalid_user_id1 = 37;
    static const uint32_t invalid_user_id2 = 50;
    static const uint32_t appId1 = 51;
    static const uint32_t appId2 = 52;

    static const uint32_t validuid1 =
        valid_user_id * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
        (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    static const uint32_t validuid2 =
        valid_user_id * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
        (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);

    static const uint32_t invaliduid1 =
        invalid_user_id1 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
        (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    static const uint32_t invaliduid2 =
        invalid_user_id1 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
        (appId2 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    static const uint32_t invaliduid3 =
        invalid_user_id2 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
        (appId1 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
    static const uint32_t invaliduid4 =
        invalid_user_id2 * KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE +
        (appId2 % KeymasterEnforcement::MULTIUSER_APP_PER_USER_RANGE);
};

class RescopeBaseTest : public KeymasterBaseTest {
    friend class KeymasterEnforcement;
};

TEST_F(KeymasterBaseTest, TEST_VALID_KEY_PERIOD_NO_TAGS) {
    keymaster_key_param_t params[] = {
        sign_param,
    };
    AuthorizationSet single_auth_set(params, 1);
    KeymasterEnforcement kmen;

    keymaster_error_t kmer = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, single_auth_set, uid);
    ASSERT_EQ(KM_ERROR_OK, kmer);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_ACTIVE_TIME) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_NO_AUTH_REQUIRED), Authorization(TAG_ACTIVE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_invalid_time =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    ASSERT_EQ(KM_ERROR_KEY_NOT_YET_VALID, kmer_invalid_time);
}

TEST_F(KeymasterBaseTest, TEST_VALID_ACTIVE_TIME) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 3);

    keymaster_error_t kmer_valid_time =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid_time);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_ORIGINATION_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
        Authorization(TAG_ORIGINATION_EXPIRE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_invalid_origination =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    ASSERT_EQ(KM_ERROR_KEY_EXPIRED, kmer_invalid_origination);
}

TEST_F(KeymasterBaseTest, TEST_VALID_ORIGINATION_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
        Authorization(TAG_ORIGINATION_EXPIRE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_valid_origination =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid_origination);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_USAGE_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_USAGE_EXPIRE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 5);

    keymaster_error_t kmer_invalid_origination =
        kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, auth_set, uid);
    ASSERT_EQ(KM_ERROR_KEY_EXPIRED, kmer_invalid_origination);
}

TEST_F(KeymasterBaseTest, TEST_VALID_USAGE_EXPIRE_TIME) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
        Authorization(TAG_USAGE_EXPIRE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_valid_usage =
        kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, auth_set, uid);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid_usage);
}

TEST_F(KeymasterBaseTest, TEST_VALID_SINGLE_USE_ACCESSES) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 3);

    keymaster_error_t kmer1 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    keymaster_error_t kmer2 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    ASSERT_EQ(KM_ERROR_OK, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_SINGLE_USE_ACCESSES) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time), Authorization(TAG_MAX_USES_PER_BOOT, 1),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer1 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    keymaster_error_t kmer2 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    ASSERT_EQ(KM_ERROR_TOO_MANY_OPERATIONS, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_TIME_BETWEEN_OPS) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_ALL_USERS), Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
        Authorization(TAG_MIN_SECONDS_BETWEEN_OPS, 10),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 5);

    keymaster_error_t kmer1 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    keymaster_error_t kmer2 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    sleep(2);
    ASSERT_EQ(KM_ERROR_TOO_MANY_OPERATIONS, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_VALID_TIME_BETWEEN_OPS) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_USAGE_EXPIRE_DATETIME, future_time),
        Authorization(TAG_ORIGINATION_EXPIRE_DATETIME, future_time),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
        Authorization(TAG_MIN_SECONDS_BETWEEN_OPS, 2),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 7);

    keymaster_error_t kmer1 = kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, auth_set, uid);
    sleep(3);
    keymaster_error_t kmer2 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);

    ASSERT_EQ(KM_ERROR_OK, kmer1);
    ASSERT_EQ(KM_ERROR_OK, kmer2);
}

TEST_F(KeymasterBaseTest, TEST_NO_RESCOPES) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 1),
    };
    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 1),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 3);
    AuthorizationSet auth_set2(params2, 3);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(auth_set1, auth_set2));
}

TEST_F(RescopeBaseTest, TEST_VALID_RESCOPE_ADD) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_MAX_USES_PER_BOOT),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_USER_ID, 1),
        Authorization(TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 1), Authorization(TAG_MAX_USES_PER_BOOT, 1),
    };

    keymaster_key_param_t params3[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 1), Authorization(TAG_USAGE_EXPIRE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 4);
    AuthorizationSet auth_set3(params3, 4);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(auth_set1, auth_set2));
    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(auth_set1, auth_set3));
}

TEST_F(RescopeBaseTest, TEST_VALID_RESCOPE_DEL) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_MAX_USES_PER_BOOT),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_USER_ID, 1),
        Authorization(TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 2);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(auth_set1, auth_set2));
}

TEST_F(RescopeBaseTest, TEST_VALID_RESCOPE_ADD_DEL) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 1),

        Authorization(TAG_RESCOPING_ADD, KM_TAG_MAX_USES_PER_BOOT),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        Authorization(TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_MAX_USES_PER_BOOT, 1), Authorization(TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params3[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_MAX_USES_PER_BOOT, 1), Authorization(TAG_USER_ID, 1),
        Authorization(TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params4[] = {
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 4);
    AuthorizationSet auth_set3(params3, 5);
    AuthorizationSet auth_set4(params4, 2);

    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(auth_set1, auth_set2));
    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(auth_set1, auth_set3));
    ASSERT_EQ(KM_ERROR_OK, kmen.AuthorizeRescope(auth_set1, auth_set4));
}

TEST_F(RescopeBaseTest, TEST_INVALID_RESCOPE_ADD) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_USER_ID, 1),
        Authorization(TAG_RESCOPING_DEL, KM_TAG_USER_ID),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_USER_ID, 1), Authorization(TAG_MAX_USES_PER_BOOT, 1),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 6);
    AuthorizationSet auth_set2(params2, 4);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(auth_set1, auth_set2));
}

TEST_F(RescopeBaseTest, TEST_INVALID_RESCOPE_DEL) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_USAGE_EXPIRE_DATETIME),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_RESCOPING_DEL, KM_TAG_PURPOSE), Authorization(TAG_USER_ID, 1),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 5);
    AuthorizationSet auth_set2(params2, 2);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(auth_set1, auth_set2));
}

TEST_F(RescopeBaseTest, TEST_INVALID_RESCOPE_ADD_DEL) {
    keymaster_key_param_t params1[] = {
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_USER_ID, 1),
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_ORIGINATION_EXPIRE_DATETIME, past_time),
        Authorization(TAG_RESCOPING_ADD, KM_TAG_ORIGINATION_EXPIRE_DATETIME),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_MAX_USES_PER_BOOT, 1),
        Authorization(TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params3[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_MAX_USES_PER_BOOT, 1),
        Authorization(TAG_USER_ID, 2), Authorization(TAG_USAGE_EXPIRE_DATETIME, 128),
    };

    keymaster_key_param_t params4[] = {
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_USER_ID, 2),
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
    };

    keymaster_key_param_t params5[] = {
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA), Authorization(TAG_USER_ID, 1),
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        Authorization(TAG_ORIGINATION_EXPIRE_DATETIME, future_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 5);
    AuthorizationSet auth_set2(params2, 3);
    AuthorizationSet auth_set3(params3, 4);
    AuthorizationSet auth_set4(params4, 3);
    AuthorizationSet auth_set5(params5, 4);

    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(auth_set1, auth_set2));
    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(auth_set1, auth_set3));
    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(auth_set1, auth_set4));
    ASSERT_EQ(KM_ERROR_INVALID_RESCOPING, kmen.AuthorizeRescope(auth_set1, auth_set5));
}

TEST_F(KeymasterBaseTest, TEST_USER_ID) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN), Authorization(TAG_USER_ID, valid_user_id),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 2);

    keymaster_error_t valid_kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, validuid1);
    keymaster_error_t valid_kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, validuid2);

    keymaster_error_t invalid_kmer1 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, invaliduid1);
    keymaster_error_t invalid_kmer2 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, invaliduid2);
    keymaster_error_t invalid_kmer3 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, invaliduid3);
    keymaster_error_t invalid_kmer4 =
        kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, invaliduid4);

    ASSERT_EQ(KM_ERROR_OK, valid_kmer1);
    ASSERT_EQ(KM_ERROR_OK, valid_kmer2);

    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer1);
    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer2);
    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer3);
    ASSERT_EQ(KM_ERROR_INVALID_USER_ID, invalid_kmer4);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_PURPOSE) {
    keymaster_purpose_t invalidPurpose1 = static_cast<keymaster_purpose_t>(-1);
    keymaster_purpose_t invalidPurpose2 = static_cast<keymaster_purpose_t>(4);

    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, invalidPurpose1), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, invalidPurpose2), Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, 3);
    AuthorizationSet auth_set2(params2, 3);

    keymaster_error_t kmer1 = kmen.AuthorizeOperation(invalidPurpose1, key_id, auth_set1, uid);
    keymaster_error_t kmer2 = kmen.AuthorizeOperation(invalidPurpose2, key_id, auth_set2, uid);
    keymaster_error_t kmer3 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set2, uid);

    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE, kmer1);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE, kmer2);
    ASSERT_EQ(KM_ERROR_UNSUPPORTED_PURPOSE, kmer3);
}

TEST_F(KeymasterBaseTest, TEST_INCOMPATIBLE_PURPOSE) {
    keymaster_key_param_t params[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time), Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
    };
    KeymasterEnforcement kmen;
    AuthorizationSet auth_set(params, 4);

    keymaster_error_t kmer_invalid1 =
        kmen.AuthorizeOperation(KM_PURPOSE_ENCRYPT, key_id, auth_set, uid);
    keymaster_error_t kmer_invalid2 =
        kmen.AuthorizeOperation(KM_PURPOSE_DECRYPT, key_id, auth_set, uid);

    keymaster_error_t kmer_valid1 = kmen.AuthorizeOperation(KM_PURPOSE_SIGN, key_id, auth_set, uid);
    keymaster_error_t kmer_valid2 =
        kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, auth_set, uid);

    ASSERT_EQ(KM_ERROR_OK, kmer_valid1);
    ASSERT_EQ(KM_ERROR_OK, kmer_valid2);
    ASSERT_EQ(KM_ERROR_INCOMPATIBLE_PURPOSE, kmer_invalid1);
    ASSERT_EQ(KM_ERROR_INCOMPATIBLE_PURPOSE, kmer_invalid2);
}

TEST_F(KeymasterBaseTest, TEST_INVALID_TAG_PAIRS) {
    const uint8_t* app_id = reinterpret_cast<const uint8_t*>("com.app");
    const size_t app_size = 7;
    keymaster_key_param_t params1[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time), Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        // Can't have "all users" and a specific user.
        Authorization(TAG_ALL_USERS), Authorization(TAG_USER_ID, valid_user_id),
    };

    keymaster_key_param_t params2[] = {
        Authorization(TAG_PURPOSE, KM_PURPOSE_VERIFY),
        Authorization(TAG_ALGORITHM, KM_ALGORITHM_RSA),
        Authorization(TAG_ACTIVE_DATETIME, past_time), Authorization(TAG_PURPOSE, KM_PURPOSE_SIGN),
        // Can't have "all applications" and a specific app ID.
        Authorization(TAG_ALL_APPLICATIONS), Authorization(TAG_APPLICATION_ID, app_id, app_size),
    };

    KeymasterEnforcement kmen;
    AuthorizationSet auth_set1(params1, array_length(params1));
    AuthorizationSet auth_set2(params2, array_length(params2));

    EXPECT_EQ(KM_ERROR_INVALID_TAG,
              kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, auth_set1, validuid1));
    EXPECT_EQ(KM_ERROR_INVALID_TAG,
              kmen.AuthorizeOperation(KM_PURPOSE_VERIFY, key_id, auth_set2, validuid1));
}

}; /* namespace test */
}; /* namespace keymaster */
