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
#include <algorithm>

#include <UniquePtr.h>
#include <gtest/gtest.h>
#include <openssl/engine.h>

#include <hardware/keymaster.h>

#include "google_keymaster_messages.h"
#include "google_keymaster_test_utils.h"
#include "google_keymaster_utils.h"
#include "key_blob.h"
#include "keymaster_tags.h"
#include "trusty_keymaster.h"
#include "trusty_keymaster_device.h"
#include "trusty_keymaster_lib.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    // Clean up stuff OpenSSL leaves around, so Valgrind doesn't complain.
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return result;
}

te_error_t trusty_init(void** /* opaque_session */) {
    return OTE_SUCCESS;
}

void trusty_deinit(void* /* opaque_session */) {
}

te_error_t trusty_call(void* /* session */, uint32_t cmd, void* in_buf, uint32_t in_size,
                       void* out_buf, uint32_t* out_size) {
    auto logger = new keymaster::test::StdoutLogger;
    keymaster::TrustyKeymaster impl(16, logger);

    switch (cmd) {
    case keymaster::GENERATE_KEY: {
        keymaster::GenerateKeyRequest req(static_cast<uint8_t*>(in_buf), in_size);
        keymaster::GenerateKeyResponse rsp;
        impl.GenerateKey(req, &rsp);

        *out_size = rsp.SerializedSize();
        uint8_t* p = static_cast<uint8_t*>(out_buf);
        rsp.Serialize(p, p + *out_size);
        return OTE_SUCCESS;
    } break;
    }
    return OTE_ERROR_ITEM_NOT_FOUND;
}

namespace keymaster {
namespace test {

class TrustyKeymasterTest : public testing::Test {
  protected:
    TrustyKeymasterTest() : device(NULL) {}

    keymaster_rsa_keygen_params_t build_rsa_params() {
        keymaster_rsa_keygen_params_t rsa_params;
        rsa_params.public_exponent = 3;
        rsa_params.modulus_size = 256;
        return rsa_params;
    }

    keymaster_dsa_keygen_params_t build_dsa_params() {
        keymaster_dsa_keygen_params_t dsa_params;
        dsa_params.key_size = 256;
        // These params are invalid for other keymaster impls.
        dsa_params.generator_len = 0;
        dsa_params.prime_p_len = 0;
        dsa_params.prime_q_len = 0;
        dsa_params.generator = NULL;
        dsa_params.prime_p = NULL;
        dsa_params.prime_q = NULL;
        return dsa_params;
    }

    TrustyKeymasterDevice device;
};

class Malloc_Delete {
  public:
    Malloc_Delete(void* p) : p_(p) {}
    ~Malloc_Delete() { free(p_); }

  private:
    void* p_;
};

typedef TrustyKeymasterTest KeyGenTest;
TEST_F(KeyGenTest, RsaSuccess) {
    keymaster_rsa_keygen_params_t params = build_rsa_params();
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_RSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    // Check the auths in the key blob.
    KeyBlob blob(ptr, size);
    EXPECT_EQ(KM_ERROR_OK, blob.error());
    EXPECT_TRUE(contains(blob.enforced(), TAG_ALGORITHM, KM_ALGORITHM_RSA));
    EXPECT_TRUE(contains(blob.enforced(), TAG_KEY_SIZE, 256));
}

TEST_F(KeyGenTest, DsaSuccess) {
    keymaster_dsa_keygen_params_t params(build_dsa_params());
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_DSA, &params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    // Check the auths in the key blob.
    KeyBlob blob(ptr, size);
    EXPECT_EQ(KM_ERROR_OK, blob.error());
    EXPECT_TRUE(contains(blob.enforced(), TAG_ALGORITHM, KM_ALGORITHM_DSA));
    EXPECT_TRUE(contains(blob.enforced(), TAG_KEY_SIZE, 256));
}

TEST_F(KeyGenTest, EcdsaSuccess) {
    keymaster_ec_keygen_params_t ec_params = {192};
    uint8_t* ptr = NULL;
    size_t size;
    ASSERT_EQ(0, device.generate_keypair(TYPE_EC, &ec_params, &ptr, &size));
    EXPECT_GT(size, 0U);
    Malloc_Delete key_deleter(ptr);

    // Check the auths in the key blob.
    KeyBlob blob(ptr, size);
    EXPECT_EQ(KM_ERROR_OK, blob.error());
    EXPECT_TRUE(contains(blob.enforced(), TAG_ALGORITHM, KM_ALGORITHM_ECDSA));
    EXPECT_TRUE(contains(blob.enforced(), TAG_KEY_SIZE, 192));
}

}  // namespace test
}  // namespace keymaster
