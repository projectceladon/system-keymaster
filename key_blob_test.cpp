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

#include <gtest/gtest.h>

#include <openssl/engine.h>

#define KEYMASTER_NAME_TAGS
#include "authorization_set.h"
#include "google_keymaster_utils.h"
#include "keymaster_tags.h"
#include "key_blob.h"

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int result = RUN_ALL_TESTS();
    // Clean up stuff OpenSSL leaves around, so Valgrind doesn't complain.
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return result;
}

namespace keymaster {

bool operator==(const AuthorizationSet& a, const AuthorizationSet& b) {
    if (a.size() != b.size())
        return false;

    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].tag != b[i].tag)
            return false;
        // TODO(check value)
    }

    return true;
}

namespace test {

class KeyBlobTest : public testing::Test {
  protected:
    KeyBlobTest()
        : key_data_({21, 22, 23, 24, 25}),
          master_key_data_({0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
          nonce_({12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}) {
        key_.key_material = const_cast<uint8_t*>(key_data_);
        key_.key_material_size = array_size(key_data_);
        master_key_.key_material = const_cast<uint8_t*>(master_key_data_);
        master_key_.key_material_size = array_size(master_key_data_);

        enforced_.push_back(TAG_ALGORITHM, KM_ALGORITHM_RSA);
        enforced_.push_back(TAG_KEY_SIZE, 256);
        enforced_.push_back(TAG_BLOB_USAGE_REQUIREMENTS, KM_BLOB_STANDALONE);
        enforced_.push_back(TAG_MIN_SECONDS_BETWEEN_OPS, 10);
        enforced_.push_back(TAG_ALL_USERS);
        enforced_.push_back(TAG_NO_AUTH_REQUIRED);
        enforced_.push_back(TAG_ORIGIN, KM_ORIGIN_HARDWARE);
        enforced_.push_back(TAG_ROOT_OF_TRUST, "foo", 3);

        unenforced_.push_back(TAG_ACTIVE_DATETIME, 10);
        unenforced_.push_back(TAG_ORIGINATION_EXPIRE_DATETIME, 100);
        unenforced_.push_back(TAG_CREATION_DATETIME, 10);
        unenforced_.push_back(TAG_CHUNK_LENGTH, 10);
    }

    AuthorizationSet enforced_;
    AuthorizationSet unenforced_;

    keymaster_key_blob_t key_;
    const uint8_t key_data_[5];
    keymaster_key_blob_t master_key_;
    const uint8_t master_key_data_[16];
    uint8_t nonce_[KeyBlob::NONCE_LENGTH];
};

TEST_F(KeyBlobTest, EncryptDecrypt) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);

    // key_data shouldn't be anywhere in the blob.
    uint8_t* begin = serialized_blob.get();
    uint8_t* end = begin + size;
    EXPECT_EQ(end, std::search(begin, end, key_data_, key_data_ + array_size(key_data_)));

    // Recover the key material.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, master_key_);
    EXPECT_EQ(KM_ERROR_OK, deserialized.error());
    EXPECT_EQ(0, memcmp(deserialized.key_material(), key_data_, array_size(key_data_)));
}

TEST_F(KeyBlobTest, WrongKeyLength) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);

    // Find the nonce, then modify it.
    serialized_blob[KeyBlob::NONCE_LENGTH]++;

    // Decrypting with wrong nonce should fail.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, master_key_);
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, deserialized.error());
}

TEST_F(KeyBlobTest, WrongNonce) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);

    // Find the nonce, then modify it.
    uint8_t* begin = serialized_blob.get();
    uint8_t* end = begin + size;
    auto nonce_ptr = std::search(begin, end, nonce_, nonce_ + array_size(nonce_));
    ASSERT_NE(nonce_ptr, end);
    EXPECT_EQ(end, std::search(nonce_ptr + 1, end, nonce_, nonce_ + array_size(nonce_)));
    (*nonce_ptr)++;

    // Decrypting with wrong nonce should fail.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, master_key_);
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, deserialized.error());
    EXPECT_NE(0, memcmp(deserialized.key_material(), key_data_, array_size(key_data_)));
}

TEST_F(KeyBlobTest, WrongTag) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);

    // Find the tag, them modify it.
    uint8_t* begin = serialized_blob.get();
    uint8_t* end = begin + size;
    auto tag_ptr = std::search(begin, end, blob.tag(), blob.tag() + KeyBlob::TAG_LENGTH);
    ASSERT_NE(tag_ptr, end);
    EXPECT_EQ(end, std::search(tag_ptr + 1, end, blob.tag(), blob.tag() + KeyBlob::TAG_LENGTH));
    (*tag_ptr)++;

    // Decrypting with wrong tag should fail.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, master_key_);
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, deserialized.error());
    EXPECT_NE(0, memcmp(deserialized.key_material(), key_data_, array_size(key_data_)));
}

TEST_F(KeyBlobTest, WrongCiphertext) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);

    // Find the ciphertext, them modify it.
    uint8_t* begin = serialized_blob.get();
    uint8_t* end = begin + size;
    auto ciphertext_ptr = std::search(begin, end, blob.encrypted_key_material(),
                                      blob.encrypted_key_material() + blob.key_material_length());
    ASSERT_NE(ciphertext_ptr, end);
    EXPECT_EQ(end, std::search(ciphertext_ptr + 1, end, blob.encrypted_key_material(),
                               blob.encrypted_key_material() + blob.key_material_length()));
    (*ciphertext_ptr)++;

    // Decrypting with wrong tag should fail.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, master_key_);
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, deserialized.error());
    EXPECT_NE(0, memcmp(deserialized.key_material(), key_data_, array_size(key_data_)));
}

TEST_F(KeyBlobTest, WrongMasterKey) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);

    uint8_t wrong_master_data[] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    keymaster_key_blob_t wrong_master;
    wrong_master.key_material = wrong_master_data;
    wrong_master.key_material_size = array_size(wrong_master_data);

    // Decrypting with wrong master key should fail.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, wrong_master);
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, deserialized.error());
    EXPECT_NE(0, memcmp(deserialized.key_material(), key_data_, array_size(key_data_)));
}

TEST_F(KeyBlobTest, WrongEnforced) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);
    uint8_t* begin = serialized_blob.get();
    uint8_t* end = begin + size;

    // Find one element of enforced_ serialization and modify it.
    keymaster_key_param_t entry = enforced_[0];
    uint8_t* entry_begin = reinterpret_cast<uint8_t*>(&entry);
    uint8_t* entry_end = entry_begin + sizeof(entry);
    auto entry_ptr = std::search(begin, end, entry_begin, entry_end);
    ASSERT_NE(end, entry_ptr);
    EXPECT_EQ(end, std::search(entry_ptr + 1, end, entry_begin, entry_end));
    reinterpret_cast<keymaster_key_param_t*>(entry_ptr)->integer++;

    // Decrypting with wrong unenforced data should fail.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, master_key_);
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, deserialized.error());
    EXPECT_NE(0, memcmp(deserialized.key_material(), key_data_, array_size(key_data_)));
}

TEST_F(KeyBlobTest, WrongUnenforced) {
    KeyBlob blob(enforced_, unenforced_, key_, master_key_, nonce_);

    size_t size = blob.SerializedSize();
    UniquePtr<uint8_t[]> serialized_blob(new uint8_t[size]);
    blob.Serialize(serialized_blob.get(), serialized_blob.get() + size);
    uint8_t* begin = serialized_blob.get();
    uint8_t* end = begin + size;

    // Find one element of unenforced_ serialization and modify it.
    keymaster_key_param_t entry = unenforced_[0];
    uint8_t* entry_begin = reinterpret_cast<uint8_t*>(&entry);
    uint8_t* entry_end = entry_begin + sizeof(entry);
    auto entry_ptr = std::search(begin, end, entry_begin, entry_end);
    ASSERT_NE(end, entry_ptr);
    EXPECT_EQ(end, std::search(entry_ptr + 1, end, entry_begin, entry_end));
    reinterpret_cast<keymaster_key_param_t*>(entry_ptr)->integer++;

    // Decrypting with wrong unenforced data should fail.
    keymaster_key_blob_t encrypted_blob = {serialized_blob.get(), size};
    KeyBlob deserialized(encrypted_blob, master_key_);
    EXPECT_EQ(KM_ERROR_INVALID_KEY_BLOB, deserialized.error());
    EXPECT_NE(0, memcmp(deserialized.key_material(), key_data_, array_size(key_data_)));
}

}  // namespace test
}  // namespace keymaster
