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

#ifndef SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_TEST_UTILS_H_
#define SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_TEST_UTILS_H_

/*
 * Utilities used to help with testing.  Not used in production code.
 */

#include <stdarg.h>

#include <algorithm>
#include <ostream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <hardware/keymaster1.h>
#include <hardware/keymaster_defs.h>
#include <keymaster/authorization_set.h>
#include <keymaster/logger.h>

std::ostream& operator<<(std::ostream& os, const keymaster_key_param_t& param);
bool operator==(const keymaster_key_param_t& a, const keymaster_key_param_t& b);
std::string hex2str(std::string);

namespace keymaster {

bool operator==(const AuthorizationSet& a, const AuthorizationSet& b);
bool operator!=(const AuthorizationSet& a, const AuthorizationSet& b);

std::ostream& operator<<(std::ostream& os, const AuthorizationSet& set);

namespace test {

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

template <keymaster_tag_t Tag>
bool contains(const AuthorizationSet& set, TypedTag<KM_BIGNUM, Tag> tag, const std::string& val) {
    int pos = set.find(tag);
    return pos != -1 &&
           std::string(reinterpret_cast<const char*>(set[pos].blob.data),
                       set[pos].blob.data_length) == val;
}

inline bool contains(const AuthorizationSet& set, keymaster_tag_t tag) {
    return set.find(tag) != -1;
}

class StdoutLogger : public Logger {
  public:
    StdoutLogger() { set_instance(this); }

    int log_msg(LogLevel level, const char* fmt, va_list args) const {
        int output_len = 0;
        switch (level) {
        case DEBUG_LVL:
            output_len = printf("DEBUG: ");
            break;
        case INFO_LVL:
            output_len = printf("INFO: ");
            break;
        case WARNING_LVL:
            output_len = printf("WARNING: ");
            break;
        case ERROR_LVL:
            output_len = printf("ERROR: ");
            break;
        case SEVERE_LVL:
            output_len = printf("SEVERE: ");
            break;
        }

        output_len += vprintf(fmt, args);
        output_len += printf("\n");
        return output_len;
    }
};

inline std::string make_string(const uint8_t* data, size_t length) {
    return std::string(reinterpret_cast<const char*>(data), length);
}

template <size_t N> std::string make_string(const uint8_t(&a)[N]) {
    return make_string(a, N);
}

const uint64_t OP_HANDLE_SENTINEL = 0xFFFFFFFFFFFFFFFF;
class Keymaster1Test : public testing::Test {
  protected:
    Keymaster1Test();
    ~Keymaster1Test();

    void init(keymaster1_device_t* device) { device_ = device; }

    keymaster1_device_t* device();

    keymaster_error_t GenerateKey(const AuthorizationSetBuilder& builder);

    keymaster_error_t ImportKey(const AuthorizationSetBuilder& builder,
                                keymaster_key_format_t format, const std::string& key_material);

    keymaster_error_t ExportKey(keymaster_key_format_t format, std::string* export_data);

    keymaster_error_t GetCharacteristics();

    keymaster_error_t BeginOperation(keymaster_purpose_t purpose);
    keymaster_error_t BeginOperation(keymaster_purpose_t purpose, const AuthorizationSet& input_set,
                                     AuthorizationSet* output_set = NULL);

    keymaster_error_t UpdateOperation(const std::string& message, std::string* output,
                                      size_t* input_consumed);
    keymaster_error_t UpdateOperation(const AuthorizationSet& additional_params,
                                      const std::string& message, std::string* output,
                                      size_t* input_consumed);

    keymaster_error_t FinishOperation(std::string* output);
    keymaster_error_t FinishOperation(const std::string& signature, std::string* output);
    keymaster_error_t FinishOperation(const AuthorizationSet& additional_params,
                                      const std::string& signature, std::string* output);

    keymaster_error_t AbortOperation();

    keymaster_error_t GetVersion(uint8_t* major, uint8_t* minor, uint8_t* subminor);

    std::string ProcessMessage(keymaster_purpose_t purpose, const std::string& message);
    std::string ProcessMessage(keymaster_purpose_t purpose, const std::string& message,
                               const AuthorizationSet& begin_params,
                               const AuthorizationSet& update_params,
                               AuthorizationSet* output_params = NULL);
    std::string ProcessMessage(keymaster_purpose_t purpose, const std::string& message,
                               const std::string& signature, const AuthorizationSet& begin_params,
                               const AuthorizationSet& update_params,
                               AuthorizationSet* output_params = NULL);
    std::string ProcessMessage(keymaster_purpose_t purpose, const std::string& message,
                               const std::string& signature);

    void SignMessage(const std::string& message, std::string* signature, keymaster_digest_t digest);
    void SignMessage(const std::string& message, std::string* signature, keymaster_digest_t digest,
                     keymaster_padding_t padding);
    void MacMessage(const std::string& message, std::string* signature, keymaster_digest_t digest,
                    size_t mac_length);

    void VerifyMessage(const std::string& message, const std::string& signature,
                       keymaster_digest_t digest);
    void VerifyMessage(const std::string& message, const std::string& signature,
                       keymaster_digest_t digest, keymaster_padding_t padding);

    std::string EncryptMessage(const std::string& message, keymaster_padding_t padding,
                               std::string* generated_nonce = NULL);
    std::string EncryptMessage(const std::string& message, keymaster_block_mode_t block_mode,
                               keymaster_padding_t padding, std::string* generated_nonce = NULL);
    std::string EncryptMessage(const AuthorizationSet& update_params, const std::string& message,
                               keymaster_padding_t padding, std::string* generated_nonce = NULL);
    std::string EncryptMessage(const AuthorizationSet& update_params, const std::string& message,
                               keymaster_block_mode_t block_mode, keymaster_padding_t padding,
                               std::string* generated_nonce = NULL);
    std::string EncryptMessageWithParams(const std::string& message,
                                         const AuthorizationSet& begin_params,
                                         const AuthorizationSet& update_params,
                                         AuthorizationSet* output_params);

    std::string DecryptMessage(const std::string& ciphertext, keymaster_padding_t padding);
    std::string DecryptMessage(const std::string& ciphertext, keymaster_block_mode_t block_mode,
                               keymaster_padding_t padding);
    std::string DecryptMessage(const std::string& ciphertext, keymaster_padding_t padding,
                               const std::string& nonce);
    std::string DecryptMessage(const std::string& ciphertext, keymaster_block_mode_t block_mode,
                               keymaster_padding_t padding, const std::string& nonce);
    std::string DecryptMessage(const AuthorizationSet& update_params, const std::string& ciphertext,
                               keymaster_padding_t padding, const std::string& nonce);
    std::string DecryptMessage(const AuthorizationSet& update_params, const std::string& ciphertext,
                               keymaster_block_mode_t block_mode, keymaster_padding_t padding,
                               const std::string& nonce);

    void CheckHmacTestVector(std::string key, std::string message, keymaster_digest_t digest,
                             std::string expected_mac);
    void CheckAesOcbTestVector(const std::string& key, const std::string& nonce,
                               const std::string& associated_data, const std::string& message,
                               const std::string& expected_ciphertext);
    void CheckAesCtrTestVector(const std::string& key, const std::string& nonce,
                               const std::string& message, const std::string& expected_ciphertext);
    AuthorizationSet UserAuthParams();
    AuthorizationSet ClientParams();

    template <typename T>
    bool ResponseContains(const std::vector<T>& expected, const T* values, size_t len) {
        return expected.size() == len &&
               std::is_permutation(values, values + len, expected.begin());
    }

    template <typename T> bool ResponseContains(T expected, const T* values, size_t len) {
        return (len == 1 && *values == expected);
    }

    AuthorizationSet hw_enforced();
    AuthorizationSet sw_enforced();

    void FreeCharacteristics();
    void FreeKeyBlob();

    void corrupt_key_blob();

    void set_key_blob(const uint8_t* key, size_t key_length) {
        FreeKeyBlob();
        blob_.key_material = key;
        blob_.key_material_size = key_length;
    }

    AuthorizationSet client_params() {
        return AuthorizationSet(client_params_, sizeof(client_params_) / sizeof(client_params_[0]));
    }

  private:
    keymaster1_device_t* device_;
    keymaster_blob_t client_id_ = {.data = reinterpret_cast<const uint8_t*>("app_id"),
                                   .data_length = 6};
    keymaster_key_param_t client_params_[1] = {
        Authorization(TAG_APPLICATION_ID, client_id_.data, client_id_.data_length)};

    uint64_t op_handle_;

    keymaster_key_blob_t blob_;
    keymaster_key_characteristics_t* characteristics_;
};

}  // namespace test
}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_TEST_UTILS_H_
