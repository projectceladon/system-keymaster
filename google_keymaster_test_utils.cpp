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

#include "google_keymaster_test_utils.h"

#include <algorithm>

#include <openssl/rand.h>

#include <keymaster/google_keymaster_messages.h>
#include <keymaster/google_keymaster_utils.h>

using std::is_permutation;
using std::ostream;
using std::string;
using std::vector;

std::ostream& operator<<(std::ostream& os, const keymaster_key_param_t& param) {
    os << "Tag: " << keymaster_tag_mask_type(param.tag);
    switch (keymaster_tag_get_type(param.tag)) {
    case KM_INVALID:
        os << " Invalid";
        break;
    case KM_INT_REP:
        os << " (Rep)";
    /* Falls through */
    case KM_INT:
        os << " Int: " << param.integer;
        break;
    case KM_ENUM_REP:
        os << " (Rep)";
    /* Falls through */
    case KM_ENUM:
        os << " Enum: " << param.enumerated;
        break;
    case KM_LONG_REP:
        os << " (Rep)";
    /* Falls through */
    case KM_LONG:
        os << " Long: " << param.long_integer;
        break;
    case KM_DATE:
        os << " Date: " << param.date_time;
        break;
    case KM_BOOL:
        os << " Bool: " << param.boolean;
        break;
    case KM_BIGNUM:
        os << " Bignum: ";
        break;
    case KM_BYTES:
        os << " Bytes: ";
        break;
    }
    return os;
}

bool operator==(const keymaster_key_param_t& a, const keymaster_key_param_t& b) {
    if (a.tag != b.tag) {
        return false;
    }

    switch (keymaster_tag_get_type(a.tag)) {
    case KM_INVALID:
        return true;
    case KM_INT_REP:
    case KM_INT:
        return a.integer == b.integer;
    case KM_ENUM_REP:
    case KM_ENUM:
        return a.enumerated == b.enumerated;
    case KM_LONG:
    case KM_LONG_REP:
        return a.long_integer == b.long_integer;
    case KM_DATE:
        return a.date_time == b.date_time;
    case KM_BOOL:
        return a.boolean == b.boolean;
    case KM_BIGNUM:
    case KM_BYTES:
        if ((a.blob.data == NULL || b.blob.data == NULL) && a.blob.data != b.blob.data)
            return false;
        return a.blob.data_length == b.blob.data_length &&
               (memcmp(a.blob.data, b.blob.data, a.blob.data_length) == 0);
    }

    return false;
}

static char hex_value[256] = {
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,
    0, 1,  2,  3,  4,  5,  6,  7, 8, 9, 0, 0, 0, 0, 0, 0,  // '0'..'9'
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 'A'..'F'
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15, 0,
    0, 0,  0,  0,  0,  0,  0,  0,  // 'a'..'f'
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,
    0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0};

string hex2str(string a) {
    string b;
    size_t num = a.size() / 2;
    b.resize(num);
    for (size_t i = 0; i < num; i++) {
        b[i] = (hex_value[a[i * 2] & 0xFF] << 4) + (hex_value[a[i * 2 + 1] & 0xFF]);
    }
    return b;
}

namespace keymaster {

bool operator==(const AuthorizationSet& a, const AuthorizationSet& b) {
    if (a.size() != b.size())
        return false;

    for (size_t i = 0; i < a.size(); ++i)
        if (!(a[i] == b[i]))
            return false;
    return true;
}

bool operator!=(const AuthorizationSet& a, const AuthorizationSet& b) {
    return !(a == b);
}

std::ostream& operator<<(std::ostream& os, const AuthorizationSet& set) {
    if (set.size() == 0)
        os << "(Empty)" << std::endl;
    for (size_t i = 0; i < set.size(); ++i) {
        os << set[i] << std::endl;
    }
    return os;
}

namespace test {

Keymaster1Test::Keymaster1Test()
    : device_(NULL), op_handle_(OP_HANDLE_SENTINEL), characteristics_(NULL) {
    blob_.key_material = NULL;
    RAND_seed("foobar", 6);
    blob_.key_material = 0;
}

Keymaster1Test::~Keymaster1Test() {
    FreeCharacteristics();
    FreeKeyBlob();
    device_->common.close(reinterpret_cast<hw_device_t*>(device_));
}

keymaster1_device_t* Keymaster1Test::device() {
    return device_;
}

keymaster_error_t Keymaster1Test::GenerateKey(const AuthorizationSetBuilder& builder) {
    AuthorizationSet params(builder.build());
    params.push_back(UserAuthParams());
    params.push_back(ClientParams());

    FreeKeyBlob();
    FreeCharacteristics();
    return device()->generate_key(device(), params.data(), params.size(), &blob_,
                                  &characteristics_);
}

keymaster_error_t Keymaster1Test::ImportKey(const AuthorizationSetBuilder& builder,
                                            keymaster_key_format_t format,
                                            const string& key_material) {
    AuthorizationSet params(builder.build());
    params.push_back(UserAuthParams());
    params.push_back(ClientParams());

    FreeKeyBlob();
    FreeCharacteristics();
    return device()->import_key(device(), params.data(), params.size(), format,
                                reinterpret_cast<const uint8_t*>(key_material.c_str()),
                                key_material.length(), &blob_, &characteristics_);
}

AuthorizationSet Keymaster1Test::UserAuthParams() {
    AuthorizationSet set;
    set.push_back(TAG_USER_ID, 7);
    set.push_back(TAG_USER_AUTH_TYPE, HW_AUTH_PASSWORD);
    set.push_back(TAG_AUTH_TIMEOUT, 300);
    return set;
}

AuthorizationSet Keymaster1Test::ClientParams() {
    AuthorizationSet set;
    set.push_back(TAG_APPLICATION_ID, "app_id", 6);
    return set;
}

keymaster_error_t Keymaster1Test::BeginOperation(keymaster_purpose_t purpose) {
    keymaster_key_param_t* out_params = NULL;
    size_t out_params_count = 0;
    keymaster_error_t error =
        device()->begin(device(), purpose, &blob_, client_params_, array_length(client_params_),
                        &out_params, &out_params_count, &op_handle_);
    EXPECT_EQ(0U, out_params_count);
    EXPECT_TRUE(out_params == NULL);
    return error;
}

keymaster_error_t Keymaster1Test::BeginOperation(keymaster_purpose_t purpose,
                                                 const AuthorizationSet& input_set,
                                                 AuthorizationSet* output_set,
                                                 bool use_client_params) {
    AuthorizationSet additional_params;
    if (use_client_params)
        additional_params.push_back(AuthorizationSet(client_params_, array_length(client_params_)));
    additional_params.push_back(input_set);

    keymaster_key_param_t* out_params;
    size_t out_params_count;
    keymaster_error_t error =
        device()->begin(device(), purpose, &blob_, additional_params.data(),
                        additional_params.size(), &out_params, &out_params_count, &op_handle_);
    if (error == KM_ERROR_OK) {
        if (output_set) {
            output_set->Reinitialize(out_params, out_params_count);
        } else {
            EXPECT_EQ(0U, out_params_count);
            EXPECT_TRUE(out_params == NULL);
        }
        keymaster_free_param_values(out_params, out_params_count);
        free(out_params);
    }
    return error;
}

keymaster_error_t Keymaster1Test::UpdateOperation(const string& message, string* output,
                                                  size_t* input_consumed) {
    uint8_t* out_tmp = NULL;
    size_t out_length;
    EXPECT_NE(op_handle_, OP_HANDLE_SENTINEL);
    keymaster_error_t error =
        device()->update(device(), op_handle_, NULL /* params */, 0 /* params_count */,
                         reinterpret_cast<const uint8_t*>(message.c_str()), message.length(),
                         input_consumed, &out_tmp, &out_length);
    if (error == KM_ERROR_OK && out_tmp)
        output->append(reinterpret_cast<char*>(out_tmp), out_length);
    free(out_tmp);
    return error;
}

keymaster_error_t Keymaster1Test::UpdateOperation(const AuthorizationSet& additional_params,
                                                  const string& message, string* output,
                                                  size_t* input_consumed) {
    uint8_t* out_tmp = NULL;
    size_t out_length;
    EXPECT_NE(op_handle_, OP_HANDLE_SENTINEL);
    keymaster_error_t error =
        device()->update(device(), op_handle_, additional_params.data(), additional_params.size(),
                         reinterpret_cast<const uint8_t*>(message.c_str()), message.length(),
                         input_consumed, &out_tmp, &out_length);
    if (error == KM_ERROR_OK && out_tmp)
        output->append(reinterpret_cast<char*>(out_tmp), out_length);
    free(out_tmp);
    return error;
}

keymaster_error_t Keymaster1Test::FinishOperation(string* output) {
    return FinishOperation("", output);
}

keymaster_error_t Keymaster1Test::FinishOperation(const string& signature, string* output) {
    AuthorizationSet additional_params;
    return FinishOperation(additional_params, signature, output);
}

keymaster_error_t Keymaster1Test::FinishOperation(const AuthorizationSet& additional_params,
                                                  const string& signature, string* output) {
    uint8_t* out_tmp = NULL;
    size_t out_length;
    keymaster_error_t error =
        device()->finish(device(), op_handle_, additional_params.data(), additional_params.size(),
                         reinterpret_cast<const uint8_t*>(signature.c_str()), signature.length(),
                         &out_tmp, &out_length);
    if (out_tmp)
        output->append(reinterpret_cast<char*>(out_tmp), out_length);
    free(out_tmp);
    return error;
}

keymaster_error_t Keymaster1Test::AbortOperation() {
    return device()->abort(device(), op_handle_);
}

string Keymaster1Test::ProcessMessage(keymaster_purpose_t purpose, const string& message,
                                      bool use_client_params) {
    AuthorizationSet input_params;
    EXPECT_EQ(KM_ERROR_OK,
              BeginOperation(purpose, input_params, NULL /* output_params */, use_client_params));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_OK, FinishOperation(&result));
    return result;
}

string Keymaster1Test::ProcessMessage(keymaster_purpose_t purpose, const string& message,
                                      const AuthorizationSet& begin_params,
                                      const AuthorizationSet& update_params,
                                      AuthorizationSet* output_params) {
    EXPECT_EQ(KM_ERROR_OK, BeginOperation(purpose, begin_params, output_params));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(update_params, message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_OK, FinishOperation(update_params, "", &result));
    return result;
}

string Keymaster1Test::ProcessMessage(keymaster_purpose_t purpose, const string& message,
                                      const string& signature, bool use_client_params) {
    AuthorizationSet input_params;
    EXPECT_EQ(KM_ERROR_OK,
              BeginOperation(purpose, input_params, NULL /* output_params */, use_client_params));

    string result;
    size_t input_consumed;
    EXPECT_EQ(KM_ERROR_OK, UpdateOperation(message, &result, &input_consumed));
    EXPECT_EQ(message.size(), input_consumed);
    EXPECT_EQ(KM_ERROR_OK, FinishOperation(signature, &result));
    return result;
}

void Keymaster1Test::SignMessage(const string& message, string* signature, bool use_client_params) {
    SCOPED_TRACE("SignMessage");
    *signature = ProcessMessage(KM_PURPOSE_SIGN, message, use_client_params);
    EXPECT_GT(signature->size(), 0U);
}

void Keymaster1Test::VerifyMessage(const string& message, const string& signature,
                                   bool use_client_params) {
    SCOPED_TRACE("VerifyMessage");
    ProcessMessage(KM_PURPOSE_VERIFY, message, signature, use_client_params);
}

string Keymaster1Test::EncryptMessage(const string& message, string* generated_nonce) {
    AuthorizationSet update_params;
    return EncryptMessage(update_params, message, generated_nonce);
}

string Keymaster1Test::EncryptMessage(const AuthorizationSet& update_params, const string& message,
                                      string* generated_nonce) {
    SCOPED_TRACE("EncryptMessage");
    AuthorizationSet begin_params, output_params;
    string ciphertext =
        ProcessMessage(KM_PURPOSE_ENCRYPT, message, begin_params, update_params, &output_params);
    if (generated_nonce) {
        keymaster_blob_t nonce_blob;
        EXPECT_TRUE(output_params.GetTagValue(TAG_NONCE, &nonce_blob));
        *generated_nonce = make_string(nonce_blob.data, nonce_blob.data_length);
    } else {
        EXPECT_EQ(-1, output_params.find(TAG_NONCE));
    }
    return ciphertext;
}

string Keymaster1Test::EncryptMessageWithParams(const string& message,
                                                const AuthorizationSet& begin_params,
                                                const AuthorizationSet& update_params,
                                                AuthorizationSet* output_params) {
    SCOPED_TRACE("EncryptMessageWithParams");
    return ProcessMessage(KM_PURPOSE_ENCRYPT, message, begin_params, update_params, output_params);
}

string Keymaster1Test::DecryptMessage(const string& ciphertext) {
    SCOPED_TRACE("DecryptMessage");
    return ProcessMessage(KM_PURPOSE_DECRYPT, ciphertext);
}

string Keymaster1Test::DecryptMessage(const string& ciphertext, const string& nonce) {
    SCOPED_TRACE("DecryptMessage");
    AuthorizationSet update_params;
    return DecryptMessage(update_params, ciphertext, nonce);
}

string Keymaster1Test::DecryptMessage(const AuthorizationSet& update_params,
                                      const string& ciphertext, const string& nonce) {
    SCOPED_TRACE("DecryptMessage");
    AuthorizationSet begin_params;
    begin_params.push_back(TAG_NONCE, nonce.data(), nonce.size());
    return ProcessMessage(KM_PURPOSE_DECRYPT, ciphertext, begin_params, update_params);
}

keymaster_error_t Keymaster1Test::GetCharacteristics() {
    FreeCharacteristics();
    return device()->get_key_characteristics(device(), &blob_, &client_id_, NULL /* app_data */,
                                             &characteristics_);
}

keymaster_error_t Keymaster1Test::ExportKey(keymaster_key_format_t format, string* export_data) {
    uint8_t* export_data_tmp;
    size_t export_data_length;

    keymaster_error_t error =
        device()->export_key(device(), format, &blob_, &client_id_, NULL /* app_data */,
                             &export_data_tmp, &export_data_length);

    if (error != KM_ERROR_OK)
        return error;

    *export_data = string(reinterpret_cast<char*>(export_data_tmp), export_data_length);
    free(export_data_tmp);
    return error;
}

keymaster_error_t
Keymaster1Test::Rescope(const AuthorizationSet& new_params, keymaster_key_blob_t* rescoped_blob,
                        keymaster_key_characteristics_t** rescoped_characteristics) {
    return device()->rescope(device(), new_params.data(), new_params.size(), &blob_, &client_id_,
                             NULL /* app data */, rescoped_blob, rescoped_characteristics);
}

void Keymaster1Test::CheckHmacTestVector(string key, string message, keymaster_digest_t digest,
                                         string expected_mac) {
    ASSERT_EQ(KM_ERROR_OK, ImportKey(AuthorizationSetBuilder()
                                         .HmacKey(key.size() * 8)
                                         .Digest(digest)
                                         .Authorization(TAG_MAC_LENGTH, expected_mac.size()),
                                     KM_KEY_FORMAT_RAW, key));
    string signature;
    SignMessage(message, &signature);
    EXPECT_EQ(expected_mac, signature) << "Test vector didn't match for digest " << (int)digest;
}

void Keymaster1Test::CheckAesCtrTestVector(const string& key, const string& nonce,
                                           const string& message,
                                           const string& expected_ciphertext) {
    ASSERT_EQ(KM_ERROR_OK, ImportKey(AuthorizationSetBuilder()
                                         .AesEncryptionKey(key.size() * 8)
                                         .Authorization(TAG_BLOCK_MODE, KM_MODE_CTR)
                                         .Authorization(TAG_CALLER_NONCE),
                                     KM_KEY_FORMAT_RAW, key));

    AuthorizationSet begin_params, update_params, output_params;
    begin_params.push_back(TAG_NONCE, nonce.data(), nonce.size());
    string ciphertext =
        EncryptMessageWithParams(message, begin_params, update_params, &output_params);
    EXPECT_EQ(expected_ciphertext, ciphertext);
}

AuthorizationSet Keymaster1Test::hw_enforced() {
    EXPECT_TRUE(characteristics_ != NULL);
    return AuthorizationSet(characteristics_->hw_enforced);
}

AuthorizationSet Keymaster1Test::sw_enforced() {
    EXPECT_TRUE(characteristics_ != NULL);
    return AuthorizationSet(characteristics_->sw_enforced);
}

void Keymaster1Test::FreeCharacteristics() {
    keymaster_free_characteristics(characteristics_);
    free(characteristics_);
    characteristics_ = NULL;
}

void Keymaster1Test::FreeKeyBlob() {
    free(const_cast<uint8_t*>(blob_.key_material));
    blob_.key_material = NULL;
}

void Keymaster1Test::corrupt_key_blob() {
    assert(blob_.key_material);
    uint8_t* tmp = const_cast<uint8_t*>(blob_.key_material);
    ++tmp[blob_.key_material_size / 2];
}

}  // namespace test
}  // namespace keymaster
