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

#ifndef SYSTEM_KEYMASTER_ANDROID_KEYMASTER_H_
#define SYSTEM_KEYMASTER_ANDROID_KEYMASTER_H_

#include <keymaster/android_keymaster_messages.h>
#include <keymaster/authorization_set.h>

namespace keymaster {

class Key;
class KeymasterContext;
class OperationTable;

/**
 * This is the reference implementation of Keymaster.  In addition to acting as a reference for
 * other Keymaster implementers to check their assumptions against, it is used by Keystore as the
 * default implementation when no secure implementation is available, and may be installed and
 * executed in secure hardware as a secure implementation.
 *
 * Note that this class doesn't actually implement the Keymaster HAL interface, instead it
 * implements an alternative API which is similar to and based upon the HAL, but uses C++ "message"
 * classes which support serialization.
 *
 * For non-secure, pure software implementation there is a HAL translation layer that converts the
 * HAL's parameters to and from the message representations, which are then passed in to this
 * API.
 *
 * For secure implementation there is another HAL translation layer that serializes the messages to
 * the TEE. In the TEE implementation there's another component which deserializes the messages,
 * extracts the relevant parameters and calls this API.
 */
class AndroidKeymaster {
  public:
    AndroidKeymaster(KeymasterContext* context, size_t operation_table_size);
    virtual ~AndroidKeymaster();

    void SupportedAlgorithms(SupportedResponse<keymaster_algorithm_t>* response) const;
    void SupportedBlockModes(keymaster_algorithm_t algorithm, keymaster_purpose_t purpose,
                             SupportedResponse<keymaster_block_mode_t>* response) const;
    void SupportedPaddingModes(keymaster_algorithm_t algorithm, keymaster_purpose_t purpose,
                               SupportedResponse<keymaster_padding_t>* response) const;
    void SupportedDigests(keymaster_algorithm_t algorithm, keymaster_purpose_t purpose,
                          SupportedResponse<keymaster_digest_t>* response) const;
    void SupportedImportFormats(keymaster_algorithm_t algorithm,
                                SupportedResponse<keymaster_key_format_t>* response) const;
    void SupportedExportFormats(keymaster_algorithm_t algorithm,
                                SupportedResponse<keymaster_key_format_t>* response) const;

    keymaster_error_t AddRngEntropy(const AddEntropyRequest& request);
    void GenerateKey(const GenerateKeyRequest& request, GenerateKeyResponse* response);
    void GetKeyCharacteristics(const GetKeyCharacteristicsRequest& request,
                               GetKeyCharacteristicsResponse* response);
    void ImportKey(const ImportKeyRequest& request, ImportKeyResponse* response);
    void ExportKey(const ExportKeyRequest& request, ExportKeyResponse* response);
    keymaster_error_t DeleteKey(const DeleteKeyRequest& request);
    keymaster_error_t DeleteAllKeys();
    void BeginOperation(const BeginOperationRequest& request, BeginOperationResponse* response);
    void UpdateOperation(const UpdateOperationRequest& request, UpdateOperationResponse* response);
    void FinishOperation(const FinishOperationRequest& request, FinishOperationResponse* response);
    keymaster_error_t AbortOperation(const keymaster_operation_handle_t op_handle);
    void GetVersion(const GetVersionRequest& request, GetVersionResponse* response);

  private:
    keymaster_error_t LoadKey(const keymaster_key_blob_t& key_blob,
                              const AuthorizationSet& additional_params,
                              AuthorizationSet* hw_enforced, AuthorizationSet* sw_enforced,
                              keymaster_algorithm_t* algorithm, UniquePtr<Key>* key);

    UniquePtr<KeymasterContext> context_;
    UniquePtr<OperationTable> operation_table_;
};

}  // namespace keymaster

#endif  //  SYSTEM_KEYMASTER_ANDROID_KEYMASTER_H_
