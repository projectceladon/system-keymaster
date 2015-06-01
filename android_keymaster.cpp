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

#include <keymaster/android_keymaster.h>

#include <assert.h>
#include <string.h>

#include <cstddef>

#include <openssl/rand.h>
#include <openssl/x509.h>

#include <UniquePtr.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/keymaster_context.h>

#include "ae.h"
#include "key.h"
#include "openssl_err.h"
#include "operation.h"
#include "operation_table.h"

namespace keymaster {

const uint8_t MAJOR_VER = 1;
const uint8_t MINOR_VER = 0;
const uint8_t SUBMINOR_VER = 0;

AndroidKeymaster::AndroidKeymaster(KeymasterContext* context, size_t operation_table_size)
    : context_(context), operation_table_(new OperationTable(operation_table_size)) {
}

AndroidKeymaster::~AndroidKeymaster() {
}

struct AE_CTX_Delete {
    void operator()(ae_ctx* ctx) const { ae_free(ctx); }
};
typedef UniquePtr<ae_ctx, AE_CTX_Delete> Unique_ae_ctx;

// TODO(swillden): Unify support analysis.  Right now, we have per-keytype methods that determine if
// specific modes, padding, etc. are supported for that key type, and AndroidKeymaster also has
// methods that return the same information.  They'll get out of sync.  Best to put the knowledge in
// the keytypes and provide some mechanism for AndroidKeymaster to query the keytypes for the
// information.

template <typename T>
bool check_supported(keymaster_algorithm_t algorithm, SupportedResponse<T>* response) {
    if (KeyFactoryRegistry::Get(algorithm) == NULL) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return false;
    }
    return true;
}

void AndroidKeymaster::GetVersion(const GetVersionRequest&, GetVersionResponse* rsp) {
    if (rsp == NULL)
        return;

    rsp->major_ver = MAJOR_VER;
    rsp->minor_ver = MINOR_VER;
    rsp->subminor_ver = SUBMINOR_VER;
    rsp->error = KM_ERROR_OK;
}

void AndroidKeymaster::SupportedAlgorithms(
    SupportedResponse<keymaster_algorithm_t>* response) const {
    if (response == NULL)
        return;

    size_t factory_count = 0;
    const KeyFactory** factories = KeyFactoryRegistry::GetAll(&factory_count);
    assert(factories != NULL);
    assert(factory_count > 0);

    UniquePtr<keymaster_algorithm_t[]> algorithms(new keymaster_algorithm_t[factory_count]);
    if (!algorithms.get()) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return;
    }

    for (size_t i = 0; i < factory_count; ++i)
        algorithms[i] = factories[i]->registry_key();

    response->results = algorithms.release();
    response->results_length = factory_count;
    response->error = KM_ERROR_OK;
}

static OperationFactory* GetOperationFactory(keymaster_algorithm_t algorithm,
                                             keymaster_purpose_t purpose,
                                             keymaster_error_t* error) {
    assert(error);
    if (error)
        *error = KM_ERROR_OK;

    OperationFactory* factory =
        OperationFactoryRegistry::Get(OperationFactory::KeyType(algorithm, purpose));
    if (factory == NULL && error)
        *error = KM_ERROR_UNSUPPORTED_PURPOSE;

    return factory;
}

template <typename T>
void GetSupported(keymaster_algorithm_t algorithm, keymaster_purpose_t purpose,
                  const T* (OperationFactory::*get_supported_method)(size_t* count) const,
                  SupportedResponse<T>* response) {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    OperationFactory* factory = GetOperationFactory(algorithm, purpose, &response->error);
    if (!factory) {
        response->error = KM_ERROR_UNSUPPORTED_PURPOSE;
        return;
    }

    size_t count;
    const T* supported = (factory->*get_supported_method)(&count);
    response->SetResults(supported, count);
}

void AndroidKeymaster::SupportedBlockModes(
    keymaster_algorithm_t algorithm, keymaster_purpose_t purpose,
    SupportedResponse<keymaster_block_mode_t>* response) const {
    GetSupported(algorithm, purpose, &OperationFactory::SupportedBlockModes, response);
}

void AndroidKeymaster::SupportedPaddingModes(
    keymaster_algorithm_t algorithm, keymaster_purpose_t purpose,
    SupportedResponse<keymaster_padding_t>* response) const {
    GetSupported(algorithm, purpose, &OperationFactory::SupportedPaddingModes, response);
}

void AndroidKeymaster::SupportedDigests(keymaster_algorithm_t algorithm,
                                        keymaster_purpose_t purpose,
                                        SupportedResponse<keymaster_digest_t>* response) const {
    GetSupported(algorithm, purpose, &OperationFactory::SupportedDigests, response);
}

void AndroidKeymaster::SupportedImportFormats(
    keymaster_algorithm_t algorithm, SupportedResponse<keymaster_key_format_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    size_t count;
    const keymaster_key_format_t* formats =
        KeyFactoryRegistry::Get(algorithm)->SupportedImportFormats(&count);
    response->SetResults(formats, count);
}

void AndroidKeymaster::SupportedExportFormats(
    keymaster_algorithm_t algorithm, SupportedResponse<keymaster_key_format_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    size_t count;
    const keymaster_key_format_t* formats =
        KeyFactoryRegistry::Get(algorithm)->SupportedExportFormats(&count);
    response->SetResults(formats, count);
}

keymaster_error_t AndroidKeymaster::AddRngEntropy(const AddEntropyRequest& request) {
    return context_->AddRngEntropy(request.random_data.peek_read(),
                                   request.random_data.available_read());
}

void AndroidKeymaster::GenerateKey(const GenerateKeyRequest& request,
                                   GenerateKeyResponse* response) {
    if (response == NULL)
        return;

    keymaster_algorithm_t algorithm;
    KeyFactory* factory = 0;
    UniquePtr<Key> key;
    if (!request.key_description.GetTagValue(TAG_ALGORITHM, &algorithm) ||
        !(factory = KeyFactoryRegistry::Get(algorithm)))
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
    else {
        KeymasterKeyBlob key_blob;
        response->enforced.Clear();
        response->unenforced.Clear();
        response->error = factory->GenerateKey(request.key_description, &key_blob,
                                               &response->enforced, &response->unenforced);
        if (response->error == KM_ERROR_OK)
            response->key_blob = key_blob.release();
    }
}

void AndroidKeymaster::GetKeyCharacteristics(const GetKeyCharacteristicsRequest& request,
                                             GetKeyCharacteristicsResponse* response) {
    if (response == NULL)
        return;

    KeymasterKeyBlob key_material;
    response->error =
        context_->ParseKeyBlob(KeymasterKeyBlob(request.key_blob), request.additional_params,
                               &key_material, &response->enforced, &response->unenforced);
    if (response->error != KM_ERROR_OK)
        return;
}

static KeyFactory* GetKeyFactory(const AuthorizationSet& hw_enforced,
                                 const AuthorizationSet& sw_enforced,
                                 keymaster_algorithm_t* algorithm, keymaster_error_t* error) {
    *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
    if (!hw_enforced.GetTagValue(TAG_ALGORITHM, algorithm) &&
        !sw_enforced.GetTagValue(TAG_ALGORITHM, algorithm))
        return nullptr;
    KeyFactory* factory = KeyFactoryRegistry::Get(*algorithm);
    if (factory)
        *error = KM_ERROR_OK;
    return factory;
}

void AndroidKeymaster::BeginOperation(const BeginOperationRequest& request,
                                      BeginOperationResponse* response) {
    if (response == NULL)
        return;
    response->op_handle = 0;

    AuthorizationSet hw_enforced;
    AuthorizationSet sw_enforced;
    keymaster_algorithm_t algorithm;
    UniquePtr<Key> key;
    response->error = LoadKey(request.key_blob, request.additional_params, &hw_enforced,
                              &sw_enforced, &algorithm, &key);
    if (response->error != KM_ERROR_OK)
        return;

    // TODO(swillden): Move this check to a general authorization checker.
    // TODO(swillden): Consider introducing error codes for unauthorized usages.
    response->error = KM_ERROR_INCOMPATIBLE_PURPOSE;
    if (!hw_enforced.Contains(TAG_PURPOSE, request.purpose) &&
        !sw_enforced.Contains(TAG_PURPOSE, request.purpose))
        return;

    response->error = KM_ERROR_UNSUPPORTED_PURPOSE;
    OperationFactory* factory = OperationFactoryRegistry::Get({algorithm, request.purpose});
    if (!factory)
        return;

    UniquePtr<Operation> operation(
        factory->CreateOperation(*key, request.additional_params, &response->error));
    if (operation.get() == NULL)
        return;

    response->output_params.Clear();
    response->error = operation->Begin(request.additional_params, &response->output_params);
    if (response->error != KM_ERROR_OK)
        return;

    response->error = operation_table_->Add(operation.release(), &response->op_handle);
}

void AndroidKeymaster::UpdateOperation(const UpdateOperationRequest& request,
                                       UpdateOperationResponse* response) {
    if (response == NULL)
        return;

    response->error = KM_ERROR_INVALID_OPERATION_HANDLE;
    Operation* operation = operation_table_->Find(request.op_handle);
    if (operation == NULL)
        return;

    response->error = operation->Update(request.additional_params, request.input, &response->output,
                                        &response->input_consumed);
    if (response->error != KM_ERROR_OK) {
        // Any error invalidates the operation.
        operation_table_->Delete(request.op_handle);
    }
}

void AndroidKeymaster::FinishOperation(const FinishOperationRequest& request,
                                       FinishOperationResponse* response) {
    if (response == NULL)
        return;

    response->error = KM_ERROR_INVALID_OPERATION_HANDLE;
    Operation* operation = operation_table_->Find(request.op_handle);
    if (operation == NULL)
        return;

    response->error =
        operation->Finish(request.additional_params, request.signature, &response->output);
    operation_table_->Delete(request.op_handle);
}

keymaster_error_t AndroidKeymaster::AbortOperation(const keymaster_operation_handle_t op_handle) {
    Operation* operation = operation_table_->Find(op_handle);
    if (operation == NULL)
        return KM_ERROR_INVALID_OPERATION_HANDLE;

    keymaster_error_t error = operation->Abort();
    operation_table_->Delete(op_handle);
    if (error != KM_ERROR_OK)
        return error;
    return KM_ERROR_OK;
}

void AndroidKeymaster::ExportKey(const ExportKeyRequest& request, ExportKeyResponse* response) {
    if (response == NULL)
        return;

    AuthorizationSet hw_enforced;
    AuthorizationSet sw_enforced;
    KeymasterKeyBlob key_material;
    response->error =
        context_->ParseKeyBlob(KeymasterKeyBlob(request.key_blob), request.additional_params,
                               &key_material, &hw_enforced, &sw_enforced);
    if (response->error != KM_ERROR_OK)
        return;

    keymaster_algorithm_t algorithm;
    KeyFactory* key_factory = GetKeyFactory(hw_enforced, sw_enforced, &algorithm, &response->error);
    if (!key_factory)
        return;

    UniquePtr<Key> key;
    response->error = key_factory->LoadKey(key_material, hw_enforced, sw_enforced, &key);
    if (response->error != KM_ERROR_OK)
        return;

    UniquePtr<uint8_t[]> out_key;
    size_t size;
    response->error = key->formatted_key_material(request.key_format, &out_key, &size);
    if (response->error == KM_ERROR_OK) {
        response->key_data = out_key.release();
        response->key_data_length = size;
    }
}

void AndroidKeymaster::ImportKey(const ImportKeyRequest& request, ImportKeyResponse* response) {
    if (response == NULL)
        return;

    keymaster_algorithm_t algorithm;
    KeyFactory* factory = 0;
    UniquePtr<Key> key;
    if (!request.key_description.GetTagValue(TAG_ALGORITHM, &algorithm) ||
        !(factory = KeyFactoryRegistry::Get(algorithm)))
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
    else {
        keymaster_key_blob_t key_material = {request.key_data, request.key_data_length};
        KeymasterKeyBlob key_blob;
        response->error = factory->ImportKey(request.key_description, request.key_format,
                                             KeymasterKeyBlob(key_material), &key_blob,
                                             &response->enforced, &response->unenforced);
        if (response->error == KM_ERROR_OK)
            response->key_blob = key_blob.release();
    }
}

keymaster_error_t AndroidKeymaster::DeleteKey(const DeleteKeyRequest& request) {
    return context_->DeleteKey(KeymasterKeyBlob(request.key_blob));
}

keymaster_error_t AndroidKeymaster::DeleteAllKeys() {
    return context_->DeleteAllKeys();
}

keymaster_error_t AndroidKeymaster::LoadKey(const keymaster_key_blob_t& key_blob,
                                            const AuthorizationSet& additional_params,
                                            AuthorizationSet* hw_enforced,
                                            AuthorizationSet* sw_enforced,
                                            keymaster_algorithm_t* algorithm, UniquePtr<Key>* key) {
    KeymasterKeyBlob key_material;
    keymaster_error_t error = context_->ParseKeyBlob(KeymasterKeyBlob(key_blob), additional_params,
                                                     &key_material, hw_enforced, sw_enforced);
    if (error != KM_ERROR_OK)
        return error;

    KeyFactory* key_factory = GetKeyFactory(*hw_enforced, *sw_enforced, algorithm, &error);
    if (error != KM_ERROR_OK) {
        assert(!key_factory);
        return error;
    }

    return key_factory->LoadKey(key_material, *hw_enforced, *sw_enforced, key);
}

}  // namespace keymaster
