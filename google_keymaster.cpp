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

#include <assert.h>
#include <string.h>

#include <cstddef>

#include <openssl/rand.h>

#include <UniquePtr.h>

#include "ae.h"
#include "dsa_operation.h"
#include "ecdsa_operation.h"
#include "google_keymaster.h"
#include "google_keymaster_utils.h"
#include "key_blob.h"
#include "rsa_operation.h"

namespace keymaster {

GoogleKeymaster::GoogleKeymaster(size_t operation_table_size)
    : operation_table_(new OpTableEntry[operation_table_size]),
      operation_table_size_(operation_table_size) {
    if (operation_table_.get() == NULL)
        operation_table_size_ = 0;
}
GoogleKeymaster::~GoogleKeymaster() {
    for (size_t i = 0; i < operation_table_size_; ++i)
        if (operation_table_[i].operation != NULL)
            delete operation_table_[i].operation;
}

const uint32_t RSA_DEFAULT_KEY_SIZE = 2048;
const uint32_t DSA_DEFAULT_KEY_SIZE = 2048;
const uint64_t RSA_DEFAULT_EXPONENT = 65537;

struct AE_CTX_Delete {
    void operator()(ae_ctx* ctx) const { ae_free(ctx); }
};
typedef UniquePtr<ae_ctx, AE_CTX_Delete> Unique_ae_ctx;

keymaster_algorithm_t supported_algorithms[] = {
    KM_ALGORITHM_RSA, KM_ALGORITHM_DSA, KM_ALGORITHM_ECDSA,
};

template <typename T>
bool check_supported(keymaster_algorithm_t algorithm, SupportedResponse<T>* response) {
    if (!array_contains(supported_algorithms, algorithm)) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return false;
    }
    return true;
}

void
GoogleKeymaster::SupportedAlgorithms(SupportedResponse<keymaster_algorithm_t>* response) const {
    if (response == NULL)
        return;
    response->SetResults(supported_algorithms);
}

void
GoogleKeymaster::SupportedBlockModes(keymaster_algorithm_t algorithm,
                                     SupportedResponse<keymaster_block_mode_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;
    response->error = KM_ERROR_OK;
}

keymaster_padding_t supported_padding[] = {KM_PAD_NONE};
void
GoogleKeymaster::SupportedPaddingModes(keymaster_algorithm_t algorithm,
                                       SupportedResponse<keymaster_padding_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
    case KM_ALGORITHM_DSA:
    case KM_ALGORITHM_ECDSA:
        response->SetResults(supported_padding);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

keymaster_digest_t supported_digests[] = {KM_DIGEST_NONE};
void GoogleKeymaster::SupportedDigests(keymaster_algorithm_t algorithm,
                                       SupportedResponse<keymaster_digest_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
    case KM_ALGORITHM_DSA:
    case KM_ALGORITHM_ECDSA:
        response->SetResults(supported_digests);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

keymaster_key_format_t supported_import_formats[] = {KM_KEY_FORMAT_PKCS8};
void
GoogleKeymaster::SupportedImportFormats(keymaster_algorithm_t algorithm,
                                        SupportedResponse<keymaster_key_format_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
    case KM_ALGORITHM_DSA:
    case KM_ALGORITHM_ECDSA:
        response->SetResults(supported_import_formats);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

keymaster_key_format_t supported_export_formats[] = {KM_KEY_FORMAT_X509};
void
GoogleKeymaster::SupportedExportFormats(keymaster_algorithm_t algorithm,
                                        SupportedResponse<keymaster_key_format_t>* response) const {
    if (response == NULL || !check_supported(algorithm, response))
        return;

    response->error = KM_ERROR_OK;
    switch (algorithm) {
    case KM_ALGORITHM_RSA:
    case KM_ALGORITHM_DSA:
    case KM_ALGORITHM_ECDSA:
        response->SetResults(supported_export_formats);
        break;
    default:
        response->results_length = 0;
        break;
    }
}

void GoogleKeymaster::GenerateKey(const GenerateKeyRequest& request,
                                  GenerateKeyResponse* response) {
    if (response == NULL)
        return;
    response->error = KM_ERROR_UNKNOWN_ERROR;

    if (!CopyAuthorizations(request.key_description, response))
        return;

    AuthorizationSet hidden_auths;
    response->error = BuildHiddenAuthorizations(request.key_description, &hidden_auths);
    if (response->error != KM_ERROR_OK)
        return;

    keymaster_algorithm_t algorithm;
    if (!request.key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }

    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        if (!GenerateRsa(request.key_description, response, &hidden_auths))
            return;
        break;
    case KM_ALGORITHM_DSA:
        if (!GenerateDsa(request.key_description, response, &hidden_auths))
            return;
        break;
    case KM_ALGORITHM_ECDSA:
        if (!GenerateEcdsa(request.key_description, response, &hidden_auths))
            return;
        break;
    default:
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return;
    }

    response->error = KM_ERROR_OK;
}

void GoogleKeymaster::GetKeyCharacteristics(const GetKeyCharacteristicsRequest& request,
                                            GetKeyCharacteristicsResponse* response) {
    if (response == NULL)
        return;
    response->error = KM_ERROR_UNKNOWN_ERROR;

    UniquePtr<KeyBlob> blob(
        LoadKeyBlob(request.key_blob, request.additional_params, &(response->error)));
    if (blob.get() == NULL)
        return;

    response->enforced.Reinitialize(blob->enforced());
    response->unenforced.Reinitialize(blob->unenforced());
    response->error = KM_ERROR_OK;
}

void GoogleKeymaster::BeginOperation(const BeginOperationRequest& request,
                                     BeginOperationResponse* response) {
    if (response == NULL)
        return;
    response->error = KM_ERROR_UNKNOWN_ERROR;
    response->op_handle = 0;

    UniquePtr<KeyBlob> key(
        LoadKeyBlob(request.key_blob, request.additional_params, &response->error));
    if (key.get() == NULL)
        return;

    UniquePtr<Operation> operation;
    switch (key->algorithm()) {
    case KM_ALGORITHM_RSA:
        operation.reset(new RsaOperation(request.purpose, *key));
        break;
    case KM_ALGORITHM_DSA:
        operation.reset(new DsaOperation(request.purpose, *key));
        break;
    default:
        response->error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        break;
    }

    if (operation.get() == NULL) {
        return;
    }

    response->error = operation->Begin();
    if (response->error != KM_ERROR_OK)
        return;

    response->error = AddOperation(operation.release(), &response->op_handle);
}

void GoogleKeymaster::UpdateOperation(const UpdateOperationRequest& request,
                                      UpdateOperationResponse* response) {
    OpTableEntry* entry = FindOperation(request.op_handle);
    if (entry == NULL) {
        response->error = KM_ERROR_INVALID_OPERATION_HANDLE;
        return;
    }

    response->error = entry->operation->Update(request.input, &response->output);
    if (response->error != KM_ERROR_OK) {
        // Any error invalidates the operation.
        DeleteOperation(entry);
    }
}

void GoogleKeymaster::FinishOperation(const FinishOperationRequest& request,
                                      FinishOperationResponse* response) {
    OpTableEntry* entry = FindOperation(request.op_handle);
    if (entry == NULL) {
        response->error = KM_ERROR_INVALID_OPERATION_HANDLE;
        return;
    }

    response->error = entry->operation->Finish(request.signature, &response->output);
    DeleteOperation(entry);
}

keymaster_error_t GoogleKeymaster::AbortOperation(const keymaster_operation_handle_t op_handle) {
    OpTableEntry* entry = FindOperation(op_handle);
    if (entry == NULL)
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    DeleteOperation(entry);
    return KM_ERROR_OK;
}

bool GoogleKeymaster::GenerateRsa(const AuthorizationSet& key_auths, GenerateKeyResponse* response,
                                  AuthorizationSet* hidden_auths) {
    uint64_t public_exponent = RSA_DEFAULT_EXPONENT;
    if (!key_auths.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent))
        AddAuthorization(Authorization(TAG_RSA_PUBLIC_EXPONENT, public_exponent), response);

    uint32_t key_size = RSA_DEFAULT_KEY_SIZE;
    if (!key_auths.GetTagValue(TAG_KEY_SIZE, &key_size))
        AddAuthorization(Authorization(TAG_KEY_SIZE, key_size), response);

    UniquePtr<uint8_t[]> key_data;
    size_t key_data_size;
    keymaster_error_t error =
        RsaOperation::Generate(public_exponent, key_size, &key_data, &key_data_size);
    if (error != KM_ERROR_OK) {
        response->error = error;
        return false;
    }

    return CreateKeyBlob(response, *hidden_auths, key_data.get(), key_data_size);
}

template <keymaster_tag_t Tag>
static void GetDsaParamData(const AuthorizationSet& auths, TypedTag<KM_BIGNUM, Tag> tag,
                            keymaster_blob_t* blob) {
    if (!auths.GetTagValue(tag, blob))
        blob->data = NULL;
}

bool GoogleKeymaster::GenerateDsa(const AuthorizationSet& key_auths, GenerateKeyResponse* response,
                                  AuthorizationSet* hidden_auths) {
    keymaster_blob_t g_blob;
    GetDsaParamData(key_auths, TAG_DSA_GENERATOR, &g_blob);
    const uint8_t* original_g = g_blob.data;

    keymaster_blob_t p_blob;
    GetDsaParamData(key_auths, TAG_DSA_P, &p_blob);
    const uint8_t* original_p = p_blob.data;

    keymaster_blob_t q_blob;
    GetDsaParamData(key_auths, TAG_DSA_Q, &q_blob);
    const uint8_t* original_q = q_blob.data;

    uint32_t key_size = DSA_DEFAULT_KEY_SIZE;
    if (!key_auths.GetTagValue(TAG_KEY_SIZE, &key_size))
        AddAuthorization(Authorization(TAG_KEY_SIZE, key_size), response);

    UniquePtr<uint8_t[]> key_data;
    size_t key_data_size;
    keymaster_error_t error =
        DsaOperation::Generate(key_size, &g_blob, &p_blob, &q_blob, &key_data, &key_data_size);

    // If any the original_* pointers are NULL, DsaOperation::Generate should have generated values
    // for the corressponding blobs.  We need to put them in the authorization set and clean up the
    // allocated memory.
    if (original_g == NULL && g_blob.data != NULL) {
        if (!AddAuthorization(Authorization(TAG_DSA_GENERATOR, g_blob), response))
            error = KM_ERROR_INVALID_DSA_PARAMS;
        delete[] g_blob.data;
    }
    if (original_p == NULL && p_blob.data != NULL) {
        if (!AddAuthorization(Authorization(TAG_DSA_P, p_blob), response))
            error = KM_ERROR_INVALID_DSA_PARAMS;
        delete[] p_blob.data;
    }
    if (original_q == NULL && q_blob.data != NULL) {
        if (!AddAuthorization(Authorization(TAG_DSA_Q, q_blob), response))
            error = KM_ERROR_INVALID_DSA_PARAMS;
        delete[] q_blob.data;
    }

    if (error != KM_ERROR_OK) {
        response->error = error;
        return false;
    }

    return CreateKeyBlob(response, *hidden_auths, key_data.get(), key_data_size);
}

bool GoogleKeymaster::GenerateEcdsa(const AuthorizationSet& key_auths,
                                    GenerateKeyResponse* response, AuthorizationSet* hidden_auths) {
    uint64_t public_exponent = RSA_DEFAULT_EXPONENT;
    if (!key_auths.GetTagValue(TAG_RSA_PUBLIC_EXPONENT, &public_exponent))
        AddAuthorization(Authorization(TAG_RSA_PUBLIC_EXPONENT, public_exponent), response);

    uint32_t key_size = RSA_DEFAULT_KEY_SIZE;
    if (!key_auths.GetTagValue(TAG_KEY_SIZE, &key_size))
        AddAuthorization(Authorization(TAG_KEY_SIZE, key_size), response);

    UniquePtr<uint8_t[]> key_data;
    size_t key_data_size;
    keymaster_error_t error = EcdsaOperation::Generate(key_size, &key_data, &key_data_size);
    if (error != KM_ERROR_OK) {
        response->error = error;
        return false;
    }

    return CreateKeyBlob(response, *hidden_auths, key_data.get(), key_data_size);
}

bool GoogleKeymaster::CreateKeyBlob(GenerateKeyResponse* response,
                                    const AuthorizationSet& hidden_auths, uint8_t* key_bytes,
                                    size_t key_length) {
    uint8_t nonce[KeyBlob::NONCE_LENGTH];
    GenerateNonce(nonce, array_size(nonce));

    keymaster_key_blob_t key_data = {key_bytes, key_length};
    UniquePtr<KeyBlob> blob(new KeyBlob(response->enforced, response->unenforced, hidden_auths,
                                        key_data, MasterKey(), nonce));
    if (blob.get() == NULL) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }

    if (blob->error() != KM_ERROR_OK) {
        return blob->error();
        return false;
    }

    size_t size = blob->SerializedSize();
    UniquePtr<uint8_t[]> blob_bytes(new uint8_t[size]);
    if (blob_bytes.get() == NULL) {
        response->error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return false;
    }
    blob->Serialize(blob_bytes.get(), blob_bytes.get() + size);
    response->key_blob.key_material_size = size;
    response->key_blob.key_material = blob_bytes.release();
    return true;
}

KeyBlob* GoogleKeymaster::LoadKeyBlob(const keymaster_key_blob_t& key,
                                      const AuthorizationSet& client_params,
                                      keymaster_error_t* error) {
    AuthorizationSet hidden;
    BuildHiddenAuthorizations(client_params, &hidden);
    UniquePtr<KeyBlob> blob(new KeyBlob(key, hidden, MasterKey()));
    if (blob.get() == NULL) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return NULL;
    } else if (blob->error() != KM_ERROR_OK) {
        *error = blob->error();
        return NULL;
    }
    return blob.release();
}

static keymaster_error_t CheckAuthorizationSet(const AuthorizationSet& set) {
    switch (set.is_valid()) {
    case AuthorizationSet::OK:
        return KM_ERROR_OK;
    case AuthorizationSet::ALLOCATION_FAILURE:
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    case AuthorizationSet::MALFORMED_DATA:
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

bool GoogleKeymaster::CopyAuthorizations(const AuthorizationSet& key_description,
                                         GenerateKeyResponse* response) {
    for (size_t i = 0; i < key_description.size(); ++i) {
        switch (key_description[i].tag) {
        case KM_TAG_ROOT_OF_TRUST:
        case KM_TAG_CREATION_DATETIME:
        case KM_TAG_ORIGIN:
            response->error = KM_ERROR_INVALID_TAG;
            return false;
        case KM_TAG_ROLLBACK_RESISTANT:
            response->error = KM_ERROR_UNSUPPORTED_TAG;
            return false;
        default:
            if (!AddAuthorization(key_description[i], response))
                return false;
            break;
        }
    }

    if (!AddAuthorization(Authorization(TAG_CREATION_DATETIME, java_time(time(NULL))), response) ||
        !AddAuthorization(Authorization(TAG_ORIGIN, origin()), response))
        return false;

    response->error = CheckAuthorizationSet(response->enforced);
    if (response->error != KM_ERROR_OK)
        return false;
    response->error = CheckAuthorizationSet(response->unenforced);
    if (response->error != KM_ERROR_OK)
        return false;

    return true;
}

keymaster_error_t GoogleKeymaster::BuildHiddenAuthorizations(const AuthorizationSet& input_set,
                                                             AuthorizationSet* hidden) {
    keymaster_blob_t entry;
    if (input_set.GetTagValue(TAG_APPLICATION_ID, &entry))
        hidden->push_back(TAG_APPLICATION_ID, entry.data, entry.data_length);
    if (input_set.GetTagValue(TAG_APPLICATION_DATA, &entry))
        hidden->push_back(TAG_APPLICATION_DATA, entry.data, entry.data_length);
    hidden->push_back(RootOfTrustTag());

    return CheckAuthorizationSet(*hidden);
}

bool GoogleKeymaster::AddAuthorization(const keymaster_key_param_t& auth,
                                       GenerateKeyResponse* response) {
    switch (auth.tag) {
    case KM_TAG_ROOT_OF_TRUST:
    case KM_TAG_APPLICATION_ID:
    case KM_TAG_APPLICATION_DATA:
        // Skip.  We handle these tags separately.
        return true;
    default:
        if (is_enforced(auth.tag))
            return response->enforced.push_back(auth);
        else
            return response->unenforced.push_back(auth);
    }
}

keymaster_error_t GoogleKeymaster::AddOperation(Operation* operation,
                                                keymaster_operation_handle_t* op_handle) {
    UniquePtr<Operation> op(operation);
    if (RAND_bytes(reinterpret_cast<uint8_t*>(op_handle), sizeof(*op_handle)) == 0)
        return KM_ERROR_UNKNOWN_ERROR;
    if (*op_handle == 0) {
        // Statistically this is vanishingly unlikely, which means if it ever happens in practice,
        // it indicates a broken RNG.
        return KM_ERROR_UNKNOWN_ERROR;
    }
    for (size_t i = 0; i < operation_table_size_; ++i) {
        if (operation_table_[i].operation == NULL) {
            operation_table_[i].operation = op.release();
            operation_table_[i].handle = *op_handle;
            return KM_ERROR_OK;
        }
    }
    return KM_ERROR_TOO_MANY_OPERATIONS;
}

GoogleKeymaster::OpTableEntry*
GoogleKeymaster::FindOperation(keymaster_operation_handle_t op_handle) {
    if (op_handle == 0)
        return NULL;

    for (size_t i = 0; i < operation_table_size_; ++i) {
        if (operation_table_[i].handle == op_handle)
            return operation_table_.get() + i;
    }
    return NULL;
}

void GoogleKeymaster::DeleteOperation(OpTableEntry* entry) {
    delete entry->operation;
    entry->operation = NULL;
    entry->handle = 0;
}

}  // namespace keymaster
