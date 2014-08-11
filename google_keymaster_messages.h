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

#ifndef SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_MESSAGES_H_
#define SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_MESSAGES_H_

#include <stdlib.h>
#include <string.h>

#include "authorization_set.h"
#include "google_keymaster_utils.h"

namespace keymaster {

// Commands
const uint32_t GENERATE_KEY = 0;

struct GenerateKeyRequest : public Serializable {
    GenerateKeyRequest() {}
    GenerateKeyRequest(uint8_t* buf, size_t size) : key_description(buf, size) {}

    AuthorizationSet key_description;

    size_t SerializedSize() const { return key_description.SerializedSize(); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const {
        return key_description.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf, const uint8_t* end) {
        return key_description.Deserialize(buf, end);
    }
};

struct GenerateKeyResponse : public Serializable {
    GenerateKeyResponse() {
        error = KM_ERROR_OK;
        key_blob.key_material = NULL;
        key_blob.key_material_size = 0;
    }
    ~GenerateKeyResponse();

    keymaster_error_t error;
    keymaster_key_blob_t key_blob;
    AuthorizationSet enforced;
    AuthorizationSet unenforced;

    size_t SerializedSize() const;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const;
    bool Deserialize(const uint8_t** buf, const uint8_t* end);
};

struct SupportedAlgorithmsResponse {
    keymaster_error_t error;
    keymaster_algorithm_t* algorithms;
    size_t algorithms_length;
};

template <typename T> struct SupportedResponse {
    SupportedResponse() : results(NULL), results_length(0) {}
    ~SupportedResponse() { delete[] results; }

    template <size_t N> void SetResults(const T (&arr)[N]) {
        delete[] results;
        results_length = 0;
        results = dup_array(arr);
        if (results == NULL) {
            error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        } else {
            results_length = N;
            error = KM_ERROR_OK;
        }
    }

    keymaster_error_t error;
    T* results;
    size_t results_length;
};

struct GetKeyCharacteristicsRequest {
    keymaster_key_blob_t key_blob;
    keymaster_blob_t client_id;
    keymaster_blob_t app_data;
};

struct GetKeyCharacteristicsResponse {
    keymaster_error_t error;
    keymaster_key_blob_t key_blob;
    AuthorizationSet enforced;
    AuthorizationSet unenforced;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_MESSAGES_H_
