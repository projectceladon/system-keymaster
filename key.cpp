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

#include "asymmetric_key.h"
#include "key_blob.h"

#include "key.h"

namespace keymaster {

Key::Key(const KeyBlob& blob) {
    authorizations_.push_back(blob.unenforced());
    authorizations_.push_back(blob.enforced());
}

/* static */
Key* Key::CreateKey(const KeyBlob& blob, keymaster_error_t* error) {
    switch (blob.algorithm()) {
    case KM_ALGORITHM_RSA:
        return new RsaKey(blob, error);
    case KM_ALGORITHM_DSA:
        return new DsaKey(blob, error);
    case KM_ALGORITHM_ECDSA:
        return new EcdsaKey(blob, error);
    default:
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return NULL;
    }
}

/* static */
Key* Key::GenerateKey(const AuthorizationSet& key_description, keymaster_error_t* error) {
    keymaster_algorithm_t algorithm;
    if (!key_description.GetTagValue(TAG_ALGORITHM, &algorithm)) {
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return NULL;
    }

    switch (algorithm) {
    case KM_ALGORITHM_RSA:
        return RsaKey::GenerateKey(key_description, error);
    case KM_ALGORITHM_DSA:
        return DsaKey::GenerateKey(key_description, error);
    case KM_ALGORITHM_ECDSA:
        return EcdsaKey::GenerateKey(key_description, error);
    default:
        *error = KM_ERROR_UNSUPPORTED_ALGORITHM;
        return NULL;
    }
}

}  // namespace keymaster
