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

#include "hmac_key.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include "hmac_operation.h"

namespace keymaster {

Operation* HmacKey::CreateOperation(keymaster_purpose_t purpose, keymaster_error_t* error) {
    *error = KM_ERROR_OK;

    uint32_t tag_length;
    if (!authorizations().GetTagValue(TAG_MAC_LENGTH, &tag_length))
        *error = KM_ERROR_UNSUPPORTED_MAC_LENGTH;

    keymaster_digest_t digest;
    if (!authorizations().GetTagValue(TAG_DIGEST, &digest) || digest != KM_DIGEST_SHA_2_256)
        *error = KM_ERROR_UNSUPPORTED_DIGEST;

    if (*error != KM_ERROR_OK)
        return NULL;

    UniquePtr<Operation> op;
    switch (purpose) {
    case KM_PURPOSE_SIGN:
    case KM_PURPOSE_VERIFY:
        op.reset(
            new HmacOperation(purpose, logger_, key_data(), key_data_size(), digest, tag_length));
        break;
    default:
        *error = KM_ERROR_UNSUPPORTED_PURPOSE;
        return NULL;
    }

    if (!op.get())
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;

    return op.release();
}

}  // namespace keymaster
