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

#include <stdlib.h>
#include <string.h>

#include "trusty_keymaster.h"

namespace keymaster {

uint8_t TrustyKeymaster::master_key_[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t TrustyKeymaster::root_of_trust_[] = "TrustyKeymaster";
size_t TrustyKeymaster::root_of_trust_size_ = sizeof(root_of_trust_);

bool TrustyKeymaster::is_enforced(keymaster_tag_t tag) {
    switch (tag) {
    // Everything not called out as enforced isn't enforced.
    default:
        return false;

    // Enforced because cryptography is performed in TrustZone.
    case KM_TAG_ALGORITHM:
    case KM_TAG_KEY_SIZE:
    case KM_TAG_RSA_PUBLIC_EXPONENT:
    case KM_TAG_DSA_GENERATOR:
    case KM_TAG_DSA_P:
    case KM_TAG_DSA_Q:
    case KM_TAG_BLOB_USAGE_REQUIREMENTS:
    case KM_TAG_ORIGIN:

    // Enforced by implementation.
    case KM_TAG_DIGEST:
    case KM_TAG_PADDING:

    // Enforced because tags are bound securely.  Rescoping isn't implemented, so rescoping won't
    // work but can't be done outside of TrustZone.
    case KM_TAG_RESCOPING_ADD:
    case KM_TAG_RESCOPING_DEL:
        return true;
    }
}

}  // namespace keymaster
