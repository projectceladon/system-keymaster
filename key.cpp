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

#include "key.h"

#include <openssl/x509.h>

#include "ecdsa_key.h"
#include "openssl_utils.h"
#include "rsa_key.h"
#include "symmetric_key.h"
#include "unencrypted_key_blob.h"

namespace keymaster {

/* static */
template <> KeyFactoryRegistry* KeyFactoryRegistry::instance_ptr = 0;

Key::Key(const KeyBlob& blob) {
    authorizations_.push_back(blob.unenforced());
    authorizations_.push_back(blob.enforced());
}

bool Key::rescopable() const {
    size_t rescope_tag_count = authorizations_.GetTagCount(TAG_RESCOPING_ADD) +
                               authorizations_.GetTagCount(TAG_RESCOPING_DEL);
    return rescope_tag_count > 0;
}

}  // namespace keymaster
