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

#ifndef EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_H_
#define EXTERNAL_KEYMASTER_TRUSTY_KEYMASTER_H_

#include "google_keymaster.h"

namespace keymaster {

class TrustyKeymaster : public GoogleKeymaster {
  public:
    TrustyKeymaster(size_t operation_table_size, Logger* logger)
        : GoogleKeymaster(operation_table_size, logger) {
        logger->log("Created TrustyKeyaster\n");
    }

  private:
    virtual bool is_enforced(keymaster_tag_t tag);
    virtual keymaster_key_origin_t origin() { return KM_ORIGIN_HARDWARE; }
    virtual keymaster_key_param_t RootOfTrustTag() {
        return Authorization(TAG_ROOT_OF_TRUST, root_of_trust_, root_of_trust_size_);
    }

    /* TODO(swillden): Call secure key derivation function to initialize master key */
    virtual keymaster_key_blob_t MasterKey() {
        keymaster_key_blob_t retval;
        retval.key_material = master_key_;
        retval.key_material_size = 16;
        return retval;
    }

    /* TODO(swillden): Use Trusty RNG to generate nonce. */
    virtual void GenerateNonce(uint8_t* nonce, size_t length) {
        for (size_t i = 0; i < length; ++i)
            nonce[i] = 0;
    }

    static uint8_t master_key_[];
    static uint8_t root_of_trust_[];
    static size_t root_of_trust_size_;
};

}  // namespace

#endif  // EXTERNAL_KEYMASTER_GOOGLE_SOFT_KEYMASTER_H_
