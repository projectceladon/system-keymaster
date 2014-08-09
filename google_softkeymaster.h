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

#ifndef SYSTEM_KEYMASTER_GOOGLE_SOFT_KEYMASTER_H_
#define SYSTEM_KEYMASTER_GOOGLE_SOFT_KEYMASTER_H_

#include "google_keymaster.h"

namespace keymaster {

class GoogleSoftKeymaster : public GoogleKeymaster {
  public:
    bool is_enforced(keymaster_tag_t /* tag */) { return false; }
    keymaster_key_origin_t origin() { return KM_ORIGIN_SOFTWARE; }

  private:
    static uint8_t master_key_[];

    uint8_t* MasterKey() { return master_key_; }

    size_t MasterKeyLength() { return 16; }

    void GetNonce(uint8_t* nonce, size_t length) {
        for (size_t i = 0; i < length; ++i)
            nonce[i] = 0;
    }
};

uint8_t GoogleSoftKeymaster::master_key_[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

}  // namespace

#endif  // SYSTEM_KEYMASTER_GOOGLE_SOFT_KEYMASTER_H_
