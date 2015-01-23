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

#ifndef SYSTEM_KEYMASTER_OCB_UTILS_H_
#define SYSTEM_KEYMASTER_OCB_UTILS_H_

#include "ae.h"

namespace keymaster {

class AeCtx {
  public:
    AeCtx() : ctx_(ae_allocate(NULL)) {}
    ~AeCtx() {
        ae_clear(ctx_);
        ae_free(ctx_);
    }

    ae_ctx* get() { return ctx_; }

  private:
    ae_ctx* ctx_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_OCB_UTILS_H_
