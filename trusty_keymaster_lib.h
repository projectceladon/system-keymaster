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

#include "common/ote_error.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/** Service Identifier for keymaster TA */
/* {5f902ace-5e5c-4cd8-ae54-87b88c22ddaf} */
#define SERVICE_KEYMASTER_UUID                                                                     \
    {                                                                                              \
        0x5f902ace, 0x5e5c, 0x4cd8, { 0xae, 0x54, 0x87, 0xb8, 0x8c, 0x22, 0xdd, 0xaf }             \
    }

// Initializes trusty session. Returns an opaque session which is used by
// clients to make trusty_call.
te_error_t trusty_init(void** opaque_session);

// Deinitializes trusty session.
void trusty_deinit(void* opaque_session);

// Makes a trusty call to send a cmd on session, with an input buffer, input
// buffer size, an output buffer and output buffer size.
// Returns data in output buffer and set out_size to actual data size.
// Note: output buffer must be large enough to hold data.
te_error_t trusty_call(void* session, uint32_t cmd, void* in_buf, uint32_t in_size, void* out_buf,
                       uint32_t* out_size);

#ifdef __cplusplus
}
#endif  // __cplusplus
