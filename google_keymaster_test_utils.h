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

#ifndef SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_TEST_UTILS_H_
#define SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_TEST_UTILS_H_

/*
 * Utilities used to help with testing.  Not used in production code.
 */

#include <ostream>

#include "keymaster_defs.h"
#include "authorization_set.h"

std::ostream& operator<<(std::ostream& os, const keymaster_key_param_t& param);
bool operator==(const keymaster_key_param_t& a, const keymaster_key_param_t& b);

namespace keymaster {
bool operator==(const AuthorizationSet& a, const AuthorizationSet& b);
std::ostream& operator<<(std::ostream& os, const AuthorizationSet& set);
}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_GOOGLE_KEYMASTER_TEST_UTILS_H_
