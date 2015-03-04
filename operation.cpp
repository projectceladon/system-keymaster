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

#include "operation.h"

namespace keymaster {

DEFINE_ABSTRACT_FACTORY_REGISTRY_INSTANCE(OperationFactory);

bool OperationFactory::supported(keymaster_padding_t padding) const {
    size_t padding_count;
    const keymaster_padding_t* supported_paddings = SupportedPaddingModes(&padding_count);
    for (size_t i = 0; i < padding_count; ++i)
        if (padding == supported_paddings[i])
            return true;
    return false;
}

bool OperationFactory::supported(keymaster_block_mode_t block_mode) const {
    size_t block_mode_count;
    const keymaster_block_mode_t* supported_block_modes = SupportedBlockModes(&block_mode_count);
    for (size_t i = 0; i < block_mode_count; ++i)
        if (block_mode == supported_block_modes[i])
            return true;
    return false;
}

bool OperationFactory::supported(keymaster_digest_t digest) const {
    size_t digest_count;
    const keymaster_digest_t* supported_digests = SupportedDigests(&digest_count);
    for (size_t i = 0; i < digest_count; ++i)
        if (digest == supported_digests[i])
            return true;
    return false;
}

}  // namespace keymaster
