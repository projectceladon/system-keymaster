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

#ifndef SYSTEM_KEYMASTER_OPERATION_H_
#define SYSTEM_KEYMASTER_OPERATION_H_

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include <keymaster/google_keymaster_utils.h>
#include <hardware/keymaster_defs.h>
#include <keymaster/logger.h>

#include "abstract_factory_registry.h"

namespace keymaster {

class AuthorizationSet;
class Key;
class Operation;

class OperationFactory {
  public:
    virtual ~OperationFactory() {}

    // Required for registry
    struct KeyType {
        KeyType(keymaster_algorithm_t alg, keymaster_purpose_t purp)
            : algorithm(alg), purpose(purp) {}

        keymaster_algorithm_t algorithm;
        keymaster_purpose_t purpose;

        bool operator==(const KeyType& rhs) const {
            return algorithm == rhs.algorithm && purpose == rhs.purpose;
        }
    };
    virtual KeyType registry_key() const = 0;

    // Factory methods
    virtual Operation* CreateOperation(const Key& key, const Logger& logger,
                                       keymaster_error_t* error) = 0;

    // Informational methods.  The returned arrays reference static memory and must not be
    // deallocated or modified.
    virtual const keymaster_padding_t* SupportedPaddingModes(size_t* padding_count) const {
        *padding_count = 0;
        return NULL;
    }
    virtual const keymaster_block_mode_t* SupportedBlockModes(size_t* block_mode_count) const {
        *block_mode_count = 0;
        return NULL;
    }
    virtual const keymaster_digest_t* SupportedDigests(size_t* digest_count) const {
        *digest_count = 0;
        return NULL;
    }
};

typedef AbstractFactoryRegistry<OperationFactory> OperationFactoryRegistry;

/**
 * Abstract base for all cryptographic operations.
 */
class Operation {
  public:
    Operation(keymaster_purpose_t purpose, const Logger& logger)
        : purpose_(purpose), logger_(logger) {}
    virtual ~Operation() {}

    keymaster_purpose_t purpose() const { return purpose_; }

    const Logger& logger() { return logger_; }

    virtual keymaster_error_t Begin(const AuthorizationSet& input_params,
                                    AuthorizationSet* output_params) = 0;
    virtual keymaster_error_t Update(const AuthorizationSet& additional_params, const Buffer& input,
                                     Buffer* output, size_t* input_consumed) = 0;
    virtual keymaster_error_t Finish(const AuthorizationSet& /* additional_params */,
                                     const Buffer& signature, Buffer* output) = 0;
    virtual keymaster_error_t Abort() = 0;

  private:
    const keymaster_purpose_t purpose_;
    const Logger& logger_;
};

}  // namespace keymaster

#endif  // SYSTEM_KEYMASTER_OPERATION_H_
