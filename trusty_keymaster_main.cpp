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

#include <stdio.h>

#include <hardware/keymaster.h>

#include "trusty_keymaster_device.h"

int main(void) {
    keymaster::TrustyKeymasterDevice device(NULL);
    if (device.session_error() != OTE_SUCCESS) {
        printf("Failed to initialize Trusty session: %d\n", device.session_error());
        return 1;
    }
    printf("Trusty session initialized\n");

    uint8_t* ptr = NULL;
    size_t size;
    int error;

    printf("=== Generating RSA key pair ===\n");
    keymaster_rsa_keygen_params_t rsa_params;
    rsa_params.public_exponent = 3;
    rsa_params.modulus_size = 256;

    error = device.generate_keypair(TYPE_RSA, &rsa_params, &ptr, &size);
    if (error != 0)
        printf("Error generating RSA key pair: %d\n", error);
    else
        delete[] ptr;

    printf("=== Generating DSA key pair ===\n");
    keymaster_dsa_keygen_params_t dsa_params;
    dsa_params.key_size = 2048;
    // These params are invalid for other keymaster impls.
    dsa_params.generator_len = 0;
    dsa_params.prime_p_len = 0;
    dsa_params.prime_q_len = 0;
    dsa_params.generator = NULL;
    dsa_params.prime_p = NULL;
    dsa_params.prime_q = NULL;
    error = device.generate_keypair(TYPE_DSA, &dsa_params, &ptr, &size);
    if (error != 0)
        printf("Error generating DSA key pair: %d\n", error);
    else
        delete[] ptr;

    printf("=== Generating ECDSA key pair ===\n");
    keymaster_ec_keygen_params_t ecdsa_params;
    ecdsa_params.field_size = 256;
    error = device.generate_keypair(TYPE_EC, &ecdsa_params, &ptr, &size);
    if (error != 0)
        printf("Error generating ECDSA key pair: %d\n", error);
    else
        delete[] ptr;
}
