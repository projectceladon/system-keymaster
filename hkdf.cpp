/*
 * Copyright 2015 The Android Open Source Project
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

#include "hmac.h"
#include "hkdf.h"

#include <assert.h>
#include <keymaster/logger.h>

namespace keymaster {

const size_t kSHA256HashLength = 32;

Rfc5869HmacSha256Kdf::Rfc5869HmacSha256Kdf(Buffer& secret, Buffer& salt, Buffer& info,
                                           size_t key_bytes_to_generate) {
    Rfc5869HmacSha256Kdf(secret.peek_read(), secret.available_read(), salt.peek_read(),
                         salt.available_read(), info.peek_read(), info.available_read(),
                         key_bytes_to_generate);
}

Rfc5869HmacSha256Kdf::Rfc5869HmacSha256Kdf(const uint8_t* secret, size_t secret_len,
                                           const uint8_t* salt, size_t salt_len,
                                           const uint8_t* info, size_t info_len,
                                           size_t key_bytes_to_generate) {
    // https://tools.ietf.org/html/rfc5869#section-2.2
    Buffer actual_salt;
    if (salt) {
        actual_salt.Reinitialize(salt, salt_len);
    } else {
        char zeros[kSHA256HashLength];
        // If salt is not given, HashLength zeros are used.
        memset(zeros, 0, sizeof(zeros));
        actual_salt.Reinitialize(zeros, sizeof(zeros));
    }

    // Step 1. Extract: PRK = HMAC-SHA256(actual_salt, secret)
    // https://tools.ietf.org/html/rfc5869#section-2.2
    Hmac prk_hmac(Hmac::SHA256);
    bool result = prk_hmac.Init(actual_salt);
    assert(result);

    // |prk| is a pseudorandom key (of kSHA256HashLength octets).
    uint8_t prk[kSHA256HashLength];
    assert(sizeof(prk) == prk_hmac.DigestLength());
    result = prk_hmac.Sign(secret, secret_len, prk, sizeof(prk));
    assert(result);

    // Step 2. Expand: OUTPUT = HKDF-Expand(PRK, info)
    // https://tools.ietf.org/html/rfc5869#section-2.3
    const size_t n = (key_bytes_to_generate + kSHA256HashLength - 1) / kSHA256HashLength;
    assert(n < 256u);

    output_.Reinitialize(n * kSHA256HashLength);
    uint8_t buf[kSHA256HashLength + info_len + 1];
    uint8_t digest[kSHA256HashLength];
    Buffer previous;

    Hmac hmac(Hmac::SHA256);
    result = hmac.Init(prk, sizeof(prk));
    assert(result);

    for (size_t i = 1; i <= n; i++) {
        memcpy(buf, previous.peek_read(), previous.available_read());
        size_t j = previous.available_read();
        memcpy(buf + j, info, info_len);
        j += info_len;
        buf[j++] = static_cast<uint8_t>(i);
        result = hmac.Sign(buf, j, digest, sizeof(digest));
        assert(result);
        output_.write(digest, sizeof(digest));
        previous.Reinitialize(reinterpret_cast<uint8_t*>(digest), sizeof(digest));
    }

    if (key_bytes_to_generate)
        secret_key_.Reinitialize(output_.peek_read(), key_bytes_to_generate);
}

}  // namespace keymaster
