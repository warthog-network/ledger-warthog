/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove

#include "os.h"
#include "cx.h"
#include "ledger_assert.h"

#include "address.h"

#include "tx_types.h"

static cx_err_t sha256(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    cx_sha256_t ctx;
    cx_err_t err = cx_sha256_init_no_throw(&ctx);
    if (err != CX_OK) {
        return err;
    }
    return cx_hash_no_throw(&ctx.header, CX_LAST, in, in_len, out, 32);
}

static cx_err_t ripemd160(const uint8_t *in, size_t in_len, uint8_t out[20]) {
    cx_ripemd160_t ctx;
    cx_err_t err = cx_ripemd160_init_no_throw(&ctx);
    if (err != CX_OK) {
        return err;
    }
    return cx_hash_no_throw(&ctx.header, CX_LAST, in, in_len, out, 20);
}

bool address_from_pubkey(const uint8_t public_key[static 65], uint8_t *out, size_t out_len) {
    uint8_t compressed[33] = {0};
    uint8_t sha[32] = {0};
    uint8_t payload[20] = {0};
    uint8_t checksum[32] = {0};

    LEDGER_ASSERT(out != NULL, "NULL out");

    if (out_len < WART_ADDRESS_LEN || public_key[0] != 0x04) {
        return false;
    }

    compressed[0] = (public_key[64] & 1u) ? 0x03 : 0x02;
    memmove(compressed + 1, public_key + 1, 32);

    if (sha256(compressed, sizeof(compressed), sha) != CX_OK) {
        return false;
    }
    if (ripemd160(sha, sizeof(sha), payload) != CX_OK) {
        return false;
    }
    if (sha256(payload, sizeof(payload), checksum) != CX_OK) {
        return false;
    }

    memmove(out, payload, sizeof(payload));
    memmove(out + sizeof(payload), checksum, 4);
    return true;
}

bool wart_address_from_payload(const uint8_t payload[static 20], uint8_t *out, size_t out_len) {
    uint8_t checksum[32] = {0};

    if (out == NULL || out_len < WART_ADDRESS_LEN) {
        return false;
    }
    if (sha256(payload, 20, checksum) != CX_OK) {
        return false;
    }
    memmove(out, payload, 20);
    memmove(out + 20, checksum, 4);
    return true;
}

bool wart_path_ok(const uint32_t *path, uint8_t len) {
    const uint32_t hardened = 0x80000000u;
    if (path == NULL || len != 5) {
        return false;
    }
    if (path[0] != (hardened | 44u) || path[1] != (hardened | 2070u)) {
        return false;
    }
    /* Account is hardened on the phone's default path, and plain on the other. */
    if (path[2] != (hardened | 0u) && path[2] != 0u) {
        return false;
    }
    if (path[3] != 0u || (path[4] & hardened) != 0u) {
        return false;
    }
    return true;
}
