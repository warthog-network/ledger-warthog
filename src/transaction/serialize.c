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
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memmove

#include "serialize.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

static void write_u32_be(uint8_t *out, size_t offset, uint32_t value) {
    out[offset] = (uint8_t) (value >> 24);
    out[offset + 1] = (uint8_t) (value >> 16);
    out[offset + 2] = (uint8_t) (value >> 8);
    out[offset + 3] = (uint8_t) value;
}

static void write_u64_be(uint8_t *out, size_t offset, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        out[offset + i] = (uint8_t) (value >> (8 * (7 - i)));
    }
}

int transaction_serialize(const transaction_t *tx, uint8_t *out, size_t out_len) {
    LEDGER_ASSERT(tx != NULL, "NULL tx");
    LEDGER_ASSERT(out != NULL, "NULL out");

    /* pinHash(32) || pinHeight(4) || nonceId(4) || pad(3) || fee(8) || to(20) || amount(8) */
    if (tx->pin_hash == NULL || tx->to == NULL || out_len < 79 || tx->pin_height > 0xffffffffu ||
        tx->nonce > 0xffffffffu) {
        return -1;
    }

    memmove(out, tx->pin_hash, 32);
    write_u32_be(out, 32, tx->pin_height);
    write_u32_be(out, 36, (uint32_t) tx->nonce);
    out[40] = 0;
    out[41] = 0;
    out[42] = 0;
    write_u64_be(out, 43, tx->fee);
    memmove(out + 51, tx->to, ADDRESS_LEN);
    write_u64_be(out, 71, tx->value);
    return 79;
}
