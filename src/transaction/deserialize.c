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
#include "buffer.h"

#include "deserialize.h"
#include "utils.h"
#include "types.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

parser_status_e transaction_deserialize(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    /* pinHash(32) || pinHeight(4) || nonceId(4) || pad(3) || fee(8) || to(20) || amount(8) */
    if (buf->size != 79) {
        PRINTF("WRONG_LENGTH_ERROR\n");
        return WRONG_LENGTH_ERROR;
    }

    tx->pin_hash = buf->ptr + buf->offset;
    if (!buffer_seek_cur(buf, 32)) {
        return WRONG_LENGTH_ERROR;
    }

    uint32_t nonce = 0;
    uint32_t pin_height = 0;
    if (!buffer_read_u32(buf, &pin_height, BE) || !buffer_read_u32(buf, &nonce, BE)) {
        PRINTF("NONCE_PARSING_ERROR\n");
        return NONCE_PARSING_ERROR;
    }
    tx->nonce = nonce;
    tx->pin_height = pin_height;

    const uint8_t *pad = buf->ptr + buf->offset;
    if (!buffer_seek_cur(buf, 3) || pad[0] != 0 || pad[1] != 0 || pad[2] != 0) {
        PRINTF("WRONG_LENGTH_ERROR\n");
        return WRONG_LENGTH_ERROR;
    }

    if (!buffer_read_u64(buf, &tx->fee, BE)) {
        PRINTF("VALUE_PARSING_ERROR\n");
        return VALUE_PARSING_ERROR;
    }

    tx->to = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, ADDRESS_LEN)) {
        PRINTF("TO_PARSING_ERROR\n");
        return TO_PARSING_ERROR;
    }

    if (!buffer_read_u64(buf, &tx->value, BE)) {
        PRINTF("VALUE_PARSING_ERROR\n");
        return VALUE_PARSING_ERROR;
    }

    tx->token_address = NULL;
    tx->memo = (uint8_t *) "";
    tx->memo_len = 0;

    return (buf->offset == buf->size) ? PARSING_OK : WRONG_LENGTH_ERROR;
}
