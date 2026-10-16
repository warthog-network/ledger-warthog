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

#include <stdbool.h>  // bool
#include <string.h>   // memmove, memset

#include "crypto_helpers.h"

#include "validate.h"
#include "menu.h"
#include "sw.h"
#include "globals.h"
#include "send_response.h"
#include "signature65.h"

void validate_pubkey(bool choice) {
    if (choice) {
        helper_send_response_pubkey();
    } else {
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
}

static int crypto_sign_message(void) {
    uint32_t info = 0;
    uint8_t raw[65] = {0};

    cx_err_t error = bip32_derive_ecdsa_sign_rs_hash_256(CX_CURVE_256K1,
                                                         G_context.bip32_path,
                                                         G_context.bip32_path_len,
                                                         CX_RND_RFC6979 | CX_LAST,
                                                         CX_SHA256,
                                                         G_context.tx_info.m_hash,
                                                         sizeof(G_context.tx_info.m_hash),
                                                         raw,
                                                         raw + 32,
                                                         &info);
    if (error != CX_OK) {
        return -1;
    }

    raw[64] = 0;
    if ((info & CX_ECCINFO_PARITY_ODD) != 0) {
        raw[64] |= 1u;
    }
    if ((info & CX_ECCINFO_xGTn) != 0) {
        raw[64] |= 2u;
    }
    if (!signature65_canonicalize(raw)) {
        return -1;
    }

    memmove(G_context.tx_info.signature, raw, sizeof(raw));
    G_context.tx_info.signature_len = sizeof(raw);
    G_context.tx_info.v = raw[64];
    PRINTF("Signature65: %.*H\n", sizeof(raw), raw);
    return 0;
}

void validate_transaction(bool choice) {
    if (choice) {
        G_context.state = STATE_APPROVED;

        if (crypto_sign_message() != 0) {
            G_context.state = STATE_NONE;
            io_send_sw(SWO_SECURITY_ISSUE);
        } else {
            helper_send_response_sig();
        }
    } else {
        G_context.state = STATE_NONE;
        io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }
}
