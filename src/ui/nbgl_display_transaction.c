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
#include <stdint.h>   // uint*_t
#include <stdio.h>    // snprintf
#include <string.h>   // memset

#include "os.h"
#include "glyphs.h"
#include "os_io_seproxyhal.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "address.h"
#include "validate.h"
#include "tx_types.h"
#include "menu.h"

// Amount and fee strings include the " WART" suffix. 48 covers a full uint64 at 8 decimals.
static char g_amount[48];
static char g_fee[48];
static char g_address[WART_ADDRESS_LEN * 2 + 1];
static char g_from[WART_ADDRESS_LEN * 2 + 1];
static char g_pin_hash[65];
static char g_nonce[16];
static char g_pin_height[16];
static char g_path[160];

// Native review shows eight rows.
static nbgl_contentTagValue_t pairs[8];
static nbgl_contentTagValueList_t pairList;

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    validate_transaction(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

static bool write_u32(char *out, size_t out_len, unsigned int value) {
    int wrote = snprintf(out, out_len, "%u", value);
    return wrote > 0 && (size_t) wrote < out_len;
}

static bool format_bip32_path(char *out, size_t out_len) {
    size_t used = 0;

    if (G_context.bip32_path_len == 0 || G_context.bip32_path_len > MAX_BIP32_PATH) {
        return false;
    }
    if (out_len < 2) {
        return false;
    }
    out[0] = 'm';
    out[1] = '\0';
    used = 1;
    for (uint8_t i = 0; i < G_context.bip32_path_len; i++) {
        uint32_t value = G_context.bip32_path[i];
        int hardened = (value & 0x80000000u) != 0;
        value &= 0x7fffffffu;
        int wrote = snprintf(out + used,
                             out_len - used,
                             hardened ? "/%u'" : "/%u",
                             (unsigned int) value);
        if (wrote < 0 || (size_t) wrote >= out_len - used) {
            return false;
        }
        used += (size_t) wrote;
    }
    return true;
}

// Native WART transfers show the account that will sign, the path, both amounts,
// the destination, and the chain pin fields.
static int ui_display_native_transaction(void) {
    explicit_bzero(g_amount, sizeof(g_amount));
    explicit_bzero(g_address, sizeof(g_address));
    explicit_bzero(g_from, sizeof(g_from));
    explicit_bzero(g_fee, sizeof(g_fee));
    explicit_bzero(g_pin_hash, sizeof(g_pin_hash));
    explicit_bzero(g_nonce, sizeof(g_nonce));
    explicit_bzero(g_pin_height, sizeof(g_pin_height));
    explicit_bzero(g_path, sizeof(g_path));
    memset(pairs, 0, sizeof(pairs));

    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        PRINTF("ui_display_transaction: bad state %d/%d (expected %d/%d)\n",
               G_context.req_type,
               G_context.state,
               CONFIRM_TRANSACTION,
               STATE_PARSED);
        return io_send_sw(SWO_CONDITIONS_NOT_SATISFIED);
    }

    if (G_context.tx_info.transaction.to == NULL) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }
    if (G_context.tx_info.transaction.pin_hash == NULL ||
        G_context.tx_info.transaction.nonce > 0xffffffffu) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    char amount[48] = {0};
    if (!format_fpu64(amount, sizeof(amount), G_context.tx_info.transaction.value, WART_DECIMALS)) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    int wrote = snprintf(g_amount, sizeof(g_amount), "%.*s WART", (int) strlen(amount), amount);
    if (wrote < 0 || (size_t) wrote >= sizeof(g_amount)) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }
    char fee_amount[48] = {0};
    if (!format_fpu64(fee_amount,
                      sizeof(fee_amount),
                      G_context.tx_info.transaction.fee,
                      WART_DECIMALS)) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }
    wrote = snprintf(g_fee, sizeof(g_fee), "%.*s WART", (int) strlen(fee_amount), fee_amount);
    if (wrote < 0 || (size_t) wrote >= sizeof(g_fee)) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    uint8_t full_address[WART_ADDRESS_LEN] = {0};
    if (!wart_address_from_payload(G_context.tx_info.transaction.to,
                                   full_address,
                                   sizeof(full_address)) ||
        format_hex(full_address, sizeof(full_address), g_address, sizeof(g_address)) == -1) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    if (format_hex(G_context.tx_info.sender,
                   sizeof(G_context.tx_info.sender),
                   g_from,
                   sizeof(g_from)) == -1 ||
        !format_bip32_path(g_path, sizeof(g_path)) ||
        !write_u32(g_nonce, sizeof(g_nonce), (unsigned int) G_context.tx_info.transaction.nonce) ||
        !write_u32(g_pin_height, sizeof(g_pin_height), G_context.tx_info.transaction.pin_height) ||
        format_hex(G_context.tx_info.transaction.pin_hash, 32, g_pin_hash, sizeof(g_pin_hash)) ==
            -1) {
        return io_send_sw(SWO_INCORRECT_DATA);
    }

    int pair_index = 0;
    pairs[pair_index].item = "From";
    pairs[pair_index].value = g_from;
    pair_index++;
    pairs[pair_index].item = "Path";
    pairs[pair_index].value = g_path;
    pair_index++;
    pairs[pair_index].item = "Amount";
    pairs[pair_index].value = g_amount;
    pair_index++;
    pairs[pair_index].item = "Fee";
    pairs[pair_index].value = g_fee;
    pair_index++;
    pairs[pair_index].item = "To";
    pairs[pair_index].value = g_address;
    pair_index++;
    pairs[pair_index].item = "Nonce";
    pairs[pair_index].value = g_nonce;
    pair_index++;
    pairs[pair_index].item = "Pin height";
    pairs[pair_index].value = g_pin_height;
    pair_index++;
    pairs[pair_index].item = "Pin hash";
    pairs[pair_index].value = g_pin_hash;
    pair_index++;

    // A 64-character pin hash needs several lines on a Nano.
    pairList.nbMaxLinesForValue = 6;
    pairList.nbPairs = pair_index;
    pairList.pairs = pairs;
    pairList.wrapping = true;

#ifdef SCREEN_SIZE_WALLET
    // On big screen size devices, display a rich text with some context on the final page
    const char *sign_text = "Sign transaction\nto send WART?";
#else
    // On small screen size devices, fallback to the SDK default text
    const char *sign_text = NULL;
#endif

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &ICON_APP_BOILERPLATE,
                       "Review transaction\nto send WART",
                       NULL,
                       sign_text,
                       review_choice);
    return 0;
}

int ui_display_transaction(void) {
    return ui_display_native_transaction();
}
