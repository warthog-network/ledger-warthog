#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "deserialize.h"
#include "utils.h"
#include "tx_types.h"
#include "format.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    buffer_t buf = {.ptr = data, .size = size, .offset = 0};
    transaction_t tx;
    parser_status_e status;
    char nonce[32] = {0};
    char pin_height[32] = {0};
    char address[41] = {0};
    char amount[32] = {0};
    char fee[32] = {0};

    memset(&tx, 0, sizeof(tx));

    status = transaction_deserialize(&buf, &tx);

    if (status == PARSING_OK) {
        format_u64(nonce, sizeof(nonce), tx.nonce);
        printf("nonce: %s\n", nonce);
        format_u64(pin_height, sizeof(pin_height), tx.pin_height);
        printf("pin_height: %s\n", pin_height);
        format_hex(tx.to, ADDRESS_LEN, address, sizeof(address));
        printf("address: %s\n", address);
        format_fpu64(amount, sizeof(amount), tx.value, 8);
        printf("amount: %s\n", amount);
        format_fpu64(fee, sizeof(fee), tx.fee, 8);
        printf("fee: %s\n", fee);
    }

    return 0;
}
