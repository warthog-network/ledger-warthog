#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "transaction/serialize.h"
#include "transaction/deserialize.h"
#include "types.h"

/* Native WART transfer: pinHash || pinHeight || nonce || pad || fee || to || amount. */
static void test_native_round_trip(void **state) {
    (void) state;

    uint8_t raw_tx[79];
    memset(raw_tx, 0x11, 32);
    raw_tx[32] = 0x00;
    raw_tx[33] = 0x00;
    raw_tx[34] = 0x00;
    raw_tx[35] = 0x07;
    raw_tx[36] = 0x00;
    raw_tx[37] = 0x00;
    raw_tx[38] = 0x00;
    raw_tx[39] = 0x09;
    raw_tx[40] = 0x00;
    raw_tx[41] = 0x00;
    raw_tx[42] = 0x00;
    raw_tx[43] = 0x00;
    raw_tx[44] = 0x00;
    raw_tx[45] = 0x00;
    raw_tx[46] = 0x00;
    raw_tx[47] = 0x05;
    raw_tx[48] = 0xf5;
    raw_tx[49] = 0xe1;
    raw_tx[50] = 0x00;
    memset(raw_tx + 51, 0xab, 20);
    raw_tx[71] = 0x00;
    raw_tx[72] = 0x00;
    raw_tx[73] = 0x00;
    raw_tx[74] = 0x00;
    raw_tx[75] = 0x0e;
    raw_tx[76] = 0xe6;
    raw_tx[77] = 0xb2;
    raw_tx[78] = 0x80;

    transaction_t tx;
    buffer_t buf = {.ptr = raw_tx, .size = sizeof(raw_tx), .offset = 0};

    assert_int_equal(transaction_deserialize(&buf, &tx), PARSING_OK);
    assert_int_equal(tx.pin_height, 7);
    assert_int_equal(tx.nonce, 9);
    assert_int_equal(tx.fee, 100000000);
    assert_int_equal(tx.value, 250000000);
    assert_int_equal(tx.memo_len, 0);
    assert_null(tx.token_address);

    uint8_t output[79];
    int length = transaction_serialize(&tx, output, sizeof(output));
    assert_int_equal(length, 79);
    assert_memory_equal(raw_tx, output, sizeof(raw_tx));
}

/* The old nonce||to||value||memo body, and any token body, is the wrong length. */
static void test_old_layout_rejected(void **state) {
    (void) state;

    uint8_t raw_tx[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x7a, 0xc3, 0x39, 0x97, 0x54, 0x4e,
        0x31, 0x75, 0xd2, 0x66, 0xbd, 0x02, 0x24, 0x39, 0xb2, 0x2c, 0xdb, 0x16, 0x50, 0x8c,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x08, 0x07, 0x00,
    };
    transaction_t tx;
    buffer_t buf = {.ptr = raw_tx, .size = sizeof(raw_tx), .offset = 0};

    assert_int_equal(transaction_deserialize(&buf, &tx), WRONG_LENGTH_ERROR);
}

static void test_wrong_length_rejected(void **state) {
    (void) state;

    uint8_t raw[80] = {0};
    transaction_t tx;
    buffer_t short_buf = {.ptr = raw, .size = 78, .offset = 0};
    buffer_t long_buf = {.ptr = raw, .size = 80, .offset = 0};

    assert_int_equal(transaction_deserialize(&short_buf, &tx), WRONG_LENGTH_ERROR);
    assert_int_equal(transaction_deserialize(&long_buf, &tx), WRONG_LENGTH_ERROR);
}

int main(void) {
    const struct CMUnitTest tests[] = {cmocka_unit_test(test_native_round_trip),
                                       cmocka_unit_test(test_old_layout_rejected),
                                       cmocka_unit_test(test_wrong_length_rejected)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
