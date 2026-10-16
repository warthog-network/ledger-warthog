/*
 * Unity port of test_tx_parser.c (originally cmocka).
 *
 * SUT: src/transaction/{deserialize,serialize}.c. Per our approach every
 * dependency is a CMock mock, never the real code:
 *   - buffer_read_u32 / buffer_read_u64 / buffer_seek_cur (buffer.h)
 *   - write_u64_be (write.h), varint_size / varint_write (varint.h)
 *     are still stubbed. The native serializer no longer calls them.
 *
 * The buffer/write/varint mocks use CMock _Stub callbacks that faithfully
 * emulate the handful of operations the parser needs (big-endian read/write
 * over the caller's buffer, offset advance, 1-byte varint). This keeps the
 * round-trip and field assertions meaningful while linking no dependency code.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "unity.h"

#include "Mockbuffer.h"
#include "Mockwrite.h"
#include "Mockvarint.h"
#include "Mockutils.h"

#include "transaction/serialize.h"
#include "transaction/deserialize.h"
#include "types.h"

// ---- Knobs to drive the error paths from individual tests ----
static bool g_check_encoding_ret;       // transaction_utils_check_encoding result
static int g_varint_write_ret;          // varint_write result (<0 => write failure)
static bool g_varint_read_fail_huge;    // read_varint: fail AND report a huge memo_len

// ---- Faithful fakes for the mocked dependencies (no SDK code linked) ----

static bool buffer_read_u32_fake(buffer_t *buffer,
                                 uint32_t *value,
                                 endianness_t endianness,
                                 int cmock_num_calls) {
    (void) endianness;
    (void) cmock_num_calls;
    if (buffer->offset + 4 > buffer->size) {
        return false;
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        v = (v << 8) | buffer->ptr[buffer->offset + i];
    }
    *value = v;
    buffer->offset += 4;
    return true;
}

static bool buffer_read_u64_fake(buffer_t *buffer,
                                 uint64_t *value,
                                 endianness_t endianness,
                                 int cmock_num_calls) {
    (void) endianness;  // the parser always reads big-endian
    (void) cmock_num_calls;
    if (buffer->offset + 8 > buffer->size) {
        return false;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | buffer->ptr[buffer->offset + i];
    }
    *value = v;
    buffer->offset += 8;
    return true;
}

static bool buffer_seek_cur_fake(buffer_t *buffer, size_t offset, int cmock_num_calls) {
    (void) cmock_num_calls;
    if (buffer->offset + offset > buffer->size) {
        return false;
    }
    buffer->offset += offset;
    return true;
}

static bool buffer_read_varint_fake(buffer_t *buffer, uint64_t *value, int cmock_num_calls) {
    (void) cmock_num_calls;
    if (g_varint_read_fail_huge) {
        *value = (uint64_t) MAX_MEMO_LEN + 1;  // drive the MEMO_LENGTH_ERROR branch
        return false;
    }
    if (buffer->offset >= buffer->size) {
        return false;
    }
    uint8_t first = buffer->ptr[buffer->offset];
    if (first >= 0xFD) {
        return false;  // multi-byte varints not needed by these vectors
    }
    *value = first;
    buffer->offset += 1;
    return true;
}

static void write_u64_be_fake(uint8_t *ptr, size_t offset, uint64_t value, int cmock_num_calls) {
    (void) cmock_num_calls;
    for (int i = 0; i < 8; i++) {
        ptr[offset + i] = (uint8_t) (value >> (8 * (7 - i)));
    }
}

static uint8_t varint_size_fake(uint64_t value, int cmock_num_calls) {
    (void) cmock_num_calls;
    return (value < 0xFD) ? 1 : 3;
}

static int varint_write_fake(uint8_t *out, size_t offset, uint64_t value, int cmock_num_calls) {
    (void) cmock_num_calls;
    if (g_varint_write_ret < 0) {
        return g_varint_write_ret;  // simulate a write failure
    }
    out[offset] = (uint8_t) value;  // 1-byte varint for value < 0xFD
    return 1;
}

static bool check_encoding_fake(const uint8_t *memo, uint64_t memo_len, int cmock_num_calls) {
    (void) memo;
    (void) memo_len;
    (void) cmock_num_calls;
    return g_check_encoding_ret;
}

void setUp(void) {
    Mockbuffer_Init();
    Mockwrite_Init();
    Mockvarint_Init();
    Mockutils_Init();

    buffer_read_u32_Stub(buffer_read_u32_fake);
    buffer_read_u64_Stub(buffer_read_u64_fake);
    buffer_seek_cur_Stub(buffer_seek_cur_fake);
    buffer_read_varint_Stub(buffer_read_varint_fake);
    write_u64_be_Stub(write_u64_be_fake);
    varint_size_Stub(varint_size_fake);
    varint_write_Stub(varint_write_fake);
    transaction_utils_check_encoding_Stub(check_encoding_fake);

    g_check_encoding_ret = true;
    g_varint_write_ret = 1;
    g_varint_read_fail_huge = false;
}

void tearDown(void) {
    Mockbuffer_Verify();
    Mockwrite_Verify();
    Mockvarint_Verify();
    Mockutils_Verify();

    Mockbuffer_Destroy();
    Mockwrite_Destroy();
    Mockvarint_Destroy();
    Mockutils_Destroy();
}

void test_native_round_trip(void) {
    uint8_t raw[79];
    memset(raw, 0x11, 32);
    raw[32] = 0x00;
    raw[33] = 0x00;
    raw[34] = 0x00;
    raw[35] = 0x07;
    raw[36] = 0x00;
    raw[37] = 0x00;
    raw[38] = 0x00;
    raw[39] = 0x09;
    raw[40] = 0x00;
    raw[41] = 0x00;
    raw[42] = 0x00;
    // fee 100000000 = 0x05f5e100
    raw[43] = 0x00;
    raw[44] = 0x00;
    raw[45] = 0x00;
    raw[46] = 0x00;
    raw[47] = 0x05;
    raw[48] = 0xf5;
    raw[49] = 0xe1;
    raw[50] = 0x00;
    memset(raw + 51, 0xab, 20);
    // amount 250000000 = 0x0ee6b280
    raw[71] = 0x00;
    raw[72] = 0x00;
    raw[73] = 0x00;
    raw[74] = 0x00;
    raw[75] = 0x0e;
    raw[76] = 0xe6;
    raw[77] = 0xb2;
    raw[78] = 0x80;

    transaction_t tx;
    buffer_t buf = {.ptr = raw, .size = sizeof(raw), .offset = 0};
    TEST_ASSERT_EQUAL(PARSING_OK, transaction_deserialize(&buf, &tx, false));
    TEST_ASSERT_EQUAL(7, tx.pin_height);
    TEST_ASSERT_EQUAL(9, tx.nonce);
    TEST_ASSERT_EQUAL(100000000, tx.fee);
    TEST_ASSERT_EQUAL(250000000, tx.value);
    TEST_ASSERT_EQUAL(0x11, tx.pin_hash[0]);
    TEST_ASSERT_EQUAL(0xab, tx.to[0]);
    TEST_ASSERT_EQUAL(0, tx.memo_len);

    uint8_t out[79];
    TEST_ASSERT_EQUAL(79, transaction_serialize(&tx, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(raw, out, sizeof(raw));
}

void test_token_flag_rejected(void) {
    uint8_t raw[79] = {0};
    transaction_t tx;
    buffer_t buf = {.ptr = raw, .size = sizeof(raw), .offset = 0};
    TEST_ASSERT_EQUAL(WRONG_LENGTH_ERROR, transaction_deserialize(&buf, &tx, true));
}

void test_wrong_length_rejected(void) {
    uint8_t raw[80] = {0};
    transaction_t tx;
    buffer_t short_buf = {.ptr = raw, .size = 78, .offset = 0};
    buffer_t long_buf = {.ptr = raw, .size = 80, .offset = 0};
    TEST_ASSERT_EQUAL(WRONG_LENGTH_ERROR, transaction_deserialize(&short_buf, &tx, false));
    TEST_ASSERT_EQUAL(WRONG_LENGTH_ERROR, transaction_deserialize(&long_buf, &tx, false));
}

void test_nonzero_pad_rejected(void) {
    uint8_t raw[79];
    memset(raw, 0x11, 32);
    memset(raw + 32, 0, 47);
    raw[40] = 0x01;
    transaction_t tx;
    buffer_t buf = {.ptr = raw, .size = sizeof(raw), .offset = 0};
    TEST_ASSERT_EQUAL(WRONG_LENGTH_ERROR, transaction_deserialize(&buf, &tx, false));
}

void test_serialize_missing_fields(void) {
    uint8_t pin[32] = {0};
    uint8_t to[ADDRESS_LEN] = {0};
    uint8_t out[79];
    transaction_t tx = {0};
    tx.to = to;
    TEST_ASSERT_EQUAL(-1, transaction_serialize(&tx, out, sizeof(out)));
    tx.pin_hash = pin;
    tx.nonce = 0x100000000ull;
    TEST_ASSERT_EQUAL(-1, transaction_serialize(&tx, out, sizeof(out)));
    tx.nonce = 1;
    TEST_ASSERT_EQUAL(-1, transaction_serialize(&tx, out, 78));
    TEST_ASSERT_EQUAL(79, transaction_serialize(&tx, out, sizeof(out)));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_native_round_trip);
    RUN_TEST(test_token_flag_rejected);
    RUN_TEST(test_wrong_length_rejected);
    RUN_TEST(test_nonzero_pad_rejected);
    RUN_TEST(test_serialize_missing_fields);
    return UNITY_END();
}
