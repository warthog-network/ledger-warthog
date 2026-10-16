/*
 * Unit tests for src/address.c.
 *
 * A Warthog address is RIPEMD160(SHA256(compressed pubkey)) plus the first
 * four bytes of SHA256(payload). The cx hash syscalls are stubbed here. The
 * known-answer check of the real hashes is tools/check_wart_vectors.py.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>

#include "unity.h"

#include "Mockledger_assert_internals.h"
#include "Mocklcx_sha3.h"
#include "lcx_sha256.h"
#include "lcx_ripemd160.h"

#include "address.h"

static const uint8_t PUBLIC_KEY[65] = {0x04, 0x01, 0x02, 0x03};

static const uint8_t FAKE_SHA[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static const uint8_t FAKE_RIPEMD[20] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
    0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3};

static const uint8_t FAKE_CHECK[32] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca,
    0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5,
    0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf};

static cx_err_t g_init_ret;
static cx_err_t g_hash_ret;
static int g_hash_calls;
static uint8_t g_compressed_prefix;
static bool g_hash_input_ok;

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void) hash;
    return g_init_ret;
}

cx_err_t cx_ripemd160_init_no_throw(cx_ripemd160_t *hash) {
    (void) hash;
    return g_init_ret;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash,
                          uint32_t mode,
                          const uint8_t *in,
                          size_t len,
                          uint8_t *out,
                          size_t out_len) {
    (void) hash;
    (void) mode;
    g_hash_calls++;
    if (g_hash_ret != CX_OK) {
        return g_hash_ret;
    }
    if (out_len == 32 && len == 33) {
        g_compressed_prefix = in[0];
        memcpy(out, FAKE_SHA, sizeof(FAKE_SHA));
        return CX_OK;
    }
    if (out_len == 20 && len == 32) {
        if (memcmp(in, FAKE_SHA, sizeof(FAKE_SHA)) != 0) {
            g_hash_input_ok = false;
        }
        memcpy(out, FAKE_RIPEMD, sizeof(FAKE_RIPEMD));
        return CX_OK;
    }
    if (out_len == 32 && len == 20) {
        if (memcmp(in, FAKE_RIPEMD, sizeof(FAKE_RIPEMD)) != 0) {
            g_hash_input_ok = false;
        }
        memcpy(out, FAKE_CHECK, sizeof(FAKE_CHECK));
        return CX_OK;
    }
    g_hash_input_ok = false;
    return CX_INVALID_PARAMETER;
}

void setUp(void) {
    Mockledger_assert_internals_Init();
    Mocklcx_sha3_Init();
    g_init_ret = CX_OK;
    g_hash_ret = CX_OK;
    g_hash_calls = 0;
    g_compressed_prefix = 0;
    g_hash_input_ok = true;
}

void tearDown(void) {
    Mockledger_assert_internals_Verify();
    Mocklcx_sha3_Verify();

    Mockledger_assert_internals_Destroy();
    Mocklcx_sha3_Destroy();
}

static jmp_buf g_assert_jmp;

static void assert_exit_cb(bool confirm, int cmock_num_calls) {
    (void) confirm;
    (void) cmock_num_calls;
    longjmp(g_assert_jmp, 1);
}

void test_address_from_pubkey_null_out(void) {
    assert_exit_AddCallback(assert_exit_cb);
    assert_exit_ExpectAnyArgs();

    if (setjmp(g_assert_jmp) == 0) {
        address_from_pubkey(PUBLIC_KEY, NULL, 0);
        TEST_FAIL_MESSAGE("address_from_pubkey should not return on NULL out");
    }
}

void test_address_from_pubkey_success(void) {
    uint8_t out[WART_ADDRESS_LEN] = {0};
    uint8_t expected[WART_ADDRESS_LEN] = {0};

    bool ok = address_from_pubkey(PUBLIC_KEY, out, sizeof(out));

    memcpy(expected, FAKE_RIPEMD, sizeof(FAKE_RIPEMD));
    memcpy(expected + sizeof(FAKE_RIPEMD), FAKE_CHECK, 4);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL(0x02, g_compressed_prefix);
    TEST_ASSERT_EQUAL(3, g_hash_calls);
    TEST_ASSERT_TRUE(g_hash_input_ok);
    TEST_ASSERT_EQUAL_MEMORY(expected, out, WART_ADDRESS_LEN);
}

void test_address_from_pubkey_odd_y_uses_prefix_03(void) {
    uint8_t key[65] = {0};
    uint8_t out[WART_ADDRESS_LEN] = {0};

    key[0] = 0x04;
    key[64] = 0x01;
    TEST_ASSERT_TRUE(address_from_pubkey(key, out, sizeof(out)));
    TEST_ASSERT_EQUAL(0x03, g_compressed_prefix);
}

void test_address_from_pubkey_buffer_too_small(void) {
    uint8_t out[WART_ADDRESS_LEN - 1] = {0};
    bool ok = address_from_pubkey(PUBLIC_KEY, out, sizeof(out));

    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_EQUAL(0, g_hash_calls);
}

void test_address_from_pubkey_rejects_compressed_key(void) {
    uint8_t key[65] = {0};
    uint8_t out[WART_ADDRESS_LEN] = {0};

    key[0] = 0x02;
    TEST_ASSERT_FALSE(address_from_pubkey(key, out, sizeof(out)));
    TEST_ASSERT_EQUAL(0, g_hash_calls);
}

void test_address_from_pubkey_hash_failure(void) {
    uint8_t out[WART_ADDRESS_LEN] = {0};

    g_hash_ret = CX_INVALID_PARAMETER;
    TEST_ASSERT_FALSE(address_from_pubkey(PUBLIC_KEY, out, sizeof(out)));
    TEST_ASSERT_EQUAL(1, g_hash_calls);
}

void test_address_from_pubkey_init_failure(void) {
    uint8_t out[WART_ADDRESS_LEN] = {0};

    g_init_ret = CX_INVALID_PARAMETER;
    TEST_ASSERT_FALSE(address_from_pubkey(PUBLIC_KEY, out, sizeof(out)));
    TEST_ASSERT_EQUAL(0, g_hash_calls);
}

void test_wart_address_from_payload(void) {
    uint8_t payload[20];
    uint8_t out[WART_ADDRESS_LEN] = {0};
    uint8_t short_out[WART_ADDRESS_LEN - 1] = {0};

    memcpy(payload, FAKE_RIPEMD, sizeof(payload));
    TEST_ASSERT_FALSE(wart_address_from_payload(payload, NULL, WART_ADDRESS_LEN));
    TEST_ASSERT_FALSE(wart_address_from_payload(payload, short_out, sizeof(short_out)));
    TEST_ASSERT_EQUAL(0, g_hash_calls);

    TEST_ASSERT_TRUE(wart_address_from_payload(payload, out, sizeof(out)));
    TEST_ASSERT_EQUAL(1, g_hash_calls);
    TEST_ASSERT_TRUE(g_hash_input_ok);
    TEST_ASSERT_EQUAL_MEMORY(FAKE_RIPEMD, out, 20);
    TEST_ASSERT_EQUAL_MEMORY(FAKE_CHECK, out + 20, 4);
}

void test_wart_path_ok(void) {
    const uint32_t hardened = 0x80000000u;
    uint32_t phone[5] = {hardened | 44u, hardened | 2070u, hardened | 0u, 0u, 0u};
    uint32_t other[5] = {hardened | 44u, hardened | 2070u, 0u, 0u, 3u};

    TEST_ASSERT_TRUE(wart_path_ok(phone, 5));
    TEST_ASSERT_TRUE(wart_path_ok(other, 5));
    TEST_ASSERT_FALSE(wart_path_ok(NULL, 5));
    TEST_ASSERT_FALSE(wart_path_ok(phone, 4));

    phone[1] = hardened | 60u;
    TEST_ASSERT_FALSE(wart_path_ok(phone, 5));
    phone[1] = hardened | 2070u;
    phone[2] = hardened | 1u;
    TEST_ASSERT_FALSE(wart_path_ok(phone, 5));
    phone[2] = hardened | 0u;
    phone[3] = 1u;
    TEST_ASSERT_FALSE(wart_path_ok(phone, 5));
    phone[3] = 0u;
    phone[4] = hardened | 1u;
    TEST_ASSERT_FALSE(wart_path_ok(phone, 5));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_address_from_pubkey_null_out);
    RUN_TEST(test_address_from_pubkey_success);
    RUN_TEST(test_address_from_pubkey_odd_y_uses_prefix_03);
    RUN_TEST(test_address_from_pubkey_buffer_too_small);
    RUN_TEST(test_address_from_pubkey_rejects_compressed_key);
    RUN_TEST(test_address_from_pubkey_hash_failure);
    RUN_TEST(test_address_from_pubkey_init_failure);
    RUN_TEST(test_wart_address_from_payload);
    RUN_TEST(test_wart_path_ok);

    return UNITY_END();
}
