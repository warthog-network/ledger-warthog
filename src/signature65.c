#include <stddef.h>   // size_t
#include <string.h>   // memmove

#include "signature65.h"

/* secp256k1 order n, and n/2. s <= n/2 is the canonical low-s form. */
static const uint8_t SECP256K1_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
    0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

static const uint8_t SECP256K1_N_HALF[32] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4,
    0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0};

static int cmp32(const uint8_t left[32], const uint8_t right[32]) {
    for (size_t i = 0; i < 32; i++) {
        if (left[i] != right[i]) {
            return left[i] < right[i] ? -1 : 1;
        }
    }
    return 0;
}

static bool is_zero(const uint8_t value[32]) {
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++) {
        acc |= value[i];
    }
    return acc == 0;
}

/* out = left - right. Caller guarantees left >= right. */
static void sub32(uint8_t out[32], const uint8_t left[32], const uint8_t right[32]) {
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int diff = (int) left[i] - (int) right[i] - borrow;
        if (diff < 0) {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = (uint8_t) diff;
    }
}

bool signature65_canonicalize(uint8_t raw[65]) {
    if (raw == NULL) {
        return false;
    }
    uint8_t *r = raw;
    uint8_t *s = raw + 32;

    if (is_zero(r) || is_zero(s) || cmp32(r, SECP256K1_N) >= 0 || cmp32(s, SECP256K1_N) >= 0) {
        return false;
    }
    if (cmp32(s, SECP256K1_N_HALF) > 0) {
        uint8_t low[32] = {0};
        sub32(low, SECP256K1_N, s);
        memmove(s, low, sizeof(low));
        raw[64] ^= 1u;
    }
    return true;
}
