/* Host checks for signature65_canonicalize. No SDK and no device. */

#include <stdio.h>
#include <string.h>

#include "signature65.h"

static int g_failed;

static void expect(int cond, const char *name) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        g_failed = 1;
    }
}

static void set32(uint8_t out[32], const uint8_t in[32]) {
    memcpy(out, in, 32);
}

int main(void) {
    const uint8_t n_minus_1[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                   0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
                                   0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40};
    const uint8_t n_half[32] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4,
                                0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0};
    const uint8_t n_value[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48,
                                 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};
    uint8_t raw[65];

    expect(!signature65_canonicalize(NULL), "null");

    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    raw[63] = 1;
    raw[64] = 0;
    expect(signature65_canonicalize(raw), "low s");
    expect(raw[63] == 1 && raw[64] == 0, "low s unchanged");

    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    set32(raw + 32, n_minus_1);
    raw[64] = 0;
    expect(signature65_canonicalize(raw), "high s");
    expect(raw[63] == 1 && raw[32] == 0 && raw[64] == 1, "high s flipped");

    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    set32(raw + 32, n_minus_1);
    raw[64] = 3;
    expect(signature65_canonicalize(raw), "high s keeps x>n bit");
    expect(raw[64] == 2, "only parity bit flips");

    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    set32(raw + 32, n_half);
    raw[64] = 1;
    expect(signature65_canonicalize(raw), "s == n/2");
    expect(raw[64] == 1 && memcmp(raw + 32, n_half, 32) == 0, "n/2 stays");

    memset(raw, 0, sizeof(raw));
    raw[63] = 1;
    expect(!signature65_canonicalize(raw), "r == 0");

    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    expect(!signature65_canonicalize(raw), "s == 0");

    memset(raw, 0, sizeof(raw));
    raw[31] = 1;
    set32(raw + 32, n_value);
    expect(!signature65_canonicalize(raw), "s == n");

    memset(raw, 0, sizeof(raw));
    set32(raw, n_value);
    raw[63] = 1;
    expect(!signature65_canonicalize(raw), "r == n");

    if (g_failed) {
        return 1;
    }
    puts("signature65 ok");
    return 0;
}
