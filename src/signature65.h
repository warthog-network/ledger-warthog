#pragma once

#include <stdbool.h>  // bool
#include <stdint.h>   // uint8_t

/**
 * r || s || recid, matching warthog-js signature65.
 * recid bit 0 is y parity. recid bit 1 is set when r.x > n.
 * On success, s is in the low half of the secp256k1 order.
 * A high s is replaced with n - s and bit 0 of recid is flipped.
 */
bool signature65_canonicalize(uint8_t raw[65]);
