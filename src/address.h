#pragma once

#include <stdint.h>   // uint*_t
#include <stddef.h>   // size_t
#include <stdbool.h>  // bool

/** 20-byte hash160 payload plus a 4-byte SHA-256 checksum. 48 hex characters. */
#define WART_ADDRESS_LEN 24

/**
 * Warthog address from an uncompressed secp256k1 public key (0x04 || X || Y).
 *
 * payload = RIPEMD160(SHA256(compressed pubkey))
 * address = payload || SHA256(payload)[0:4]
 *
 * @return true if success, false otherwise.
 */
bool address_from_pubkey(const uint8_t public_key[static 65], uint8_t *out, size_t out_len);

/**
 * Append the 4-byte SHA-256 checksum to a 20-byte address payload.
 * out is payload || SHA256(payload)[0:4].
 */
bool wart_address_from_payload(const uint8_t payload[static 20], uint8_t *out, size_t out_len);

/**
 * Accept the two mobile-wallet paths:
 * m/44'/2070'/0'/0/index and m/44'/2070'/0/0/index.
 */
bool wart_path_ok(const uint32_t *path, uint8_t len);
