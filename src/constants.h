#pragma once

/**
 * Instruction class of the Warthog application.
 */
#define CLA 0xE0

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Maximum transaction length (bytes).
 */
#define MAX_TRANSACTION_LEN 510

/**
 * Maximum signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72

/**
 * WART amounts are E8: 1 WART = 100000000 units.
 */
#define WART_DECIMALS 8

/**
 * Kept so the boilerplate display helpers still compile. Warthog uses WART_DECIMALS.
 */
#define EXPONENT_SMALLEST_UNIT WART_DECIMALS

/**
 * SLIP-44 coin type 2070, the path the mobile wallet uses for Warthog.
 */
#define WARTHOG_COIN_TYPE 2070

/**
 * Hardened Warthog coin type (0x80000816).
 */
#define WARTHOG_COIN_TYPE_HARDENED (0x80000000u | WARTHOG_COIN_TYPE)
