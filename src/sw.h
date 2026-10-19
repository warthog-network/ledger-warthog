#pragma once

#if defined(__has_include)
#if __has_include("status_words.h")
#include "status_words.h"
#endif
#endif

/* The original Nano S SDK (API level 24) has SWO_SUCCESS in errors.h and does
 * not ship status_words.h. These are the ISO7816 codes the app already returns
 * on Nano S+ and the other targets. */
#ifndef SWO_SUCCESS
#define SWO_SUCCESS 0x9000
#endif
#ifndef SWO_SECURITY_ISSUE
#define SWO_SECURITY_ISSUE 0x6600
#endif
#ifndef SWO_CONDITIONS_NOT_SATISFIED
#define SWO_CONDITIONS_NOT_SATISFIED 0x6985
#endif
#ifndef SWO_INCORRECT_DATA
#define SWO_INCORRECT_DATA 0x6A80
#endif
#ifndef SWO_INCORRECT_P1_P2
#define SWO_INCORRECT_P1_P2 0x6A86
#endif
#ifndef SWO_WRONG_DATA_LENGTH
#define SWO_WRONG_DATA_LENGTH 0x6A87
#endif
#ifndef SWO_INVALID_INS
#define SWO_INVALID_INS 0x6D00
#endif
#ifndef SWO_INVALID_CLA
#define SWO_INVALID_CLA 0x6E00
#endif

/**
 * Status word for dynamic token TLV parsing/validation failed.
 */
#define SW_INVALID_DYNAMIC_TOKEN 0xB009
/**
 * Status word for swap failure
 */
#define SW_SWAP_FAIL 0xC000

/**
 * Application specific swap error code context
 */
typedef enum swap_error_application_specific_code_t {
    SWAP_ERROR_CODE = 0x00,
    SWAP_ERROR_WRONG_TOKEN_INFO = 0x01,
} swap_error_application_specific_code_t;
