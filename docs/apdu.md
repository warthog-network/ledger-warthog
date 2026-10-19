# Warthog APDU

CLA is `0xE0`. The OS `get-app` command uses CLA `0xB0` and is not one of these instructions.

A native transfer is the only transaction this app signs. INS `0x07` and INS `0x22`
are not commands. They return `0x6D00`.

## Commands

| CLA | INS | Name | P1 | P2 | Data |
| --- | --- | --- | --- | --- | --- |
| `E0` | `03` | GET_VERSION | `00` | `00` | empty |
| `E0` | `04` | GET_APP_NAME | `00` | `00` | empty |
| `E0` | `05` | GET_PUBLIC_KEY | `00` return, `01` confirm on screen | `00` | BIP32 path |
| `E0` | `06` | SIGN_TX | chunk index, `00` on the first APDU | `80` if more follow, `00` on the last | first APDU: path. Later APDUs: transfer bytes |

The first SIGN_TX APDU must use P1 `00` and P2 `80`. P1 must be at most `03`. P2 must be `00` or `80`.

## BIP32 path

The path data is one length byte, then each index as a 4-byte big-endian integer.

Accepted paths are `m/44'/2070'/0'/0/index` and `m/44'/2070'/0/0/index`.
The index is not hardened. Any other path returns `0x6A80`.

## Native transfer

The body is 79 bytes, big-endian:

| Field | Bytes |
| --- | --- |
| pin hash | 32 |
| pin height | 4 |
| nonce | 4 |
| zeros | 3 |
| fee | 8 |
| destination | 20 |
| amount | 8 |

Amounts are E8: 1 WART is `100000000`. A body of any other length, or a non-zero pad,
returns `0x6A80` and the device does not ask for a signature.

The device shows From, Path, Amount, Fee, To, Nonce, Pin height, and Pin hash.
Reject returns `0x6985` and no signature.

## Responses

GET_VERSION returns three bytes: major, minor, patch.

GET_APP_NAME returns the ASCII name.

GET_PUBLIC_KEY returns `pubkey_len` (1, value 65), the 65-byte uncompressed key,
`chaincode_len` (1, value 32), and the 32-byte chain code.

SIGN_TX returns 65 bytes: `r` (32) || `s` (32) || `recid` (1). `s` is in the low
half of the secp256k1 order. The signed message is one SHA-256 of the 79-byte body.

## Status words

| SW | Meaning |
| --- | --- |
| `9000` | Success |
| `6985` | User rejected the review |
| `6600` | Signature length was not 65 bytes |
| `6A80` | The path or the transfer body was rejected |
| `6A86` | P1 or P2 is not valid for this command |
| `6A87` | The APDU data has the wrong length |
| `6D00` | Unknown INS |
| `6E00` | CLA is not `E0` |
