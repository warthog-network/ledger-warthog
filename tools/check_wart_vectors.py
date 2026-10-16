#!/usr/bin/env python3
"""Known answers for a native WART transfer.

Checks the 79-byte body, its SHA-256, and the 48-hex address formula against
the same rules as warthog-js. Signs that hash with a TEST-ONLY private key
(the integer 1) and checks the signature65 form.

This script does not send a sign APDU. --show-sign-apdu only prints bytes.
--device sends two read-only app commands, GET_VERSION and GET_APP_NAME, plus
the OS get-app command. It never asks the Ledger to sign.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

# TEST-ONLY. The integer 1. Not a seed phrase. Never put funds on this key.
TEST_PRIVATE_KEY = 1

PIN_HASH = bytes.fromhex("11" * 32)
PIN_HEIGHT = 7
NONCE = 9
FEE_E8 = 100_000_000  # 1 WART
TO_PAYLOAD = bytes.fromhex("ab" * 20)
AMOUNT_E8 = 250_000_000  # 2.5 WART
PATH = "m/44'/2070'/0'/0/0"

GET_VERSION = bytes.fromhex("e003000000")
GET_APP_NAME = bytes.fromhex("e004000000")
OS_GET_APP = bytes.fromhex("b001000000")
READ_ONLY = {GET_VERSION, GET_APP_NAME, OS_GET_APP}


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % P, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return x3, y3


def _point_mul(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _decompress(x: int, y_odd: int):
    y2 = (pow(x, 3, P) + B) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2:
        return None
    if (y & 1) != y_odd:
        y = P - y
    return x, y


def recover_public_key(digest: bytes, r: int, s: int, recid: int):
    x = r + (recid // 2) * N
    if x >= P:
        return None
    point_r = _decompress(x, recid & 1)
    if point_r is None:
        return None
    e = int.from_bytes(digest, "big")
    s_r = _point_mul(s, point_r)
    e_g = _point_mul(e, (GX, GY))
    if e_g is None or s_r is None:
        return None
    summed = _point_add(s_r, (e_g[0], (-e_g[1]) % P))
    return _point_mul(pow(r, -1, N), summed)


def native_body() -> bytes:
    body = b"".join(
        [
            PIN_HASH,
            PIN_HEIGHT.to_bytes(4, "big"),
            NONCE.to_bytes(4, "big"),
            b"\x00\x00\x00",
            FEE_E8.to_bytes(8, "big"),
            TO_PAYLOAD,
            AMOUNT_E8.to_bytes(8, "big"),
        ]
    )
    if len(body) != 79:
        raise RuntimeError(f"native body is {len(body)} bytes")
    return body


def address_from_uncompressed(public_key: bytes) -> str:
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise RuntimeError("public key is not 04 || X || Y")
    prefix = 0x03 if public_key[64] & 1 else 0x02
    compressed = bytes([prefix]) + public_key[1:33]
    payload = hashlib.new("ripemd160", hashlib.sha256(compressed).digest()).digest()
    checksum = hashlib.sha256(payload).digest()[:4]
    return (payload + checksum).hex()


def signature65(private_key, digest: bytes) -> str:
    der = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    if s > N // 2:
        s = N - s
    public_numbers = private_key.public_key().public_numbers()
    found = None
    for recid in range(4):
        point = recover_public_key(digest, r, s, recid)
        if point == (public_numbers.x, public_numbers.y):
            found = recid
            break
    if found is None:
        raise RuntimeError("could not recover the test public key from the signature")
    low_der = encode_dss_signature(r, s)
    private_key.public_key().verify(low_der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    return f"{r:064x}{s:064x}{found:02x}"


def decode_dss_signature(der: bytes):
    return utils.decode_dss_signature(der)


def encode_dss_signature(r: int, s: int) -> bytes:
    return utils.encode_dss_signature(r, s)


def check_vectors() -> dict[str, str]:
    private_key = ec.derive_private_key(TEST_PRIVATE_KEY, ec.SECP256K1())
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    body = native_body()
    digest = hashlib.sha256(body).digest()
    sender = address_from_uncompressed(public_key)
    to_checksum = hashlib.sha256(TO_PAYLOAD).digest()[:4]
    to_address = (TO_PAYLOAD + to_checksum).hex()
    sig = signature65(private_key, digest)
    if len(sig) != 130:
        raise RuntimeError("signature65 must be 65 bytes, 130 hex characters")
    return {
        "body": body.hex(),
        "hash": digest.hex(),
        "from": sender,
        "to": to_address,
        "signature65": sig,
    }


def sign_apdus(body: bytes) -> tuple[bytes, bytes]:
    # m/44'/2070'/0'/0/0
    path = bytes.fromhex("058000002c80000816800000000000000000000000")
    first = bytes.fromhex("e0060080") + bytes([len(path)]) + path
    second = bytes.fromhex("e0060100") + bytes([len(body)]) + body
    return first, second


def print_review(vectors: dict[str, str]) -> None:
    print("TEST-ONLY key: private scalar 1. Do not fund this key.")
    print(f"From       {vectors['from']}")
    print(f"Path       {PATH}")
    print("Amount     2.5 WART")
    print("Fee        1 WART")
    print(f"To         {vectors['to']}")
    print(f"Nonce      {NONCE}")
    print(f"Pin height {PIN_HEIGHT}")
    print(f"Pin hash   {PIN_HASH.hex()}")
    print(f"Body       {vectors['body']}")
    print(f"SHA-256    {vectors['hash']}")
    print(f"signature65 {vectors['signature65']}")


def print_sign_apdu(body: bytes) -> None:
    first, second = sign_apdus(body)
    print("These APDUs are not sent.")
    print(f"path APDU  {first.hex()}")
    print(f"body APDU  {second.hex()}")
    print("Approve on the device only when every review row matches the lines above")
    print("and the Ledger is using a test seed with no funds you care about.")


def _status(reply: bytes) -> bytes:
    if len(reply) < 2:
        raise RuntimeError("reply is too short")
    return reply[-2:]


def query_device(serial: str | None) -> int:
    ledger_dev = Path(__file__).resolve().parents[2] / "ledger-dev"
    sys.path.insert(0, str(ledger_dev))
    from ledger_hid import LedgerError, open_ledger, parse_app, read_apdu, write_apdu

    def exchange(apdu: bytes) -> bytes:
        if apdu not in READ_ONLY:
            raise RuntimeError("refusing to send anything except a read-only query")
        write_apdu(dev, apdu, allow_other=apdu != OS_GET_APP)
        return read_apdu(dev)

    try:
        dev = open_ledger(serial=serial)
    except LedgerError as exc:
        print(exc)
        return 1
    try:
        try:
            print("OS app    ", parse_app(exchange(OS_GET_APP)))
        except LedgerError as exc:
            print(f"OS app     {exc}")
            return 1
        version = exchange(GET_VERSION)
        if _status(version) != b"\x90\x00" or len(version) != 5:
            print(f"GET_VERSION status {version.hex()}")
            return 1
        major, minor, patch = version[0], version[1], version[2]
        name = exchange(GET_APP_NAME)
        if _status(name) != b"\x90\x00":
            print(f"GET_APP_NAME status {name.hex()}")
            return 1
        app_name = name[:-2].decode("ascii", "replace")
        print(f"App        {app_name} {major}.{minor}.{patch}")
        if app_name != "Warthog" or (major, minor, patch) != (0, 2, 0):
            print("Expected the open app to be Warthog 0.2.0.")
            return 1
    finally:
        dev.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Warthog transfer vectors. Does not sign on a device.")
    parser.add_argument("--show-sign-apdu", action="store_true", help="Print the sign APDUs. Does not send them.")
    parser.add_argument("--device", action="store_true", help="Read the open app name and version only.")
    parser.add_argument("--serial", help="USB serial when more than one Ledger is plugged in.")
    args = parser.parse_args(argv)

    vectors = check_vectors()
    print_review(vectors)
    if args.show_sign_apdu:
        print_sign_apdu(bytes.fromhex(vectors["body"]))
    if args.device:
        return query_device(args.serial)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - report the vector failure and stop
        print(exc)
        sys.exit(1)
