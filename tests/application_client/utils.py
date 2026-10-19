import hashlib

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_string


def check_signature_validity(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Check a signature65 (r || s || recid) over SHA-256(message)."""
    if len(public_key) == 65 and public_key[0] == 0x04:
        public_key = public_key[1:]
    if len(public_key) != 64 or len(signature) != 65:
        return False
    pk: VerifyingKey = VerifyingKey.from_string(public_key, curve=SECP256k1)
    digest = hashlib.sha256(message).digest()
    return pk.verify_digest(signature[:64], digest, sigdecode=sigdecode_string)
