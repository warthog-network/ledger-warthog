import hashlib
import re
from pathlib import Path

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_string


# Check a signature65 (r || s || recid) over SHA-256(message).
def check_signature_validity(public_key: bytes, signature: bytes, message: bytes) -> bool:
    # The app returns a 65-byte uncompressed key. ecdsa wants the 64-byte x || y.
    if len(public_key) == 65 and public_key[0] == 0x04:
        public_key = public_key[1:]
    if len(public_key) != 64 or len(signature) != 65:
        return False
    pk: VerifyingKey = VerifyingKey.from_string(public_key, curve=SECP256k1)
    digest = hashlib.sha256(message).digest()
    return pk.verify_digest(signature[:64], digest, sigdecode=sigdecode_string)


def verify_name(name: str) -> None:
    """Verify the app name, based on defines in Makefile

    Args:
        name (str): Name to be checked
    """

    name_str = ""
    lines = _read_makefile()
    name_re = re.compile(r"^APPNAME\s?=\s?\"?(?P<val>\w+)\"?", re.I)
    for line in lines:
        info = name_re.match(line)
        if info:
            dinfo = info.groupdict()
            name_str = dinfo["val"]
    assert name_str == name, f"Expected name {name_str!r}, got {name!r}"


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> list[str]:
    """Read lines from the parent Makefile"""

    parent = Path(__file__).parent.parent.parent.resolve()
    makefile = f"{parent}/Makefile"
    with open(makefile, encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines
