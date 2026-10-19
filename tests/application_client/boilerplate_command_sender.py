from collections.abc import Generator
from contextlib import contextmanager
from enum import IntEnum

from ragger.backend.interface import RAPDU, BackendInterface
from ragger.bip import pack_derivation_path
from ragger.error import StatusWords

MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class InsType(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_PUBLIC_KEY = 0x05
    SIGN_TX = 0x06


# Custom error codes specific to Boilerplate app
custom_errors = {"SW_INVALID_DYNAMIC_TOKEN": 0xB009, "SW_SWAP_FAIL": 0xC000}

# Build the combined dictionary first
_errors_dict = {m.name: m.value for m in StatusWords}
_errors_dict.update(custom_errors)

# Create the Errors enum
Errors = IntEnum("Errors", _errors_dict)  # type: ignore[misc]


def split_message(message: bytes, max_size: int) -> list[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


class BoilerplateCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=0xB0,  # specific CLA for BOLOS
            ins=0x01,  # specific INS for get_app_and_version
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=b"",
        )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_START, p2=P2.P2_LAST, data=b"")

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_START, p2=P2.P2_LAST, data=b"")

    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=pack_derivation_path(path),
        )

    @contextmanager
    def get_public_key_with_confirmation(self, path: str) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_CONFIRM,
            p2=P2.P2_LAST,
            data=pack_derivation_path(path),
        ) as response:
            yield response

    @contextmanager
    def _sign_transaction(self, ins: InsType, path: str, transaction: bytes) -> Generator[None, None, None]:
        """Send a chunked SIGN_TX. The first APDU is the path. The rest is the body."""
        self.backend.exchange(
            cla=CLA,
            ins=ins,
            p1=P1.P1_START,
            p2=P2.P2_MORE,
            data=pack_derivation_path(path),
        )
        messages = split_message(transaction, MAX_APDU_LEN)
        idx: int = P1.P1_START + 1

        for msg in messages[:-1]:
            self.backend.exchange(cla=CLA, ins=ins, p1=idx, p2=P2.P2_MORE, data=msg)
            idx += 1

        with self.backend.exchange_async(cla=CLA, ins=ins, p1=idx, p2=P2.P2_LAST, data=messages[-1]) as response:
            yield response

    @contextmanager
    def sign_tx(self, path: str, transaction: bytes) -> Generator[None, None, None]:
        with self._sign_transaction(InsType.SIGN_TX, path, transaction) as response:
            yield response

    def get_async_response(self) -> RAPDU | None:
        return self.backend.last_async_response

    def sign_tx_sync(self, path: str, transaction: bytes) -> RAPDU | None:
        with self.sign_tx(path, transaction):
            pass
        rapdu = self.get_async_response()
        assert isinstance(rapdu, RAPDU)
        return rapdu
