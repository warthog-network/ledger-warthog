from .boilerplate_utils import UINT64_MAX, parse_hex_address

UINT32_MAX = 0xFFFFFFFF


class TransactionError(Exception):
    pass


class Transaction:
    """Native WART transfer.

    The serialized body is 79 bytes, big-endian:

    pin_hash(32) || pin_height(4) || nonce(4) || 3 zero bytes || fee(8) || to(20) || amount(8)
    """

    def __init__(
        self,
        pin_hash: bytes,
        pin_height: int,
        nonce: int,
        fee: int,
        to: str | bytes,
        amount: int,
    ) -> None:
        self.pin_hash = pin_hash
        self.pin_height = pin_height
        self.nonce = nonce
        self.fee = fee
        self.to = parse_hex_address(to)
        self.amount = amount

        if len(self.pin_hash) != 32:
            raise TransactionError(f"Bad pin hash length: '{len(self.pin_hash)}'!")

        if not 0 <= self.pin_height <= UINT32_MAX:
            raise TransactionError(f"Bad pin height: '{self.pin_height}'!")

        if not 0 <= self.nonce <= UINT32_MAX:
            raise TransactionError(f"Bad nonce: '{self.nonce}'!")

        if not 0 <= self.fee <= UINT64_MAX:
            raise TransactionError(f"Bad fee: '{self.fee}'!")

        if not 0 <= self.amount <= UINT64_MAX:
            raise TransactionError(f"Bad amount: '{self.amount}'!")

        if len(self.to) != 20:
            raise TransactionError(f"Bad address: '{self.to.hex()}'!")

    def serialize(self) -> bytes:
        return b"".join(
            [
                self.pin_hash,
                self.pin_height.to_bytes(4, byteorder="big"),
                self.nonce.to_bytes(4, byteorder="big"),
                b"\x00\x00\x00",
                self.fee.to_bytes(8, byteorder="big"),
                self.to,
                self.amount.to_bytes(8, byteorder="big"),
            ]
        )
