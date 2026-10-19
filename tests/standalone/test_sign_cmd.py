import pytest
from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)
from application_client.boilerplate_currency_utils import WART_PATH
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
    unpack_sign_tx_response,
)
from application_client.boilerplate_transaction import Transaction
from application_client.utils import check_signature_validity
from ragger.error import ExceptionRAPDU

# pin hash 0x11 * 32, pin height 7, nonce 9, fee 1 WART, to 0xab * 20, amount 2.5 WART.
WART_TX = Transaction(
    pin_hash=bytes([0x11]) * 32,
    pin_height=7,
    nonce=9,
    fee=100_000_000,
    to=bytes([0xAB]) * 20,
    amount=250_000_000,
).serialize()


def test_sign_tx_short_tx(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)
    path = WART_PATH

    rapdu = client.get_public_key(path=path)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    with client.sign_tx(path=path, transaction=WART_TX):
        scenario_navigator.review_approve()

    response = client.get_async_response().data
    signature = unpack_sign_tx_response(response)
    assert check_signature_validity(public_key, signature, WART_TX)


def test_sign_tx_refused(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=WART_PATH, transaction=WART_TX):
            scenario_navigator.review_reject()

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_sign_tx_wrong_length(backend):
    client = BoilerplateCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_sync(path=WART_PATH, transaction=b"\x00" * 78)

    assert e.value.status == Errors.SW_INCORRECT_DATA
    assert len(e.value.data) == 0


def test_sign_tx_nonzero_pad(backend):
    client = BoilerplateCommandSender(backend)
    body = bytearray(WART_TX)
    body[40] = 1

    with pytest.raises(ExceptionRAPDU) as e:
        client.sign_tx_sync(path=WART_PATH, transaction=bytes(body))

    assert e.value.status == Errors.SW_INCORRECT_DATA
    assert len(e.value.data) == 0
