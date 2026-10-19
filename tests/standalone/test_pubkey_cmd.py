import pytest
from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)
from application_client.boilerplate_currency_utils import (
    WART_PATH,
    WART_PATH_PLAIN_ACCOUNT,
)
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import CurveChoice, calculate_public_key_and_chaincode
from ragger.error import ExceptionRAPDU


def test_get_public_key_no_confirm(backend):
    for path in [WART_PATH, WART_PATH_PLAIN_ACCOUNT]:
        client = BoilerplateCommandSender(backend)
        response = client.get_public_key(path=path).data
        _, public_key, _, chain_code = unpack_get_public_key_response(response)

        ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(
            CurveChoice.Secp256k1, path=path
        )
        assert public_key.hex() == ref_public_key
        assert chain_code.hex() == ref_chain_code


def test_get_public_key_confirm_accepted(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)
    path = WART_PATH

    with client.get_public_key_with_confirmation(path=path):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().data
    _, public_key, _, chain_code = unpack_get_public_key_response(response)

    ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(
        CurveChoice.Secp256k1, path=path
    )
    assert public_key.hex() == ref_public_key
    assert chain_code.hex() == ref_chain_code


def test_get_public_key_confirm_refused(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=WART_PATH):
            scenario_navigator.address_review_reject()

    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_get_public_key_unexpected_path(backend):
    client = BoilerplateCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        client.get_public_key(path="m/44'/1'/0'/0/0")

    assert e.value.status == Errors.SW_INCORRECT_DATA
    assert len(e.value.data) == 0
