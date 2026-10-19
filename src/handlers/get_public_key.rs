use crate::app_ui::address::ui_display_pk;
use crate::crypto::address_from_pubkey;
use crate::utils::{get_pubkey_from_path, Bip32Path};
use crate::AppSW;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};
use ledger_device_sdk::io::{Command, CommandResponse};
use ledger_device_sdk::log;

/// GET_PUBLIC_KEY. Derives the key for a Warthog path and, when P1 is 1, asks
/// the user to confirm the 48-character address before returning it.
pub fn handler_get_public_key(
    command: Command<'_>,
    display: bool,
) -> Result<CommandResponse<'_>, AppSW> {
    log::debug!("=> handler_get_public_key");
    let data = command.get_data();
    let path: Bip32Path = data.try_into()?;

    let pubkey = get_pubkey_from_path(&path)?;
    let (_, cc) = Secp256k1::derive_from(path.as_ref());

    let comm = command.into_comm();
    if display {
        let address = address_from_pubkey(&pubkey)?;
        if !ui_display_pk(comm, &address)? {
            return Err(AppSW::Deny);
        }
    }

    let mut response = comm.begin_response();
    response.append(&[pubkey.len() as u8])?;
    response.append(&pubkey)?;

    const CHAINCODE_LEN: u8 = 32;
    let code = cc.ok_or(AppSW::IncorrectData)?;
    response.append(&[CHAINCODE_LEN])?;
    response.append(&code.value)?;

    Ok(response)
}
