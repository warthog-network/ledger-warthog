use crate::app_ui::sign::ui_display_tx;
use crate::crypto::{address_from_payload, address_from_pubkey, sign_hash};
use crate::tx::parse_native_tx;
use crate::utils::{get_pubkey_from_path, Bip32Path};
use crate::AppSW;
use alloc::vec::Vec;
use ledger_device_sdk::hash::sha2::Sha2_256;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::io::{Command, CommandResponse};
use ledger_device_sdk::log;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

const MAX_TRANSACTION_LEN: usize = 510;

/// Transaction context holding state between APDU chunks.
pub struct TxContext {
    raw_tx: Vec<u8>,
    path: Bip32Path,
    /// True after a valid chunk 0. Later chunks are rejected until then.
    started: bool,
    review_finished: bool,
    pub home: NbglHomeAndSettings,
}

impl TxContext {
    pub fn new() -> TxContext {
        TxContext {
            raw_tx: Vec::new(),
            path: Default::default(),
            started: false,
            review_finished: false,
            home: Default::default(),
        }
    }

    pub fn finished(&self) -> bool {
        self.review_finished
    }

    fn reset(&mut self) {
        self.raw_tx.clear();
        self.path = Default::default();
        self.started = false;
        self.review_finished = false;
    }
}

/// SIGN_TX. Chunk 0 is the BIP32 path. Later chunks append the 79-byte body.
/// The last chunk parses, shows the review, and on approval returns signature65.
pub fn handler_sign_tx<'a>(
    command: Command<'a>,
    chunk: u8,
    more: bool,
    ctx: &mut TxContext,
) -> Result<CommandResponse<'a>, AppSW> {
    log::debug!("=> handler_sign_tx");
    let data = command.get_data();
    if chunk == 0 {
        log::debug!("Chunk 0: path");
        ctx.reset();
        ctx.path = data.try_into()?;
        ctx.started = true;
        Ok(command.into_response())
    } else {
        if !ctx.started {
            return Err(AppSW::Deny);
        }
        if ctx.raw_tx.len() + data.len() > MAX_TRANSACTION_LEN {
            return Err(AppSW::WrongDataLength);
        }
        ctx.raw_tx.extend_from_slice(data);

        if more {
            ctx.review_finished = false;
            Ok(command.into_response())
        } else {
            log::debug!("Last chunk, parsing native transfer");
            let tx = parse_native_tx(&ctx.raw_tx).ok_or(AppSW::IncorrectData)?;
            let pubkey = get_pubkey_from_path(&ctx.path)?;
            let from = address_from_pubkey(&pubkey)?;
            let to = address_from_payload(&tx.to)?;

            let mut hasher = Sha2_256::new();
            let mut message_hash = [0u8; 32];
            hasher
                .hash(&ctx.raw_tx, &mut message_hash)
                .map_err(|_| AppSW::IncorrectData)?;

            let comm = command.into_comm();
            if ui_display_tx(comm, &tx, ctx.path.as_ref(), &from, &to)? {
                ctx.review_finished = true;
                let signature = sign_hash(ctx.path.as_ref(), &message_hash)?;
                if signature.len() != 65 {
                    return Err(AppSW::SecurityIssue);
                }
                let mut response = comm.begin_response();
                response.append(&signature)?;
                Ok(response)
            } else {
                ctx.review_finished = true;
                Err(AppSW::Deny)
            }
        }
    }
}
