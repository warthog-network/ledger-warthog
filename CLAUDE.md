# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ledger AI instructions submodule

Generic, cross-repo Ledger embedded-app rules live in the `ledger-app-ai-instructions` submodule
(top-level directory), imported via the `@ledger-app-ai-instructions/CLAUDE.md` line above. It carries
`EMBEDDED.instructions.md`, `RUST.instructions.md`, `C.instructions.md`, `TEST.instructions.md`, and
`REVIEW.instructions.md`. `.github/instructions` is a symlink into `ledger-app-ai-instructions/instructions`
so GitHub Copilot picks up the same files. Run `git submodule update --init` after cloning, or both the
import and the symlink will dangle. Keep this `CLAUDE.md` limited to app-specific guidance; contribute
cross-repo rules to the submodule instead.

@ledger-app-ai-instructions/CLAUDE.md

## What this repo is

Warthog Ledger app written in Rust on top of `app-boilerplate-rust`. It targets Nano X, Nano S+, Stax, Flex, and Apex P. It is a `#![no_std]` / `#![no_main]` binary built against `ledger_device_sdk`. Nano S is **not** supported. Exchange swap is **not** enabled: `sample_main` exits when `arg0 != 0` and does not sign.

The wire interface matches the 0.2.0 C app. The spec is `docs/apdu.md`. Package version `0.3.0` is the Rust port of that app.

## Architecture

### APDU dispatch

1. `Comm` receives an APDU with `CLA=0xe0`; wrong-CLA APDUs are rejected by the SDK (`comm.set_expected_cla(0xe0)`).
2. `Instruction::try_from(ApduHeader)` in `src/main.rs` parses `(INS, P1, P2)`. Invalid P1/P2 → `AppSW::WrongP1P2` (`0x6A86`); unknown INS → `AppSW::InsNotSupported` (`0x6D00`).
3. `handle_apdu` routes to a handler in `src/handlers/`. Handlers return `Result<CommandResponse, AppSW>`.
4. Status words match the C app: `0x6985` deny / bad sign state, `0x6A80` bad path or transfer body, `0x6A87` bad APDU length, `0x6600` signature failure, `0x9000` ok.
5. After `GetPubkey { display: true }` and a completed `SignTx` review, `show_status_and_home_if_needed` shows the NBGL status screen and returns home.

### Paths, transfer, signature

Accepted paths are `m/44'/2070'/0'/0/index` and `m/44'/2070'/0/0/index`. The index is not hardened. Anything else is `0x6A80`.

`SignTx` chunks live in `TxContext` (`src/handlers/sign_tx.rs`):

- `P1=0, P2=0x80` — BIP32 path only. Resets the context.
- `P1=1..=3, P2=0x80` — more body bytes.
- `P1=1..=3, P2=0x00` — last chunk. Body must be 79 bytes with a zero pad, or the app returns `0x6A80` and shows nothing.
- A body chunk before chunk 0 returns `0x6985`.

The body is `pin hash (32) || pin height (4) || nonce (4) || 3 zero bytes || fee (8) || to (20) || amount (8)`. Amounts are E8. The review shows From, Path, Amount, Fee, To, Nonce, Pin height, and Pin hash.

Address = `RIPEMD160(SHA256(compressed pubkey)) || SHA256(payload)[0..4]` (24 bytes, 48 hex characters). The destination field is the 20-byte payload; the device appends the checksum before display.

Hash = SHA-256 of the raw 79-byte body. Signature = secp256k1 RFC6979, returned as 65 bytes `r || s || recid` with low `s`. `recid` bit 1 (`r.x > n`) is not available from `deterministic_sign` in this SDK.

### UI (NBGL)

- Home: `NbglHomeAndSettings` in `src/app_ui/menu.rs`, stored on `TxContext` and re-shown after each review.
- Address / transaction review: `src/app_ui/address.rs` and `src/app_ui/sign.rs`. `NbglReview` does not forward the C app's `wrapping` flag, so the 64-character pin hash can be clipped on Nano.
- Icons are still the boilerplate crab glyphs. `build.rs` pre-processes `icons/crab_14x14.gif` + `icons/mask_14x14.gif` into `glyphs/home_nano_nbgl.png`.

### Settings (NVM)

`src/settings.rs` still reserves a 10-byte `AtomicStorage` in `.nvm_data`. The home screen does not expose a switch. Do not store secrets there.

## App-specific embedded notes (when editing Rust code)

The generic embedded/Rust rules are imported above; the points below are this app's concrete conventions:

- `#![no_std]` — `extern crate alloc` is declared in `main.rs`; use `alloc::{vec::Vec, string::String, format}`. Never reference `std::`.
- Treat APDU bytes as untrusted input — validate lengths and structure before parsing.
- Secrets derived from the seed must never be stored, exported, or shown to the user. Sensitive buffers should be zeroed after use.
- Use `ledger_device_sdk::log::debug!` liberally around APDU entry points, crypto calls, and parsing — these are the only way to debug on Speculos.
- Any signing or pubkey-export flow must be gated by an explicit user-validation screen. Do not introduce blind-signing paths.

## Test client layout

- `tests/application_client/` — Python `BoilerplateCommandSender` (APDU construction) and response unpacker.
- `tests/standalone/` — pytest suite for a normal dashboard launch. Screenshot baselines are still the old boilerplate images and must be regenerated.
- `tests/swap/` is leftover boilerplate and is not registered in `ledger_app.toml`. Do not turn Exchange signing back on.
- Tests must construct APDU payloads with named variables and `struct.pack` — no raw hex literals.

