# Warthog Ledger app — peer review

Version **0.2.0**. This is an unaudited sideload of a C app ported from Ledger's
boilerplate. Ledger's own note on that boilerplate still applies: it is a
reference for maintaining old C apps, and new apps are expected to start from
the Rust boilerplate. Do not treat this build as a released wallet.

Use a **test seed**. Do not put coins you care about on that seed. Delete the
sideload when the review is done.

There is no host wallet in this repo that sends a sign command. Loading the
app and reading version 0.2.0 is the install check. Signing is a separate step,
and only on that test seed.

## What 0.2.0 changes

A native WART transfer is 79 bytes:

`pinHash(32) || pinHeight(4) || nonceId(4) || 3 zero bytes || fee(8) || to(20) || amount(8)`

Amounts are E8 (8 decimal places). The signed message is one SHA-256 of those
79 bytes. The reply is 65 bytes, `r || s || recid`, with `s` in the low half
of the secp256k1 order.

The device shows eight rows before it will sign: From, Path, Amount, Fee, To,
Nonce, Pin height, Pin hash. From is the 48-character address of the key that
will sign. To is the 20-byte destination plus its 4-byte checksum.

Accepted paths are `m/44'/2070'/0'/0/index` and `m/44'/2070'/0/0/index`.
Anything else is rejected. Token, liquidity, limit, cancel, and asset-create
transactions are rejected. Swap stays compiled out because the app name is
Warthog, not Boilerplate.

## Try the vectors on a laptop

From `ledger-warthog`:

```shell
python3 tools/check_wart_vectors.py
gcc -Wall -Wextra -Werror -I src -o /tmp/test_signature65 tools/test_signature65.c src/signature65.c
/tmp/test_signature65
```

The Python script prints a sample transfer and a signature for **private key
1**. That key is a test scalar, not a seed phrase, and it is not on your
Ledger. The sample From address belongs to that key. On a device, From must be
the address of the path on the seed you loaded, not the sample From.

`python3 tools/check_wart_vectors.py --show-sign-apdu` prints the two sign
commands and does not send them.

## Original Nano S

The same sources build for the original Nano S. Set `BOLOS_SDK=$NANOS_SDK`
before `make` and `make load`. That binary is not the Nano S+ binary. A Nano S+
build will not install on a Nano S.

## Load version 0.2.0 on a Nano S+

On this laptop, a page does the same steps. From `ledger-dev`:

```shell
.venv/bin/python ledger_gui.py
```

It opens http://127.0.0.1:8765. Unlock the Nano and stay on the home screen,
then click **Install Warthog**. Approve the prompt on the device. The commands
below are those same steps, written out.

The `bin/` directory may still hold an older build. Run `make` again before
`make load`.

1. Unlock the Nano S+ and leave it on the dashboard. Do not open an app.
2. On this laptop, Docker Desktop's socket is down. Use the system socket:

```shell
cd /home/whitefang/webdev/warthog/ledger-warthog
source ../ledger-dev/env.sh
docker run --rm -ti --user "$(id -u):$(id -g)" --privileged \
  -v /dev/bus/usb:/dev/bus/usb \
  -v "$PWD":/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest
```

This laptop already has `ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder:latest`.
The boilerplate README names `ledger-app-dev-tools` instead. Either image can
build the app. The command above uses the image that is already downloaded.

3. Inside the container, for a Nano S+ (the default):

```shell
make
make load
```

4. Confirm the install on the device when it asks.

If the container cannot open the Nano, install the rules from `ledger-dev`
(mode `0660` and `uaccess`). Do not install the boilerplate file that sets
mode `0666`.

```shell
cd /home/whitefang/webdev/warthog/ledger-dev
sudo ./install-udev.sh
```

Unplug the Nano, plug it back in, unlock the dashboard, and run `make load` again.

On macOS or Windows, build in the container the same way, then on the host:

```shell
python3 -m pip install ledgerblue
python3 -m ledgerblue.runScript --scp --fileName bin/app.apdu --elfFile bin/app.elf
```

## Check that the new app is the one running

Open the Warthog app on the device, then on the host:

```shell
cd /home/whitefang/webdev/warthog/ledger-dev
.venv/bin/python get_version.py
```

That sends only the OS read of the open app. Expect `Warthog 0.2.0`. If it
says the Ledger is locked, unlock it and try again.

The same read, plus the app's own version and name commands, is:

```shell
cd /home/whitefang/webdev/warthog/ledger-warthog
python3 tools/check_wart_vectors.py --device
```

That command refuses every APDU except those three reads.

## What a reviewer should look at

- The eight review rows, and that Reject returns to the menu without a signature.
- From changes when the path's index changes, and a path outside the two
  accepted shapes is refused.
- Amount and fee show 8 decimal places, not the raw E8 integer.
- To is 48 hex characters. The first 40 are the destination. The last 8 are
  the checksum.
- A 79-byte body round-trips. A different length or a non-zero pad is refused.
- `signature65` matches `warthog-js` `Account.sign` on the same 32-byte hash:
  low `s`, and recid bit 0 flipped when a high `s` was normalized.
- The app does not offer swap, and it does not sign any transaction type other
  than the 79-byte native transfer.

Do not approve a transaction unless the rows match the bytes you sent and the
device is on a test seed.

## Remove the sideload

Unlock the dashboard. In the same container:

```shell
make delete
```

You can also uninstall Warthog from the device settings. After that, the
dashboard should not list Warthog.

## Where to write notes

Add a file under [review-notes/](review-notes/README.md), one file per
reviewer, named `yourname.md`. Say what you ran, on which device, and what
you saw. Do not include a seed, a private key, or a signature from a seed
that has ever held funds.
