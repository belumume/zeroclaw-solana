# depin-attest reference deployment

This plugin is meant to run on the same small ARM hardware a DePIN node uses, so it is
proven on a real aarch64 host, not only on an x86 dev box.

## Proven on aarch64

The ZeroClaw host and this plugin both build and run on 64-bit ARM. Verified on an
Always-Free ARM VM (4 vCPU, 24 GB, Ubuntu 24.04, `uname -m` = `aarch64`):

- the ZeroClaw host builds from source with `plugins-wasm,plugins-wasm-cranelift`
- `depin-attest` builds from source to `wasm32-wasip2` on the ARM box
- the resulting `.wasm` installs into the ARM host and shows up in `zeroclaw plugin list`

The plugin's `.wasm` is architecture-independent, so the same artifact runs on an ARM host
and an x86 host. Building it on ARM confirms the whole toolchain works there too.

## Reproduce on any aarch64 box

On a fresh aarch64 Ubuntu box (a cloud ARM VM or a Raspberry Pi 4 / 5 / Zero 2):

```
sudo apt-get install -y build-essential clang pkg-config libssl-dev git curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup target add wasm32-wasip2

# host
git clone https://github.com/zeroclaw-labs/zeroclaw.git
cd zeroclaw && cargo build --release --features plugins-wasm,plugins-wasm-cranelift
# Node-only build: this box runs the publisher headless, with no chat channel.
# Building the SHOP host? Add `,whatsapp-web` — it is absent from `default-channels`
# and omitting it drops the WhatsApp channel silently. See QUICKSTART step 1.

# plugin
cd /path/to/depin-attest
cargo build --target wasm32-wasip2 --release
cp target/wasm32-wasip2/release/depin_attest.wasm ./depin_attest.wasm
/path/to/zeroclaw plugin install .
```

## Bring your own Pi (wiring)

The plugin does not read hardware directly. A WASM tool plugin has no GPIO permission by
design, so the physical read happens in the host and the reading arrives as a plain
`execute()` argument. That keeps the plugin's blast radius small and lets a judge host-test
it with a mocked reading, no hardware required.

The mapping for a physical node:

```
  physical sensor            Pi GPIO / host                 depin-attest tool call
  ---------------            --------------                 ----------------------
  PIR motion sensor  ----->  GPIO pin (high on motion) ->   reading = motion_detected
  reed switch (door) ----->  GPIO pin (open/closed)    ->   reading = contact_opened /
                                                                      contact_closed
  tamper switch      ----->  GPIO pin (tamper trip)    ->   reading = tamper_triggered

  the node also passes its own device_id and the observed_at unix time.
```

The host watches the GPIO line, and on an edge it calls the tool:

```
depin_attest_reading(reading = "tamper_triggered", device_id = "<node id>", observed_at = <unix secs>)
```

The plugin then validates the reading against its allowlist, sanitizes the device id, builds
the durable-nonce-fronted attestation, signs it with the operator's scoped session key, and
broadcasts it. The physical part is a single GPIO read; everything after it is the bounded,
replay-proof on-chain path documented in [`README.md`](README.md).
