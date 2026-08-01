"""Certify-then-broadcast: the host side of the T1 oracle-publish path.

This is the call site for `certify_publish_tx`. It exists as a tracked script because
a certifier nobody calls is a library, not a defense, and the difference matters to
anyone auditing this.

The threat it answers is not a stolen key. When an agent builds a transaction and asks a
human to approve it, the sentence the human reads was written by the model. Influence the
model and you influence the description, so an attacker does not need the signing key, only
an operator who reads one plausible sentence and says yes.

The publish path is allowed to express exactly one intent, so it never asks. Before any
bytes leave the machine, the exact serialized transaction is re-derived from the wire and
checked: instruction 0 must be a System AdvanceNonceAccount, instruction 1 must be our
oracle program's publish_reading touching our feed PDA, and there must be no third
instruction. An appended transfer, a swapped program, or a spoofed feed is refused. The
check trusts neither the model, nor the plugin, nor the wire.

Where intent is variable (a spend), this shape does not apply, and the bound is the audited
Allowances program on chain instead. See docs/WRITEUP.md.

Takes the plugin's base64 partial tx (fee-payer slot 0 EMPTY, device signature at slot 1),
signs slot 0 with the agent session keypair, broadcasts, then reads the feed PDA back and
prints the on-chain sequence.

Usage: python3 scripts/broadcast_certified.py <partial_b64_file> <session_keypair.json>
Env:   ZC_RPC, ZC_FEED, ZC_ORACLE_PROGRAM override the devnet defaults.
"""

import base64
import json
import os
import struct
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from certify_publish_tx import CertificationError, certify_publish_tx

RPC = os.environ.get("ZC_RPC", "https://api.devnet.solana.com")
FEED = os.environ.get("ZC_FEED", "CfWaZAQ9mG1WbAhNCSQJz284MR1NC8fvfiHRaNvyQ9sU")
ORACLE_PROGRAM = os.environ.get(
    "ZC_ORACLE_PROGRAM", "EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn"
)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    sys.exit("needs: pip3 install cryptography")


def rpc(method, params):
    req = urllib.request.Request(
        RPC,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req, timeout=30).read())


raw = base64.b64decode(open(sys.argv[1]).read().strip())
seed = bytes(json.load(open(sys.argv[2]))[:32])

# Fail-closed action certification. Nothing broadcasts unless the exact serialized tx is
# EXACTLY {advance_nonce, publish_reading -> our feed}.
try:
    _intent = certify_publish_tx(raw, ORACLE_PROGRAM, FEED)
    print(f"fail-closed certification OK: {_intent['intent']}")
except CertificationError as e:
    sys.exit(f"REFUSED (fail-closed action certification): {e}")

# legacy tx: shortvec(num_sigs) + sigs*64 + message
nsigs = raw[0]
assert nsigs < 0x80, "shortvec >1 byte unexpected"
sigs = [raw[1 + i * 64 : 1 + (i + 1) * 64] for i in range(nsigs)]
msg = raw[1 + nsigs * 64 :]
assert sigs[0] == b"\x00" * 64, "fee-payer slot 0 is not empty; refusing"
assert sigs[1] != b"\x00" * 64, "device sig missing at slot 1"

sig0 = Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
out = bytes([nsigs]) + sig0 + b"".join(sigs[1:]) + msg
b64 = base64.b64encode(out).decode()

res = rpc(
    "sendTransaction", [b64, {"encoding": "base64", "preflightCommitment": "confirmed"}]
)
if "error" in res:
    sys.exit(f"send failed: {res['error']}")
txsig = res["result"]
print(f"landed: {txsig}")
print(f"explorer: https://explorer.solana.com/tx/{txsig}?cluster=devnet")

# confirm + read back the feed sequence (offset: 8 disc +32+32+1+8+1+12 = 94, u64 LE)
for _ in range(30):
    time.sleep(2)
    st = rpc("getSignatureStatuses", [[txsig]])["result"]["value"][0]
    if st and st.get("confirmationStatus") in ("confirmed", "finalized"):
        break
acct = rpc("getAccountInfo", [FEED, {"encoding": "base64", "commitment": "confirmed"}])[
    "result"
]["value"]
data = base64.b64decode(acct["data"][0])
seq = struct.unpack_from("<Q", data, 94)[0]
val = struct.unpack_from("<q", data, 73)[0]
print(f"feed on-chain now: sequence={seq} value={val}")
