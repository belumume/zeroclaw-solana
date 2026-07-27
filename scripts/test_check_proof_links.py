"""Controls for check-proof-links.py, in all three directions.

Two directions is the usual bar and it is not enough for this gate. Must-fire alone passes for a
checker that flags every link, which teaches its reader to skip it. Must-not-fire alone is the
state the repo was already in: twelve links were backed, nobody had shown the gate could tell the
difference, and two dead links sat in a judge-facing table for days.

The third bucket is the one most suites omit. A gate that cannot read its own inputs must not
report the same thing as a gate that read them and found nothing, because those are
indistinguishable downstream and only one is good news. Cases 8 through 10 assert it degrades to
2 rather than to 0.

CASE 1 IS THE REAL INCIDENT, copied from the row that was live in docs/DEVNET-PROOF.md, including
the "pruned before capture" text in the adjacent cell. That text is not incidental: it is why the
row looked handled. If case 1 ever stops firing, this gate is blind and the prose is doing the
reassuring again.

CASE 2 IS THE OTHER HALF of the same incident. The link that actually reached a judge-facing
README was invisible because the sibling checker enumerated six documents by hand and plugin
READMEs were not among them. If case 2 stops firing, the scope has been hand-maintained again.

Run: python scripts/test_check_proof_links.py
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Overridable so the suite can be pointed at a pre-fix copy of the gate. Driving the must-fire
# cases against an older version is what shows a change did something, rather than that the new
# cases happen to agree with the new code.
GATE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "check-proof-links.py"

FIRE = 1
CLEAN = 0
CANNOT = 2

# Real signatures from this repo's own bundle, so the fixtures are the artifacts rather than
# lookalikes. The first two are the transactions whose bytes were genuinely lost.
PRUNED_1 = "2pgdXYASpLxcSKuBBzxWnHRWKVZiJbdzpu4SCrjeznL1ptJc1iNcT8ste79Goti14MadKZHvo1rsNMVemmAbEBH"
PRUNED_2 = "2j9emSvsWHKyTEGVT3iLik9XGxpQkLLqAhLLQqjgkVEQx2QPHJQnxqzKLMqxCtCjnsdne276aFH4z76Z3CdJah5E"
HELD = "agHTsrz1Z6XhFjKN2g9DxFjJP363He2rHByvDN7r6KUDurzxxxcdj4LcfTA6AQpNsFk4cYqjk9k4kHfwgxWRFQd"
UNKNOWN = "4kDo6NCcAxSe3BSTtQ4onTASenxRWr2miagweVway3RnDMLG7drv6NkTdV7eRtTSDcNXURy2ESpKcqkk2jG9sYqS"


def link(sig):
    return f"https://explorer.solana.com/tx/{sig}?cluster=devnet"


def bundle_with(captured=(), pruned=()):
    txs = {}
    for s in captured:
        txs[s] = {
            "status": "CAPTURED",
            "slot": 1,
            "blockTime": 1,
            "err": None,
            "raw_base64": "AA==",
            "raw_sha256": "00",
            "raw_len": 1,
        }
    for s in pruned:
        txs[s] = {
            "status": "ALREADY_PRUNED",
            "detail": "endpoint no longer serves this transaction",
        }
    return {"captured_utc": "x", "cluster": "devnet", "transactions": txs}


# A doc that always passes, so a green result in the cases below proves the parser ran on
# something rather than proving the tree was empty.
ANCHOR_DOC = (
    "docs/DEVNET-PROOF.md",
    f"Settlement: [agHTsrz1...]({link(HELD)}) captured.\n",
)

cases = []


def case(name, want, docs, bundle, untracked_docs=()):
    cases.append((name, want, docs, bundle, untracked_docs))


# ---------------------------------------------------------------- must fire (rc=1)

# Verbatim shape of the row that shipped: the offline-status column already said the bytes were
# gone, and the signature stayed clickable anyway. An accurate label beside a dead link still
# hands a reader a dead end.
case(
    "THE INCIDENT SHAPE: clickable link to a pruned tx, labelled pruned in the next cell",
    FIRE,
    [
        (
            "docs/DEVNET-PROOF.md",
            f"| 2026-07-23T02:42Z | 10 | 29.0C | [2pgdXYAS...]({link(PRUNED_1)}) "
            f"| pruned before capture |\n",
        )
    ],
    bundle_with(captured=[HELD], pruned=[PRUNED_1]),
)

# The other half of the same incident. This file class was outside the sibling checker's
# hand-maintained six-document list, which is how a dead link reached a judge-facing README
# through every green run.
case(
    "THE SCOPE SHAPE: a plugin README is in scope, not just the six core docs",
    FIRE,
    [
        ANCHOR_DOC,
        (
            "plugins/depin-attest/README.md",
            f"Attestation landed on devnet: [cHvDQsPX...]({link(PRUNED_2)})\n",
        ),
    ],
    bundle_with(captured=[HELD], pruned=[PRUNED_2]),
)

# Absent from the register entirely, which is worse than a recorded loss: nobody ever decided
# anything about it.
case(
    "a linked signature the bundle has never heard of",
    FIRE,
    [
        ANCHOR_DOC,
        ("README.md", f"See [4kDo6NCc...]({link(UNKNOWN)}) for the settlement.\n"),
    ],
    bundle_with(captured=[HELD]),
)


# ------------------------------------------------------------ must NOT fire (rc=0)

case(
    "a link whose bytes are held passes",
    CLEAN,
    [ANCHOR_DOC],
    bundle_with(captured=[HELD]),
)

# The remedy this gate steers toward. If this fires, the gate is telling authors to delete real
# history rather than to stop offering it as evidence, and the depin-attest README would be red.
case(
    "a BARE uncaptured signature in backticks is history, not a claim",
    CLEAN,
    [
        ANCHOR_DOC,
        (
            "plugins/depin-attest/README.md",
            f"- tx `{PRUNED_2}`\n\nThat signature no longer resolves and is kept as history.\n",
        ),
    ],
    bundle_with(captured=[HELD], pruned=[PRUNED_2]),
)

# Accounts persist rather than being pruned, so an address link makes no claim this gate governs.
case(
    "an /address/ link is out of scope",
    CLEAN,
    [
        ANCHOR_DOC,
        (
            "docs/NOTES.md",
            "Feed at https://explorer.solana.com/address/"
            "JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg?cluster=devnet\n",
        ),
    ],
    bundle_with(captured=[HELD]),
)

# Tracked is the boundary because a reader receives exactly the tracked tree.
case(
    "an untracked doc with a dead link is not a reader's problem",
    CLEAN,
    [ANCHOR_DOC],
    bundle_with(captured=[HELD], pruned=[PRUNED_1]),
    untracked_docs=[("scratch.md", f"[dead]({link(PRUNED_1)})\n")],
)


# ------------------------------------------- must NOT report clean when it cannot check (rc=2)

case(
    "DEGRADE: a missing bundle cannot pass",
    CANNOT,
    [ANCHOR_DOC],
    None,
)

case(
    "DEGRADE: a bundle holding no captured bytes cannot pass",
    CANNOT,
    [ANCHOR_DOC],
    bundle_with(pruned=[PRUNED_1, PRUNED_2]),
)

# The vacuous scan. A parser that matches nothing prints the same clean line as a tree that is
# genuinely fine, and this repo publishes transaction links by construction.
case(
    "DEGRADE: finding zero links at all is a broken gate, not a clean tree",
    CANNOT,
    [("docs/DEVNET-PROOF.md", "No links here at all.\n")],
    bundle_with(captured=[HELD]),
)


def run_case(name, want, docs, bundle, untracked_docs):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "scripts" / "check-proof-links.py").write_text(
            GATE.read_text(encoding="utf-8"), encoding="utf-8"
        )
        subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)

        if bundle is not None:
            b = root / "docs" / "proof-bundle" / "devnet-transactions.json"
            b.parent.mkdir(parents=True, exist_ok=True)
            b.write_text(json.dumps(bundle, indent=2), encoding="utf-8")

        for rel, body in docs:
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body, encoding="utf-8")

        subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True)

        # Written AFTER git add, so they exist on disk and are absent from the index. That is the
        # case that matters: it looks fine to the author and is invisible to a cloner.
        for rel, body in untracked_docs:
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body, encoding="utf-8")

        out = subprocess.run(
            [sys.executable, str(root / "scripts" / "check-proof-links.py")],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return out.returncode, (out.stdout or "") + (out.stderr or "")


LABEL = {
    FIRE: "FIRE (rc=1)",
    CLEAN: "NOT FIRE (rc=0)",
    CANNOT: "REFUSE TO PASS (rc=2)",
}


def main():
    if not GATE.exists():
        print(f"gate not found at {GATE}")
        return 2

    npass = nfail = 0
    last_want = None
    for name, want, docs, bundle, untracked in cases:
        if want != last_want:
            print(f"\nMUST {LABEL[want]}:")
            last_want = want
        rc, output = run_case(name, want, docs, bundle, untracked)
        if rc == want:
            print(f"  ok   {name} (rc={rc})")
            npass += 1
        else:
            print(f"  FAIL {name} (rc={rc} want={want})")
            print("       " + output.strip().replace("\n", "\n       "))
            nfail += 1

    print(f"\n{npass} passed, {nfail} failed")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
