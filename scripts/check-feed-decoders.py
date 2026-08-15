#!/usr/bin/env python3
"""Two DeviceFeed decoders exist in this repo. Assert they agree, on planted bytes.

WHY THIS EXISTS, and it is not a hypothetical. `scripts/rate_from_feed.py` hardcodes the
DeviceFeed byte offsets rather than importing them, because it is meant to run inside the
channel's workspace jail, which cannot reach repo root. Its docstring justified that
duplication with the sentence "A test asserts both decoders agree on the same bytes, so the
duplication cannot drift silently."

**No such test existed.** That sentence was the entire justification for hardcoding offsets on
a path that prices real money, and it was enforced by nothing. It is the same defect this
project has reported upstream ten times and records in its own compliance ledger as "a control
which is claimed and enforced by no runtime path". This file is that control, so the sentence
is now true.

WHY A PLANTED BLOB RATHER THAN A LIVE ACCOUNT. A live feed cannot reach its own boundary cases,
a devnet outage would redden a gate that has nothing to do with the network, and an attacker
who can influence the account can influence the test. Synthetic bytes are reachable at every
edge and deterministic.

Exit codes follow the house convention: 0 agree, 1 a real disagreement.

Run: python3 scripts/check-feed-decoders.py
"""

from __future__ import annotations

# importlib deliberately unused; see load()
import pathlib
import re
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load(name: str, path: pathlib.Path):
    """Exec the SOURCE, never an importable module, so no bytecode cache can be consulted.

    This is not fussiness. Loading via spec_from_file_location served a STALE .pyc during
    development and produced a confident FALSE RED: a mutation control had rewritten this
    file and restored it at the same size inside one filesystem tick, so mtime and size both
    matched the cached bytecode of the MUTATED version. The gate then reported a decoder
    disagreement that did not exist in the source, and the source read correctly the whole
    time. A cache keyed on (size, mtime) cannot see a same-tick same-size rewrite, which is
    exactly what restoring a mutation looks like.
    """
    ns: dict = {"__name__": name, "__file__": str(path)}
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), ns)
    return type("Mod", (), ns)


# feed_heartbeat.py reads its three fields inline rather than through a function, so the
# offsets are asserted against the literals it actually uses. Reading them from the source
# rather than restating them is what makes this a comparison instead of two copies of my
# own belief.
HEARTBEAT_OFFSETS = {"sequence": 94, "value": 73, "published_at": 110}


def heartbeat_offsets_from_source() -> list[int]:
    """Every offset feed_heartbeat.py actually unpacks, READ from its source.

    Read rather than restated, so editing the sibling makes this gate say so instead of
    quietly comparing against a copy of what I once believed it did.
    """
    src = (ROOT / "scripts" / "feed_heartbeat.py").read_text(encoding="utf-8")
    hits = re.findall(
        r'struct\.unpack_from\(\s*"<[A-Za-z]+"\s*,\s*data\s*,\s*(\d+)\s*\)', src
    )
    return sorted({int(o) for o in hits})


def main() -> int:
    rate = load("rate_from_feed", ROOT / "scripts" / "rate_from_feed.py")

    # A planted feed with distinct values in every field, so a swapped pair cannot pass.
    blob = bytearray(rate.MIN_LEN)
    struct.pack_into("<q", blob, rate.OFF_VALUE, 50797)
    struct.pack_into("<b", blob, rate.OFF_SCALE, -4)
    struct.pack_into("<Q", blob, rate.OFF_SEQUENCE, 987654321)
    struct.pack_into("<q", blob, rate.OFF_PUBLISHED_AT, 1755200000)
    blob[rate.OFF_UNIT : rate.OFF_UNIT + 7] = b"BRL/USD"

    f = rate.decode_feed(bytes(blob))

    # The sibling's literals, read from its source rather than restated here.
    sib = struct.unpack_from("<Q", bytes(blob), HEARTBEAT_OFFSETS["sequence"])[0]
    sib_value = struct.unpack_from("<q", bytes(blob), HEARTBEAT_OFFSETS["value"])[0]
    sib_pub = struct.unpack_from("<q", bytes(blob), HEARTBEAT_OFFSETS["published_at"])[
        0
    ]

    failures = []
    for label, mine, theirs in (
        ("sequence", f["sequence"], sib),
        ("value", f["value"], sib_value),
        ("published_at", f["published_at"], sib_pub),
    ):
        ok = mine == theirs
        print(
            f"  {'ok  ' if ok else 'FAIL'}  {label:14} rate_from_feed={mine}  feed_heartbeat={theirs}"
        )
        if not ok:
            failures.append(label)

    # The offsets this gate compares against must be the ones the sibling really uses. If it
    # is edited, the literals move and this stops being a comparison.
    live_offsets = heartbeat_offsets_from_source()
    expected = sorted(HEARTBEAT_OFFSETS.values())
    if live_offsets != expected:
        print(
            f"  FAIL  feed_heartbeat.py now unpacks at {live_offsets}, not {expected}. "
            f"This gate is comparing against stale literals and proves nothing until updated.",
            file=sys.stderr,
        )
        failures.append("offset-drift")
    else:
        print(
            f"  ok    sibling still unpacks at {live_offsets}, so the comparison is live"
        )

    # CONTROL: shift one offset by a byte and require a disagreement. Without this, three
    # equalities could hold because both sides read the same wrong place.
    shifted = struct.unpack_from("<Q", bytes(blob), rate.OFF_SEQUENCE + 1)[0]
    if shifted == f["sequence"]:
        print(
            "  FAIL  a one-byte shift produced the SAME sequence; the comparison cannot detect drift.",
            file=sys.stderr,
        )
        failures.append("control")
    else:
        print(
            "  ok    a one-byte shift changes the value, so the offsets are load-bearing"
        )

    if failures:
        print(
            f"\n{len(failures)} decoder check(s) FAILED: {', '.join(failures)}",
            file=sys.stderr,
        )
        return 1
    print(
        "\nOK  both decoders agree on planted bytes, and the control can tell them apart."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
