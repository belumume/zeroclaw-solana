#!/usr/bin/env python3
"""Bind the argument names two plugins pass between each other.

`x402-pay-build` decides whether a 402 challenge describes a payment the operator authorised, then
hands the result to `allowance-spend-build`, which already reads the delegation, fails closed
unless the agent is the delegatee, and emits the unsigned transaction. That composition is the
correct layering, and it has one seam: the FIELD NAMES.

The seam is invisible at compile time. `x402-pay-build` emits JSON and the other plugin parses it,
so a rename on either side type-checks, tests green, and fails at runtime on a live payment, which
is the worst place to find it. So this reads the CONSUMER's `parameters_schema` and requires the
PRODUCER to emit exactly the fields it declares.

It restates neither side's list. A checker holding its own copy of the names is a third thing to
keep in step, and then a rename can pass this while breaking the pair.

Exit 0 they agree, 1 they differ, 2 could not check. A could-not-check is NOT a pass: a pattern
that stopped matching would otherwise report agreement over nothing.

  --selftest   renames a field on each side in a copy and requires a complaint
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSUMER = ROOT / "plugins/allowance-spend-build/src/lib.rs"
PRODUCER = ROOT / "plugins/x402-pay-build/src/compose.rs"

# The consumer declares its inputs as a serde_json::json! literal inside parameters_schema().
CONSUMER_PROPS = re.compile(r'"properties":\s*\{(.*?)\n\s*\},\s*\n\s*"required"', re.S)
CONSUMER_KEY = re.compile(r'^\s{20}"([a-z_]+)":\s*\{', re.M)
CONSUMER_REQUIRED = re.compile(r'"required":\s*\[([^\]]*)\]')
# The producer emits them in one json! literal too.
PRODUCER_JSON = re.compile(r"serde_json::json!\(\{(.*?)\}\)", re.S)
PRODUCER_KEY = re.compile(r'"([a-z_]+)":\s*self\.')


def read_consumer(text: str) -> tuple[set[str], set[str]] | None:
    props = CONSUMER_PROPS.search(text)
    req = CONSUMER_REQUIRED.search(text)
    if not props or not req:
        print("CANNOT CHECK  the consumer's parameters_schema did not parse")
        return None
    declared = set(CONSUMER_KEY.findall(props.group(1)))
    required = {m.strip().strip('"') for m in req.group(1).split(",") if m.strip()}
    if not declared or not required:
        print(
            f"CANNOT CHECK  the consumer declared {len(declared)} field(s), {len(required)} required"
        )
        return None
    return declared, required


def read_producer(text: str) -> set[str] | None:
    body = PRODUCER_JSON.search(text)
    if not body:
        print("CANNOT CHECK  the producer's json! literal did not parse")
        return None
    keys = set(PRODUCER_KEY.findall(body.group(1)))
    if not keys:
        print("CANNOT CHECK  the producer emitted no recognisable field names")
        return None
    return keys


def compare(consumer_text: str | None = None, producer_text: str | None = None) -> int:
    if not CONSUMER.is_file() or not PRODUCER.is_file():
        print(f"CANNOT CHECK  a file is missing:\n  {CONSUMER}\n  {PRODUCER}")
        return 2
    c = (
        consumer_text
        if consumer_text is not None
        else CONSUMER.read_text(encoding="utf-8")
    )
    p = (
        producer_text
        if producer_text is not None
        else PRODUCER.read_text(encoding="utf-8")
    )

    consumer = read_consumer(c)
    produced = read_producer(p)
    if consumer is None or produced is None:
        return 2
    declared, required = consumer

    missing = required - produced
    unknown = produced - declared
    if missing or unknown:
        print(
            "\nFAIL  the two plugins disagree about the arguments passed between them:"
        )
        for m in sorted(missing):
            print(
                f"        {m!r} is REQUIRED by allowance-spend-build and x402-pay-build omits it"
            )
        for u in sorted(unknown):
            print(
                f"        {u!r} is emitted by x402-pay-build and allowance-spend-build does not declare it"
            )
        print(
            "\n      Nothing catches this at compile time: one emits JSON and the other parses\n"
            "      it, so a rename type-checks and fails on a live payment instead."
        )
        return 1

    print(
        f"consumer declares {len(declared)} field(s), {len(required)} required; producer emits "
        f"{len(produced)}; read from both sources"
    )
    print("\nOK  the two plugins agree about the arguments passed between them.")
    return 0


def selftest() -> int:
    c = CONSUMER.read_text(encoding="utf-8")
    p = PRODUCER.read_text(encoding="utf-8")
    passed = failed = 0

    def check(name: str, ok: bool, detail: str = "") -> None:
        nonlocal passed, failed
        print(
            f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else "")
        )
        if ok:
            passed += 1
        else:
            failed += 1

    check("the UNPERTURBED pair agrees, so the check can say yes", compare(c, p) == 0)

    # A rename on the PRODUCER side: it stops emitting a required field.
    for field in ("delegation", "amount", "receiver"):
        mutated = p.replace(f'"{field}": self.', f'"{field}_renamed": self.', 1)
        rc = compare(c, mutated)
        check(f"renaming {field!r} in the producer is caught", rc == 1, f"rc={rc}")

    # A rename on the CONSUMER side: it starts requiring something nobody emits.
    mutated_c = c.replace(
        '"required": ["delegation", "amount", "receiver"]',
        '"required": ["delegation", "amount", "beneficiary"]',
        1,
    )
    rc = compare(mutated_c, p)
    check("a new required field on the consumer is caught", rc == 1, f"rc={rc}")

    # An unreadable side must NOT read as agreement.
    rc = compare("fn nothing() {}", p)
    check(
        "an unparseable consumer is a could-not-check, not a pass", rc == 2, f"rc={rc}"
    )

    assert CONSUMER.read_text(encoding="utf-8") == c, (
        "the consumer was modified on disk"
    )
    assert PRODUCER.read_text(encoding="utf-8") == p, (
        "the producer was modified on disk"
    )
    print(f"\nRESULT: {passed} passed, {failed} failed, {passed + failed} total")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv else compare())
