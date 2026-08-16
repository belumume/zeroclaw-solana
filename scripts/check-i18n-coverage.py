#!/usr/bin/env python3
"""Every customer-facing message on the pay page routes through the locale lookup.

WHY THIS IS A GATE RATHER THAN A NOTE. The enforce-versus-write test is a conjunction:
real, repeating, and cheaply decidable without judgement. All three hold.

  REAL       A Brazilian customer read "Esta carteira tem 0.0002 USDC, needs 0.39. Fund
             this wallet on Solana mainnet, then retry." on the live page, at the moment
             the payment stopped and they were being told what to do about it.
  REPEATING  Three instances of one shape. The skill's step 4b hardcoded a how-to-pay line
             in English and the model reproduced it inside a Portuguese reply; the
             shortfall sentence had three of its four fragments hardcoded; and the
             no-wallet-detected message was hardcoded in full. Each was found separately,
             by a human or a reviewer, never by anything that runs.
  DECIDABLE  A `status(...)` call either begins with `T(` or it begins with a bare string
             literal. No judgement is involved.

WHAT IT CHECKS
  1. No `status()` call starts with a bare string literal.
  2. Every key passed to `T()` exists in the pt table, so a lookup cannot silently fall
     through to its English default and look translated in the source while rendering
     English to the customer. That silent-fallthrough is the failure this half exists for:
     `T('typo', 'English')` is valid JavaScript, renders English, and reads as localised.
  3. The pt table carries no key nothing uses, since a dead entry is a translation someone
     believes is shipping.

HONEST CEILING, so the gate is never read as more coverage than it has:
  - It governs `webshop-pay/src/app.js` only. Other surfaces have their own conventions.
  - It cannot judge TRANSLATION QUALITY. A pt entry that is wrong, or that is English text
    sitting in the pt table, passes. Only a reader who speaks the language catches that.
  - It only knows about `status()`. A message delivered by some other call, or written
    straight into the DOM, is invisible to it.
  - Check 3 is reported as a finding but does not fail the run, because a key staged ahead
    of its use is a legitimate intermediate state.

Exit codes follow the house convention: 0 ok, 1 finding, 2 could-not-check.
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
APP = REPO / "webshop-pay" / "src" / "app.js"

# A status() call is localised when its first argument is a T( lookup.
STATUS_BARE = re.compile(r"\bstatus\(\s*(['\"])(?P<text>(?:[^'\"\\]|\\.)*)\1")
STATUS_T = re.compile(r"\bstatus\(\s*T\(")
T_CALL = re.compile(r"\bT\(\s*(['\"])(?P<key>[A-Za-z0-9_]+)\1")
# Descend INTO the pt namespace. The table is `STR={pt:{...}}`, so a pattern anchored on
# `STR={` captures `pt` itself as though it were a message key and reports it as unused
# forever. Caught on the first real run, by the gate flagging a key that is not one.
PT_TABLE = re.compile(r"STR\s*=\s*\{\s*pt\s*:\s*\{(?P<body>.*?)\n\s*\}", re.S)
PT_KEY = re.compile(r"^\s*(?P<key>[A-Za-z0-9_]+)\s*:", re.M)


def load():
    if not APP.is_file():
        return None
    return APP.read_text(encoding="utf-8")


def audit(src):
    """Return (bare, missing, unused) findings for the given source text."""
    bare = []
    for m in STATUS_BARE.finditer(src):
        line = src[: m.start()].count("\n") + 1
        bare.append((line, m.group("text")[:80]))

    table = PT_TABLE.search(src)
    pt_keys = set(PT_KEY.findall(table.group("body"))) if table else set()
    used = {m.group("key") for m in T_CALL.finditer(src)}

    missing = sorted(used - pt_keys)
    unused = sorted(pt_keys - used)
    return bare, missing, unused, len(used), len(pt_keys)


def selftest():
    """Both directions on planted inputs. A gate that has never gone red proves nothing.

    Every fixture carries the PRODUCTION table shape, `STR={pt:{...}}`, rather than a
    flattened `STR={...}`. The flattened form is where a whole suite goes fictional: each
    case inherits the helper's shape, so one wrong helper silently voids all of them while
    the suite reads green. This exact defect shipped here first, and it surfaced only
    because the parser was corrected to match production and the fixtures then failed.
    """

    def table(*pairs):
        body = "".join(f" {k}:'{v}',\n" for k, v in pairs)
        return "var STR={pt:{\n" + body + "}};\n"

    cases = [
        (
            "a bare status literal is caught",
            table(("a", "x")) + "status('Hardcoded English.','err');\nT('a','x')",
            lambda r: len(r[0]) == 1,
        ),
        (
            "a wrapped status literal is clean",
            table(("a", "x")) + "status(T('a','Hardcoded English.'),'err')",
            lambda r: len(r[0]) == 0,
        ),
        (
            "a T() key absent from the pt table is caught",
            table(("a", "x")) + "status(T('typo','English'),'err')",
            lambda r: r[1] == ["typo"],
        ),
        (
            "a pt key nothing uses is reported",
            table(("a", "x"), ("b", "y")) + "status(T('a','English'),'err')",
            lambda r: r[2] == ["b"],
        ),
        (
            "a clean source is clean on all three",
            table(("a", "x")) + "status(T('a','English'),'err')",
            lambda r: not r[0] and not r[1] and not r[2],
        ),
        (
            "the pt NAMESPACE key is not itself reported as an unused message key",
            table(("a", "x")) + "status(T('a','English'),'err')",
            lambda r: "pt" not in r[2],
        ),
    ]
    bad = 0
    for name, src, ok in cases:
        result = audit(src)
        good = ok(result)
        print(f"  {'ok  ' if good else 'FAIL'}  {name}")
        if not good:
            bad += 1
            print(
                f"        got bare={result[0]} missing={result[1]} unused={result[2]}"
            )
    print(
        f"\n{'OK' if not bad else 'FAILED'}  {len(cases) - bad}/{len(cases)}; "
        "the detector fires and stays silent as it should."
    )
    return 1 if bad else 0


def main():
    if "--selftest" in sys.argv:
        return selftest()

    src = load()
    if src is None:
        print(f"NOT CHECKED: {APP} is missing.")
        print(
            "  Exits 2 rather than 0 on purpose: a coverage check that cannot find its"
        )
        print("  subject has not established coverage.")
        return 2

    bare, missing, unused, n_used, n_keys = audit(src)
    wrapped = len(STATUS_T.findall(src))

    print(
        f"scanned {APP.relative_to(REPO)}: {wrapped} localised status call(s), "
        f"{n_used} distinct T() key(s), {n_keys} pt entr(ies)"
    )

    if unused:
        print(f"\nNOTE  {len(unused)} pt entr(ies) nothing uses: {', '.join(unused)}")
        print("      Reported, not fatal: a key staged ahead of its use is legitimate.")

    if not bare and not missing:
        print("\nOK  every customer-facing status message routes through the lookup,")
        print("    and every key it asks for exists in the pt table.")
        return 0

    for line, text in bare:
        print(
            f"\nFINDING  {APP.relative_to(REPO)}:{line} hardcoded English in status()"
        )
        print(f"         {text}")
        print("         Wrap it: status(T('<key>', '<the English>'), ...) and add the")
        print(
            "         pt entry. A customer hitting this path reads the wrong language"
        )
        print("         at the moment something went wrong.")
    for key in missing:
        print(
            f"\nFINDING  T('{key}', ...) has no pt entry, so it silently renders English."
        )
        print(
            "         This passes every syntax check and looks localised in the source."
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
