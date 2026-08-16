#!/usr/bin/env python3
"""The shop's four constants are pinned in TWO files, and nothing made them agree.

`skills/solana-pay/SKILL.md` carries a table the MODEL reads on every order.
`skills/solana-pay/scripts/pay_link.py` carries constants the SCRIPT enforces on every link.

They are deliberately separate: the script runs inside the channel's workspace jail and cannot
reach repo root, so it cannot import anything, and the skill file has to state the values in prose
a model can follow. Duplication is the right call. Nothing checking the duplication is not.

WHAT DISAGREEMENT ACTUALLY COSTS, which is why this is worth a gate rather than a note. The deploy
map copies the skill file and the script SEPARATELY, so they can arrive from different commits. If
the table says one merchant and the script enforces another, the model composes links the script
then refuses, and the shop stops taking orders. That failure is loud and safe, which is the good
case. The quiet case is worse: the LABEL and the NETWORK line have no cross-check at all until now,
so a table drifting there changes what a customer is told without changing what the script permits.

DERIVED FROM SOURCE, NEVER RESTATED. Both sides are read out of their own files. Restating either
value here would create a third copy and this gate would then be checking two of three, which is
the shape of a checker that reads clean while the thing it guards is broken.

Modelled on `scripts/check-pay-link-rate-agreement.py`, which binds a different duplicated constant
the same way.

Exit 0 agree, 1 disagree, 2 could not check.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL = ROOT / "skills" / "solana-pay" / "SKILL.md"
SCRIPT = ROOT / "skills" / "solana-pay" / "scripts" / "pay_link.py"

# The script side: a module-level constant assignment. Anchored at line start so a mention inside a
# comment or a message string cannot satisfy it.
SCRIPT_PINS = {
    "recipient": re.compile(r'^MERCHANT\s*=\s*"([^"]+)"', re.M),
    "mint": re.compile(r'^MINT\s*=\s*"([^"]+)"', re.M),
    "label": re.compile(r'^LABEL\s*=\s*"([^"]+)"', re.M),
}

# The skill side: the indented table a model reads. `network` is matched but compared differently,
# since the script has no network constant to compare against.
SKILL_ROW = re.compile(r"^\s{4,}(recipient|mint|label|network)\s{2,}(\S.*?)\s*$", re.M)


def fail(msg: str, code: int = 2) -> int:
    print(f"FAIL  {msg}")
    return code


def main() -> int:
    for p in (SKILL, SCRIPT):
        if not p.is_file():
            return fail(
                f"{p.relative_to(ROOT).as_posix()} is absent; nothing was compared"
            )

    skill_text = SKILL.read_text(encoding="utf-8")
    script_text = SCRIPT.read_text(encoding="utf-8")

    table = {k: v for k, v in SKILL_ROW.findall(skill_text)}
    if len(table) < 4:
        return fail(
            f"the skill file's constants table parsed {len(table)} of 4 rows "
            f"({', '.join(sorted(table)) or 'none'}); a partial read cannot certify agreement"
        )

    script_vals = {}
    for name, pat in SCRIPT_PINS.items():
        m = pat.search(script_text)
        if not m:
            return fail(
                f"no {name} constant found in the enforcing script; nothing was compared"
            )
        script_vals[name] = m.group(1)

    problems = []
    for name, got in sorted(script_vals.items()):
        # The table's mint row carries a trailing parenthetical gloss; compare the leading token.
        want = table[name].split("  ")[0].strip()
        want = want.split(" (")[0].strip()
        if want != got:
            problems.append(f"{name}: skill says {want!r}, script enforces {got!r}")

    # NETWORK is checked for PRESENCE and CONTENT, not against the script, because the script has
    # no network constant. It is the one of the four no code can enforce, so the most this can do
    # is confirm the table still says mainnet rather than silently naming the other network.
    net = table["network"].lower()
    if "mainnet" not in net:
        problems.append(
            f"network: the table does not say mainnet ({table['network']!r})"
        )
    elif re.search(r"\bdevnet\b", net) and "never devnet" not in net:
        problems.append(
            f"network: the table names devnet outside a prohibition ({table['network']!r})"
        )

    if problems:
        print("FAIL  the shop's two constant tables disagree:")
        for p in problems:
            print(f"        {p}")
        print(
            "      The model reads the skill file and the script enforces its own values, so a"
        )
        print(
            "      disagreement means links get composed and then refused, or worse, a customer"
        )
        print("      is told something the script never checks.")
        return 1

    shown = ", ".join(
        f"{k}={v[:12]}.." if len(v) > 14 else f"{k}={v}"
        for k, v in sorted(script_vals.items())
    )
    print(
        f"PASS  4 constants agree across both pinning files ({shown}, network=mainnet)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
