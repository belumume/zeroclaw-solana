#!/usr/bin/env python3
"""Controls for check-config-drift.py, the one gate never shown to fail.

WHY THIS EXISTS. An audit of all fourteen tracked gates asked a single question of each: has it
ever produced the OPPOSITE verdict on a known input? Thirteen had either their own controls or a
sibling test file. This one had neither, and on any developer machine it returns 2 (cannot check)
because the agent config lives on the ARM node rather than here. So its two real verdicts, pass
and drift, had never executed anywhere a human could see them.

That is the exact shape this project keeps finding: a green gate that asserts nothing. A checker
whose failing branch has never run is a hypothesis, and the fact that it exits cleanly every day
is evidence about the machine, not about the code.

ZC_CONFIG lets the gate be pointed at a synthetic config, so all three verdicts are reachable
offline with no network, no agent and nothing touched on the box.

Run: python3 scripts/test_check_config_drift.py
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "check-config-drift.py"
QUICKSTART = ROOT / "QUICKSTART.md"


# The four hosts QUICKSTART documents. Read from the doc rather than restated, so this suite
# cannot drift away from the thing it is testing the way a hardcoded copy would.
def documented_four() -> list[str]:
    import re

    doc = QUICKSTART.read_text(encoding="utf-8")
    i = doc.find("http_request.allowed_domains")
    m = re.search(r"\[[^\]]*\]", doc[i : i + 1200])
    return [
        s.strip().strip('"').strip("'")
        for s in m.group(0).strip("[]").split(",")
        if s.strip()
    ]


def run(config_text: str | None) -> tuple[int, str]:
    """Drive the real gate against a synthetic config. None means no config file at all."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    try:
        env = dict(os.environ)
        if config_text is None:
            env["ZC_CONFIG"] = str(tmp / "absent.toml")
        else:
            p = tmp / "config.toml"
            p.write_text(config_text, encoding="utf-8", newline="\n")
            env["ZC_CONFIG"] = str(p)
        r = subprocess.run(
            [sys.executable, str(GATE)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=str(ROOT),
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def toml_list(items: list[str]) -> str:
    return "[" + ", ".join(f'"{i}"' for i in items) + "]"


def main() -> int:
    four = documented_four()
    if len(four) != 4:
        print(
            f"FAIL  could not read the documented host list from QUICKSTART (got {four})"
        )
        return 1

    agreeing = (
        f"[http_request]\nallowed_domains = {toml_list(four)}\n\n"
        f"[web_fetch]\nallowed_domains = {toml_list(four)}\n"
    )

    cases = []

    def check(label: str, cond: bool, detail: str = "") -> None:
        cases.append((label, cond))
        print(
            f"  {'ok  ' if cond else 'FAIL'}  {label}"
            + ("" if cond else f"\n        {detail}")
        )

    # 1. NO CONFIG -> 2, the could-not-check verdict, distinct from a finding.
    rc, out = run(None)
    check(
        "an absent config is COULD-NOT-CHECK (2), not a pass and not a finding",
        rc == 2,
        f"rc={rc}",
    )
    check(
        "and it says so rather than claiming drift",
        "nothing is claimed" in out.lower(),
        out[-200:],
    )

    # 2. AGREEING config -> 0. The pass path, which has never run on a developer machine.
    rc, out = run(agreeing)
    check("a config matching the doc passes", rc == 0, f"rc={rc}\n{out[-300:]}")
    check(
        "and says the documented posture is the running one",
        "No drift" in out,
        out[-200:],
    )

    # 3. DRIFT -> 1. The finding path, the whole reason the gate exists.
    #
    # count=1 is load-bearing and its absence was a real defect in the first version of this
    # case. `agreeing` embeds the identical host list for BOTH tools, so a bare .replace()
    # mutates both and the case silently exercises two simultaneous drifts while calling itself
    # a single swapped host. The assertions passed either way, which is precisely what makes a
    # fixture that does not match its own name dangerous: it reads as covering the isolated
    # case and covers something else. Swapping ONE host in ONE tool also tests something the
    # both-drifted version cannot, that the untouched tool is left alone.
    drifted = agreeing.replace(f'"{four[-1]}"', '"api.evil.example"', 1)
    assert drifted.count("api.evil.example") == 1, (
        "the swap was meant to hit exactly one tool"
    )
    rc, out = run(drifted)
    check("a host swapped in ONE tool is caught", rc == 1, f"rc={rc}\n{out[-300:]}")
    check(
        "and the UNTOUCHED tool still reports PASS",
        "PASS  web_fetch.allowed_domains" in out,
        out[-300:],
    )
    check(
        "and the offending tool is named",
        "http_request.allowed_domains" in out,
        out[-250:],
    )

    # 4. THE WILDCARD, which is the failure the gate's own prose calls out by name.
    rc, out = run(
        '[http_request]\nallowed_domains = ["*"]\n\n[web_fetch]\nallowed_domains = ["*"]\n'
    )
    check("an allowlist of ['*'] is caught", rc == 1, f"rc={rc}")
    check("and is named as the whole internet", "whole internet" in out, out[-250:])

    # 5. UNSET, which inherits the wildcard default and is not the same as absent.
    rc, out = run("[http_request]\n\n[web_fetch]\n")
    check("an UNSET allowlist is caught, not treated as absent", rc == 1, f"rc={rc}")
    check(
        "and explains that an unconfigured allowlist is not an allowlist",
        "not an allowlist" in out,
        out[-250:],
    )

    # 6. A LIVE PROFILE the doc does not mention at all.
    rc, out = run(agreeing + '\n[risk_profiles.ghost]\nauto_approve = ["shell"]\n')
    check("a live risk profile absent from the doc is caught", rc == 1, f"rc={rc}")
    check(
        "and is named as undocumented",
        "not documented" in out.lower() or "absent from" in out.lower(),
        out[-250:],
    )

    failed = sum(1 for _, ok in cases if not ok)
    if failed:
        print(f"\n{failed}/{len(cases)} control(s) FAILED")
        return 1
    print(
        f"\nOK  {len(cases)}/{len(cases)}; all three verdicts reachable, and drift is caught four ways."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
