#!/usr/bin/env python3
"""Does the running config match the config this repo documents? (stdlib only)

    python3 scripts/check-config-drift.py
    ZC_CONFIG=/path/to/config.toml python3 scripts/check-config-drift.py

Exit 0 = the documented security posture is the one actually running.
Exit 1 = they have drifted, with the difference printed.

WHY THIS EXISTS
---------------
QUICKSTART documents an auto-approve list and an egress allowlist. Those are the
security posture, and a reviewer auditing the documented posture is auditing
whatever the document says, not whatever the machine does. An audit found the two
had drifted: the documented list was missing two tools that were live, and a
second risk profile was running with `shell`, `http_request` and `memory_store`
auto-approved while appearing in no document at all.

Nothing catches that class on its own. Tests pass, the daemon runs, the document
reads correctly, and the gap only surfaces when someone compares them by hand. So
this compares them by machine, and it is runnable by a stranger against their own
config after following the reproduction, which is the point: it checks that the
instructions produce the posture they claim, not that our machine is configured
the way we remember.

Deliberately NOT a CI job: CI has no running config to compare against. This is a
local check, like the reproduction it guards.
"""

import os
import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
QUICKSTART = REPO / "QUICKSTART.md"

DEFAULT_CONFIG = Path.home() / ".zeroclaw" / "config.toml"


def documented_list(text: str, anchor: str):
    """First bracketed list following an anchor in the markdown."""
    i = text.find(anchor)
    if i < 0:
        return None
    m = re.search(r"\[[^\]]*\]", text[i : i + 1200])
    if not m:
        return None
    return [
        s.strip().strip('"').strip("'")
        for s in m.group(0).strip("[]").split(",")
        if s.strip()
    ]


def compare(label, documented, live, problems):
    if documented is None:
        problems.append(f"{label}: not documented in QUICKSTART.md at all")
        print(f"FAIL  {label}: absent from QUICKSTART")
        return
    if live is None:
        problems.append(f"{label}: documented but absent from the running config")
        print(f"FAIL  {label}: documented but not set in the config")
        return
    only_doc = sorted(set(documented) - set(live))
    only_live = sorted(set(live) - set(documented))
    if not only_doc and not only_live:
        print(f"PASS  {label} ({len(live)} entries, documented and live agree)")
        return
    problems.append(label)
    print(f"FAIL  {label}: documented and running config differ")
    if only_live:
        print(f"        running but UNDOCUMENTED: {', '.join(only_live)}")
        print("        an undocumented capability is one a reviewer cannot audit")
    if only_doc:
        print(f"        documented but NOT running: {', '.join(only_doc)}")
        print("        the instructions describe a posture nobody has")


def main():
    cfg_path = Path(os.environ.get("ZC_CONFIG", DEFAULT_CONFIG))
    if not cfg_path.is_file():
        print(f"no config at {cfg_path}")
        print(
            "Set ZC_CONFIG if yours lives elsewhere. Nothing to compare, so nothing is claimed."
        )
        return 1
    live = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    doc = QUICKSTART.read_text(encoding="utf-8")
    print(f"comparing {cfg_path}\n     against {QUICKSTART.name}\n")

    problems = []

    for profile in sorted(live.get("risk_profiles", {})):
        entry = live["risk_profiles"][profile]
        if not isinstance(entry, dict) or "auto_approve" not in entry:
            continue
        compare(
            f"risk_profiles.{profile}.auto_approve",
            documented_list(doc, f"risk_profiles.{profile}.auto_approve"),
            entry["auto_approve"],
            problems,
        )

    for tool in ("http_request", "web_fetch"):
        live_domains = live.get(tool, {}).get("allowed_domains")
        if live_domains is None:
            problems.append(f"{tool}.allowed_domains")
            print(
                f"FAIL  {tool}.allowed_domains: unset, so it inherits the ['*'] default"
            )
            print("        an unconfigured allowlist is not an allowlist")
            continue
        if live_domains == ["*"]:
            problems.append(f"{tool}.allowed_domains")
            print(f"FAIL  {tool}.allowed_domains: set to ['*'], the whole internet")
            continue
        compare(
            f"{tool}.allowed_domains",
            documented_list(doc, f"{tool}.allowed_domains"),
            live_domains,
            problems,
        )

    print()
    if problems:
        print(
            f"{len(problems)} drift(s). The documented posture is not the running one."
        )
        return 1
    print("No drift. What the reproduction documents is what is running.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
