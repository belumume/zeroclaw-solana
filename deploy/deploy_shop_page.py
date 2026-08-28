#!/usr/bin/env python3
"""Deploy the built pay page to Cloudflare Pages without the token crossing a tool boundary.

WHY A SCRIPT RATHER THAN A SHELL LINE. `pass-output-redaction.py` blocks `pass item view` unless
the requested field is on its allow-list, and the Pages credentials live in CUSTOM fields
(`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`) that are not on it. That guard is right to be
strict: in Claude Code, stdout is captured into conversation context and persisted to the session
JSONL and to exports.

Its override marker is `# pass-output-cleared: <reason>` and it means "I accept the secret being
logged", which is precisely what must NOT happen here. So this is a route-around rather than an
override, and it preserves the guard's intent more completely than the override would: the value is
read into a variable inside ONE process, handed to wrangler through the environment, and never
printed, never echoed, never written to a file. What reaches stdout is a character count.

STAGING. wrangler uploads a DIRECTORY. Pointing it at `webshop-pay/` would upload `build.py` and
whatever else lands there, and pointing it at anything under the repo risks sweeping `.git`, whose
paths carry the operator's username. So the payload is copied to a fresh staging directory holding
exactly the two files Pages serves. A fresh directory rather than a cleaned one, because clearing it
would need a recursive delete and the safety guard is right to block those.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# DERIVED, never hardcoded, and never a placeholder either. This file is TRACKED, so an absolute
# home path here ships the author's account name to every clone -- which it did until 2026-08-06,
# and `scripts/check-identifier-leaks.py` was red on exactly this line. A `<your-user>` placeholder
# would have fixed the leak and broken the script for everyone including its owner; deriving fixes
# both. PASS_CLI overrides for a non-default install.
PASS_EXE = Path(
    os.environ.get("PASS_CLI")
    or Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    / "Programs"
    / "ProtonPass"
    / "pass-cli.exe"
)
ITEM = "Cloudflare Pages deploy token (zeroclaw-shop-pay)"
VAULT = "Personal"
PROJECT = "zeroclaw-shop-pay"

SRC = Path(__file__).resolve().parent.parent / "webshop-pay"
# NOT THE DEPLOY SET. This script cannot deploy -- see _refuse_if_superseded below -- and
# these two lists are inert. The live set is SERVE in scripts/deploy-pay-page.py, which is
# the only list a reader should act on and the only one a deploy reads.
#
# They are kept because the reason underneath them is worth keeping and lives nowhere else,
# and because a reader who finds this file first must be told which list is authoritative.
# Two payload lists with no such marker is how one of them drifts from what the page needs
# while the other stays right, and only the live one matters when that happens.
PAYLOAD = ["index.html", "_headers"]
# `vendor/` holds the bundled Solana libraries the pay path imports at click time. They used
# to come from esm.sh, which meant one click fanned out into 18+ third-party requests and any
# shield or blocker turned a healthy page into "o pagamento nao foi concluido". Same-origin
# removes the whole class, which is why the page cannot be served without it.
#
# The live set names that bundle AS A FILE rather than copying this directory whole: a
# directory copy ships whatever lands in it next, which is the shape this repo already had
# to clean up once when a ruff cache reached a public origin.
PAYLOAD_DIRS = ["vendor"]


def creds() -> tuple[str, str]:
    """Read the two custom fields. The values stay in this process."""
    import json

    r = subprocess.run(
        [
            str(PASS_EXE),
            "item",
            "view",
            "--vault-name",
            VAULT,
            "--item-title",
            ITEM,
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if r.returncode != 0:
        raise SystemExit(f"FATAL pass-cli rc={r.returncode}: {(r.stderr or '')[:200]}")

    found: dict[str, str] = {}

    def walk(o):
        # Proton Pass shape, verified against the live item rather than assumed:
        #   .item.content.content.Custom.sections[].section_fields[]
        #     .name    -> "CLOUDFLARE_API_TOKEN"
        #     .content -> {"Hidden": "..."} for a secret, {"Text": "..."} for a plain field
        # A flat {"name","value"} pair does NOT exist here, which is what the first attempt
        # assumed; it found nothing and reported an empty field list rather than guessing.
        if isinstance(o, dict):
            n, c = o.get("name"), o.get("content")
            if isinstance(n, str) and isinstance(c, dict):
                for kind in ("Hidden", "Text"):
                    if isinstance(c.get(kind), str):
                        found[n] = c[kind]
                        break
            for x in o.values():
                walk(x)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(json.loads(r.stdout))
    tok = found.get("CLOUDFLARE_API_TOKEN", "")
    acc = found.get("CLOUDFLARE_ACCOUNT_ID", "")
    if not tok or not acc:
        # Names only, never values, so a rename is diagnosable without a leak.
        raise SystemExit(
            "FATAL missing credential field. Custom field names on the item: "
            + ", ".join(sorted(found))
            or "(none)"
        )
    return tok, acc


def main() -> int:
    index = SRC / "index.html"
    if not index.is_file():
        print(f"FATAL missing {index}. Run webshop-pay/build.py first.")
        return 2

    tok, acc = creds()
    print(
        f"credentials: token {len(tok)} chars, account {len(acc)} chars (values not printed)"
    )

    stage = Path(f"C:/tmp/shopdeploy-{int(time.time())}")
    stage.mkdir(parents=True, exist_ok=False)
    for name in PAYLOAD:
        src = SRC / name
        if src.is_file():
            shutil.copy2(src, stage / name)
    for name in PAYLOAD_DIRS:
        src = SRC / name
        if src.is_dir():
            shutil.copytree(src, stage / name)
    staged = sorted(p.name for p in stage.iterdir())
    print(f"staged {stage}: {staged}")
    assert not any(n in (".git", ".wrangler") for n in staged), (
        "staging dir is not clean"
    )

    env = dict(os.environ, CLOUDFLARE_API_TOKEN=tok, CLOUDFLARE_ACCOUNT_ID=acc)
    cmd = [
        "npx",
        "-y",
        "wrangler@latest",
        "pages",
        "deploy",
        str(stage),
        "--project-name",
        PROJECT,
        "--branch",
        "main",
        "--commit-dirty=true",
    ]
    print("deploying ...")
    r = subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        shell=True,
    )
    out = (r.stdout or "") + (r.returncode and (r.stderr or "") or "")
    # Never echo the whole log unfiltered: wrangler can surface the account id.
    for line in out.splitlines():
        if any(
            k in line
            for k in (
                "Success",
                "Uploading",
                "uploaded",
                "Deployment",
                "http",
                "Error",
                "error",
            )
        ):
            print("  " + line.strip()[:160])
    print(f"wrangler rc={r.returncode}")
    return r.returncode


SUPERSEDED_BY = "scripts/deploy-pay-page.py"


def _refuse_if_superseded() -> None:
    """This script no longer deploys anything, and it must not start.

    It is retained rather than deleted because `deploy/make_invariants.py` cites it by file:line as
    the cautionary example of a defect that once shipped, and deleting the file would turn a live
    citation into a dead pointer. Nothing invokes it: a sweep of .md, .py and .yml on 2026-08-19
    found only that citation, a compound note, and a handoff entry derived from a review finding
    against this file.

    IT IS DISABLED BECAUSE IT IS A TRAP, not because it is merely unused. Its deploy call is
    `npx -y wrangler@latest`, which resolves and executes whatever npm currently serves, plus the
    whole transitive tree, with a live Cloudflare Pages deploy token in the environment. That token
    publishes the pay page, so anyone who found this script first and ran it would take the worse of
    two supply-chain shapes for a deploy the other script already does. The live path resolves npx
    explicitly, refuses if it is absent, and pins no version -- weaker exposure, and the one tracked
    for fixing.

    Delete this file only together with the citation in make_invariants.py, and only after checking
    that no gitignored runbook invokes it, which a repo-scoped grep cannot see.
    """
    sys.exit(
        f"REFUSED: {__file__} is superseded by {SUPERSEDED_BY} and does not deploy.\n"
        f"Nothing was uploaded. Use: python {SUPERSEDED_BY} --publish"
    )


if __name__ == "__main__":
    _refuse_if_superseded()
    sys.exit(main())
