"""Controls for check-identifier-leaks.py, in BOTH directions.

One direction alone proves nothing here. Only-must-fire passes for a checker that flags
every path and address, which trains its reader to skip it, and this repo's tree
legitimately contains a container-image home path, WhatsApp group JIDs shaped exactly
like e-mail addresses, and 218 commits under a noreply identity. Only-must-pass is the
state the repo was actually in: no gate at all, a username found by hand, scrubbed from
the tree and the history, and a second identifier still sitting on a surface nobody
looked at.

Case 1 and case 2 are the two real incident shapes:
  1. an absolute Windows home path hardcoded in a tracked script
  2. a personal e-mail as commit author identity, which survives a content scrub because
     rewriting blobs does not touch identities

If either stops firing, this gate is blind to the thing it was built for.

Run: python scripts/test_check_identifier_leaks.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Overridable so the suite can be driven against a mutated copy of the gate. That is what
# shows a case fires for its OWN reason rather than passing by coincidence.
GATE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "check-identifier-leaks.py"

FIRE = 1
CLEAN = 0

NOREPLY = "9999999+someone@users.noreply.github.com"

cases = []


def case(
    name,
    want,
    files,
    author=NOREPLY,
    n_commits=3,
    lower_floors=True,
    expect_refusal=False,
):
    cases.append((name, want, files, author, n_commits, lower_floors, expect_refusal))


# ------------------------------------------------------------------ must fire (rc=1)

# INCIDENT 1, verbatim shape: the constant that was live in the tracked audit workflow.
# The account segment is assembled at runtime so this control file does not itself carry
# a personal identifier -- the same rule the gate is written under.
_ACCT = "e" + "lzai"
case(
    "INCIDENT 1: absolute Windows home path in a tracked script",
    FIRE,
    {
        "scripts/audit/host-security-audit.workflow.js": f"const ROOT = 'C:/Users/{_ACCT}/DEV/zeroclaw-host'\n"
    },
)

# INCIDENT 2: the surface a content scrub cannot reach. The tree is spotless here; the
# only carrier is the commit identity.
case(
    "INCIDENT 2: personal e-mail as commit author, tree otherwise clean",
    FIRE,
    {"README.md": "nothing personal in this tree at all\n"},
    author="someone_real@simplelogin.com",
)

case(
    "posix home under a personal account",
    FIRE,
    {"tools/run.sh": f"cd /home/{_ACCT}/src && cargo build\n"},
)
case(
    "macos home under a personal account",
    FIRE,
    {"docs/NOTES.md": f"the artifact lands in `/Users/{_ACCT}/Downloads`\n"},
)
case(
    "WSL mount carrying the Windows account",
    FIRE,
    {"BUILD.md": f"    cd /mnt/c/Users/{_ACCT}/DEV/zeroclaw-solana\n"},
)
# INCIDENT 4, verbatim shape: this shipped to the public raw URL inside a module docstring
# and sat there behind a green gate. It carries no username and no credential, so every
# other shape in this file misses it by construction. That is the whole reason it needs its
# own pattern rather than being assumed covered.
case(
    "INCIDENT 4: a path into the authoring agent's own config, no username anywhere",
    FIRE,
    {
        "webshop-pay/build.py": (
            '"""The general form is in `~/.claude/rules/'
            'skill-consolidation-extract-diff-first.md`."""\n'
        )
    },
)
case(
    "the same shape without the tilde, as a bare relative path",
    FIRE,
    {"docs/NOTES.md": "cross-checked against .claude/solutions/some-note.md\n"},
)
# MUST-NOT-FIRE control. The pattern is anchored on `.claude/<subdir>/` precisely so it does
# NOT match this repo's own tracked `.claude/` project directory, which is mentioned
# legitimately in real docs. If this ever goes FIRE the pattern was widened into noise, and a
# gate that cries wolf gets routed around, which is worse than not having it.
case(
    "the repo's own .claude project directory, mentioned legitimately",
    CLEAN,
    {
        "README.md": (
            "Project config lives in `.claude/` and the goal file is `.claude/GOAL.md`.\n"
            "Agent worktrees land under `.claude/worktrees/` and are gitignored.\n"
        )
    },
)
case(
    "WSL UNC path",
    FIRE,
    {"docs/env.md": r"open(r'\\wsl$\Ubuntu\home\x\notes.txt')" + "\n"},
)
case(
    "home env expansion",
    FIRE,
    {"setup.ps1": "copy $env:USERPROFILE\\.secrets\\api.env .\n"},
)
case(
    "private key block committed",
    FIRE,
    {"keys/dev.pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n"},
)
case(
    "api token committed",
    FIRE,
    {"config/local.toml": 'anthropic = "sk-ant-' + "A" * 40 + '"\n'},
)
case(
    "personal e-mail in a tracked doc",
    FIRE,
    {"CONTRIBUTING.md": "reach the maintainer at realperson@protonmail.com\n"},
)

# ----------------------------------------------------------------- must NOT fire (rc=0)
# Every one of these is a shape the repo legitimately contains today. If any starts
# firing, the gate has become the boy who cried wolf and will be ignored.

case(
    "container image default user is a role, not a person",
    CLEAN,
    {"scripts/qr_live_server.py": '    ROOT = "/home/ubuntu/zc"\n'},
)
case(
    "CI runner home is a role",
    CLEAN,
    {".github/workflows/ci.yml": "    path: /home/runner/work/target\n"},
)
case(
    "Windows Public profile is a role, not an account",
    CLEAN,
    {"docs/win.md": "installs under `C:/Users/Public/Documents`\n"},
)
case(
    "WhatsApp group JIDs are chat-room ids that look like addresses",
    CLEAN,
    {
        "scripts/test_whatsapp_posture_guard.sh": (
            'run "the live node posture" 0 \'allowed_groups = ["000000000000000000@g.us"]\n'
            'run "a genuinely allowlisted group" 0 \'allowed_groups = ["120363111@g.us"]\n'
        )
    },
)
case(
    "documentation placeholder addresses",
    CLEAN,
    {"docs/QUICKSTART.md": "set it to you@example.com or admin@yourdomain.com\n"},
)
case(
    "noreply commit identity, which is this repo's deliberate posture",
    CLEAN,
    {"README.md": "ordinary content\n"},
    author=NOREPLY,
)
case(
    "a token-shaped word that is too short to be a credential",
    CLEAN,
    {"docs/API.md": "the prefix is `sk-ant-` followed by the key body\n"},
)
# INCIDENT 3: the gate failed on the repo's FIRST pull request, and would have failed on
# every one after it. GitHub commits the synthetic `Merge <head> into <base>` object as
# `GitHub <noreply@github.com>`; that object is reachable from `git log --all` in an
# Actions checkout, belongs to no branch here, and cannot be rewritten by anyone. The
# defect hid because work had gone straight to main until then.
case(
    "GitHub's own machine identity on the synthetic pull-request merge commit",
    CLEAN,
    {"README.md": "ordinary content\n"},
    author="noreply@github.com",
)
# OVER-CORRECTION CONTROL for the case above. The fix is an exact-address allowlist and
# NOT a `github.com` domain entry, so a real person at that domain must still fire. If
# this ever goes CLEAN, the allowlist was widened into a hole.
case(
    "a real person's address at the same domain still fires",
    FIRE,
    {"README.md": "ordinary content\n"},
    author="someone_real@github.com",
)

# The reserved synthetic JID, cleared in FILE CONTENT and not only in commit metadata. Those two
# scans disagreed until now, so the same string meant two different things depending on which
# surface carried it. A fixture proving a recipient gets redacted has to contain a matching
# address, so without this entry the redaction path could not be tested at all.
case(
    "the reserved all-zero JID is not a person, in file content",
    CLEAN,
    {
        "deploy/thing.py": 'r.add("p", False, "would send to 00000000000@s.whatsapp.net")\n'
    },
)
# OVER-CORRECTION CONTROL. `@s.whatsapp.net` is a PHONE NUMBER, unlike `@g.us` which is a room
# id, so the fix has to be an exact address and never a domain rule. A dialable number at that
# same domain must still fire. If this goes CLEAN, the allowlist was widened into a hole and the
# gate has stopped covering the leak it most exists to catch.
case(
    "a dialable number at the same domain still fires",
    FIRE,
    {"deploy/thing.py": 'RECIPIENT = "5511987654321@s.whatsapp.net"\n'},
)

# --------------------------------------------------------------------- the FLOORS
# These deliberately do NOT lower the floors. Without them the floor itself is untested,
# because every case above overrides it to run against a small fixture -- which is exactly
# the shape of defect this gate exists to catch one level up.

case(
    "FLOOR: a tree too small to trust is REFUSED, not passed",
    FIRE,
    {"README.md": "tiny\n"},
    lower_floors=False,
    expect_refusal=True,
)


# ------------------------------------------------------------------------- harness


def build_repo(tmp, files, author, n_commits):
    subprocess.run(
        ["git", "init", "-q", "-b", "main", tmp], check=True, capture_output=True
    )

    def g(*a, env=None):
        e = dict(os.environ)
        e.update(env or {})
        subprocess.run(["git", "-C", tmp, *a], check=True, capture_output=True, env=e)

    g("config", "user.name", "fixture")
    g("config", "user.email", NOREPLY)
    # Filler commits under the canonical identity, so the history-floor cases have a
    # realistic scope and the identity check has a clean majority to sit against.
    for i in range(max(0, n_commits - 1)):
        p = Path(tmp) / f"filler{i}.txt"
        p.write_text(f"filler {i}\n", encoding="utf-8")
        g("add", "-A")
        g("commit", "-q", "-m", f"filler {i}")
    for rel, body in files.items():
        p = Path(tmp) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    g("add", "-A")
    g(
        "commit",
        "-q",
        "-m",
        "the case under test",
        env={
            "GIT_AUTHOR_NAME": "fixture",
            "GIT_AUTHOR_EMAIL": author,
            "GIT_COMMITTER_NAME": "fixture",
            "GIT_COMMITTER_EMAIL": author,
        },
    )


def run_case(name, want, files, author, n_commits, lower_floors, expect_refusal):
    with tempfile.TemporaryDirectory() as tmp:
        build_repo(tmp, files, author, n_commits)
        gate_copy = Path(tmp) / "scripts" / GATE.name
        gate_copy.parent.mkdir(parents=True, exist_ok=True)
        gate_copy.write_text(GATE.read_text(encoding="utf-8"), encoding="utf-8")
        env = dict(os.environ)
        if lower_floors:
            env["CHECK_IDENT_MIN_TRACKED"] = "1"
            env["CHECK_IDENT_MIN_COMMITS"] = "1"
        out = subprocess.run(
            [sys.executable, str(gate_copy)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        blob = (out.stdout or "") + (out.stderr or "")
        refused = "refusing to report" in blob
        if expect_refusal and not refused:
            return (
                False,
                f"expected a REFUSAL over a too-small scope, got rc={out.returncode}",
            )
        if refused and not expect_refusal:
            return False, f"unexpected refusal: {blob.strip()[:160]}"
        if out.returncode != want:
            return (
                False,
                f"want rc={want}, got rc={out.returncode}\n      {blob.strip()[:300]}",
            )
        return True, ""


def main():
    print(f"gate under test: {GATE}")
    npass = nfail = 0
    for name, want, files, author, n_commits, lower_floors, expect_refusal in cases:
        ok, why = run_case(
            name, want, files, author, n_commits, lower_floors, expect_refusal
        )
        if ok:
            npass += 1
            print(f"  PASS  [{'fire ' if want == FIRE else 'clean'}] {name}")
        else:
            nfail += 1
            print(f"  FAIL  [{'fire ' if want == FIRE else 'clean'}] {name}")
            print(f"      {why}")
    print(f"\nRESULT: {npass} passed, {nfail} failed, {len(cases)} total")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
