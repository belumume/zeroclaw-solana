"""Pre-publication audit: does any surface a clone receives carry a personal identifier?

A leak survives on more surfaces than the one that gets fixed. This repo has already
had an absolute home path in a tracked script, found by hand and scrubbed from both the
working tree and the history. Nothing then checked the OTHER surfaces, and a name-keyed
sweep cannot: it misses a file that cites the same person by a different identifier.

So this keys on the SHAPE an identifier leaves, never on a literal name, and walks every
surface a `git clone` actually delivers:

  1. tracked text files     - source, docs, fixtures, lockfiles, CI config
  2. tracked binary files   - printable strings inside committed artifacts
  3. commit metadata        - author and committer identity on every reachable commit

Surface 3 is the one no working-tree check can see, and it is the one that survives a
content scrub, because a scrub rewrites blobs and leaves identities alone.

This file deliberately contains NO personal identifier of its own. A denylist that names
what it protects publishes it the moment the repo goes public, so every rule here is
either a shape or a positive allowlist.

Reports only. Nothing here mutates the tree or the history.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A DETECTOR AND ITS FIXTURES NECESSARILY CONTAIN THE SHAPES THEY DETECT, so scanning them
# reports this gate's own pattern list and its own synthetic test data as leaks. Left in, the
# gate is red on a clean tree forever, which is how a gate stops being read.
#
# Self-exclusion IS a hole, so it is bounded to exactly two paths and earns it two ways:
#   1. the fixtures are provably SYNTHETIC -- verified against the live values rather than by
#      eye: the file contains neither the real git-email local-part nor the real OS username;
#   2. `test_check_identifier_leaks.py` drives the detectors directly, so a pattern that stopped
#      working fails there loudly rather than being hidden by this skip.
# Anything beyond these two files is scanned, including any future detector added elsewhere.
SELF_PATHS = frozenset(
    {
        "scripts/check-identifier-leaks.py",
        "scripts/test_check_identifier_leaks.py",
    }
)

# Floors, same reasoning as the sibling gates: a discovery step that breaks returns an
# empty set, every loop below is skipped, and the result is a PASS line byte-identical to
# a clean run. A gate that reports success because it found nothing to check is worse than
# no gate, because the green is believed. Set far below the live numbers and far above
# zero, which is the only value the defect actually produces.
MIN_TRACKED = int(os.environ.get("CHECK_IDENT_MIN_TRACKED", "100"))
MIN_COMMITS = int(os.environ.get("CHECK_IDENT_MIN_COMMITS", "50"))

# A home directory is the highest-signal shape: it carries an account name, it is never
# needed for a path that ships, and it is what the earlier incident actually was.
HOME_SHAPES = {
    "windows home": re.compile(r"[A-Za-z]:[/\\]+Users[/\\]+([A-Za-z0-9._-]+)"),
    "posix home": re.compile(r"/home/([A-Za-z0-9._-]+)"),
    "macos home": re.compile(r"/Users/([A-Za-z0-9._-]+)"),
    "wsl mount": re.compile(r"/mnt/[a-z]/Users/([A-Za-z0-9._-]+)", re.IGNORECASE),
}

OTHER_SHAPES = {
    "wsl unc path": re.compile(r"\\\\wsl[$.][^\s\"'<>|]*", re.IGNORECASE),
    "home env expansion": re.compile(r"%USERPROFILE%|\$env:USERPROFILE", re.IGNORECASE),
    "private key block": re.compile(
        r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY"
    ),
    "api token": re.compile(
        r"sk-ant-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}"
        r"|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}"
        r"|xox[bpas]-[A-Za-z0-9-]{10,}|AKIA[A-Z0-9]{16}"
        r"|hf_[A-Za-z0-9]{30,}|nvapi-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{35}"
    ),
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Account names that identify a machine role rather than a person. A CI image, a container
# user and a cloud image default all legitimately appear in a path that ships.
ROLE_ACCOUNTS = {
    "runner",
    "runneradmin",
    "ubuntu",
    "root",
    "user",
    "users",
    "public",
    "default",
    "administrator",
    "vagrant",
    "docker",
    "node",
    "app",
    "ec2-user",
    "opc",
    "home",
    "username",
    "youruser",
    "someuser",
    "example",
    "test",
}

# Address shapes that carry no personal identity. GitHub's noreply form is the deliberate
# posture for this repo's commits; the rest are documentation placeholders.
IMPERSONAL_EMAIL = re.compile(
    r"@(?:users\.noreply\.github\.com"
    r"|(?:example|test|invalid|localhost|domain|yourdomain|company|email)\."
    r"(?:com|org|net|tld)"
    r"|example\.(?:com|org|net)"
    r"|g\.us)$",  # WhatsApp group JIDs: a chat-room id, not a mailbox
    re.IGNORECASE,
)


def git(*args, check=True):
    out = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and out.returncode != 0:
        raise SystemExit(
            f"git {' '.join(args)} failed with rc={out.returncode}; refusing to report a "
            f"result over a surface that was never read.\nstderr: {out.stderr.strip()[:400]}"
        )
    return out.stdout


def scan_line(line):
    """Yield (shape, detail) for every personal identifier shape on one line."""
    for shape, rx in HOME_SHAPES.items():
        for m in rx.finditer(line):
            account = m.group(1)
            if account.lower() in ROLE_ACCOUNTS:
                continue
            yield shape, f"account {account!r} in {m.group(0)!r}"
    for shape, rx in OTHER_SHAPES.items():
        for m in rx.finditer(line):
            hit = m.group(0)
            # Never echo a whole credential into CI output.
            if shape == "api token":
                hit = hit[:10] + "..."
            yield shape, hit
    for m in EMAIL_RE.finditer(line):
        addr = m.group(0)
        if IMPERSONAL_EMAIL.search(addr):
            continue
        yield "personal email", addr


def scan_tracked(findings):
    files = [f for f in git("ls-files").split("\n") if f and f not in SELF_PATHS]
    if len(files) < MIN_TRACKED:
        raise SystemExit(
            f"discovery found {len(files)} tracked file(s), expected at least "
            f"{MIN_TRACKED}. The walk is broken; refusing to report a result over a "
            f"scope this small."
        )
    binaries = 0
    for rel in files:
        p = ROOT / rel
        if not p.is_file():
            continue
        raw = p.read_bytes()
        if b"\0" in raw[:8192]:
            # A committed artifact ships verbatim, so its printable strings are a real
            # surface. This does NOT cover rendered pixels inside a container; frames
            # need a separate OCR sweep and one is recorded in the compliance ledger.
            binaries += 1
            text = bytes(c if 32 <= c < 127 else 10 for c in raw).decode(
                "ascii", "replace"
            )
            for line in text.split("\n"):
                if len(line) < 4:
                    continue
                for shape, detail in scan_line(line):
                    findings.append((f"{rel} (binary strings)", shape, detail))
            continue
        text = raw.decode("utf-8", "replace")
        for n, line in enumerate(text.split("\n"), 1):
            for shape, detail in scan_line(line):
                findings.append((f"{rel}:{n}", shape, detail))
    return len(files), binaries


def scan_commit_metadata(findings):
    """The surface a content scrub cannot reach.

    Rewriting blobs leaves author and committer identity untouched, so an identity
    configured before the repo adopted its noreply posture survives every tree-level
    fix and becomes visible in `git log` the moment the repo is public.
    """
    raw = git("log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce")
    rows = [r for r in raw.split("\n") if r.strip()]
    if len(rows) < MIN_COMMITS:
        raise SystemExit(
            f"history walk found {len(rows)} commit(s), expected at least {MIN_COMMITS}. "
            f"Refusing to report a result over a scope this small."
        )
    bad = {}
    for row in rows:
        parts = row.split("\x1f")
        if len(parts) != 5:
            continue
        sha, an, ae, cn, ce = parts
        for _role, addr in (("author", ae), ("committer", ce)):
            if not addr or IMPERSONAL_EMAIL.search(addr):
                continue
            # Keyed on SHA, not appended per role: one commit carries BOTH an author and
            # a committer identity, so appending each would report twice the number of
            # affected commits. A count is a claim, and this one names commits.
            bad.setdefault(addr, set()).add(sha[:9])
    for addr, shas in bad.items():
        shas = sorted(shas)
        findings.append(
            (
                f"commit metadata ({len(shas)} commit(s), e.g. {shas[0]})",
                "identity email",
                f"{addr} - not a noreply address, visible in `git log` once public",
            )
        )
    return len(rows)


def main():
    findings = []
    n_files, n_bin = scan_tracked(findings)
    n_commits = scan_commit_metadata(findings)

    print(
        f"surfaces read: {n_files} tracked file(s) ({n_bin} binary), "
        f"{n_commits} commit(s) across all refs"
    )

    if not findings:
        print("PASS  no personal identifier on any surface a clone receives")
        return 0

    print(f"\n{len(findings)} identifier finding(s):\n")
    for where, shape, detail in findings:
        print(f"  {where}")
        print(f"      [{shape}] {detail}")
    print(
        "\nA finding in commit metadata is NOT fixable by editing the tree. It needs a "
        "history rewrite (git filter-repo --mailmap) and a force-push, done while the "
        "repo is still private so the old objects were never publicly reachable by SHA."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
