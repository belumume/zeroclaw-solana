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
  4. history blob content   - every version of every file any clone-reachable ref carries

Surface 3 is the one no working-tree check can see, and it is the one that survives a
content scrub, because a scrub rewrites blobs and leaves identities alone.

Surface 4 was added after the PASS line was measured to be overclaiming. Surfaces 1-3 read
the CURRENT tree and commit IDENTITY; they never read a historical blob's CONTENT, which a
clone receives in full. So an identifier committed and then fixed left surfaces 1-3 green
while every clone still carried the original blob. Measured at the time it was added: eight
such blobs, twenty-five findings, sixteen of eighteen carriers reachable from `origin/main`
itself -- a recurring pattern over the repo's life, not a one-off. It is scanned as BLOBS
rather than as patch text because a clone receives objects: `git log -p` renders nothing
for a binary file, nothing for a merge commit by default, and reports one blob twice when
one commit adds it and another removes it.

HONEST CEILING -- what this still cannot see, after surface 4:
  - RENDERED PIXELS inside a committed image or video. Printable strings are read; a
    username visible only as pixels in a screenshot or a demo frame needs an OCR sweep,
    which is tracked separately in the compliance ledger.
  - Objects NOT reachable from a clone-visible ref: a local-only branch, a stash, a
    dangling object. Correct by scope -- a clone never receives them -- but it means a
    clean run here says nothing about an unpushed local branch. Measured when surface 4
    landed: three needle-carrying blobs existed in the local object store and only one was
    clone-reachable, so scanning the raw store instead would have reported two false
    findings, in the direction that gets a real gate loosened.
  - Anything a shape here does not describe. The shape list is a denylist of forms, and a
    novel form passes. `scan_line` is the single place to widen.
  - Content in a ref this clone does not have. A shallow or single-branch clone is caught
    by the floors below, which REFUSE rather than report a result over a scope never read.

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
MIN_HISTORY_BLOBS = int(os.environ.get("CHECK_IDENT_MIN_HISTORY_BLOBS", "400"))

# ACCEPTED HISTORICAL EXPOSURES.
#
# History here is IMMUTABLE by a settled decision, so a finding on surface 4 can never be
# fixed the way a tree finding can. The repo is already public, so a scrub cannot un-expose
# anything; the blast radius of a rewrite crosses every live worktree; `submission/demo-human`
# is protected until the bounty's winners are announced; and the payload is an account name
# and some install paths, NOT a credential, so nothing needs rotating.
#
# That makes every entry below a JUDGEMENT that was made once, recorded, and is re-checked
# on every run -- never a rubber stamp. What the register buys is the fail-on-NEW property:
# an identifier entering a pushed ref goes red while the branch is still rebaseable, which
# is the only window in which history is cheap to fix.
#
# KEYED ON BLOB SHA, and the alternatives were measured rather than assumed:
#   - (commit sha, path) rots and mis-counts. The one known exposure is a SINGLE blob that
#     70de5645 introduced and 0618d54b removed, so a commit key needs two entries for one
#     thing and neither of them points at the content.
#   - (blob sha, shape) also needs two entries for that one line, because `windows home`
#     and `macos home` both match `C:/Users/<acct>/...`. That multiplicity is an artifact of
#     overlapping regexes, not a real distinction.
#   - a bare count is not a key at all: a new leak replacing an old one leaves it satisfied.
# A blob sha is content-addressed, immutable, survives a rename, and is exactly the unit a
# clone receives. `findings` is the guard that closes the one hole a bare blob key leaves:
# a blob's content cannot change, so if the number of findings in it ever does, a detector
# was widened and that blob needs re-auditing rather than silently staying cleared.
ACCEPTED_HISTORY = {
    "38bf02c6683fb7ed9f90bdae17938aeb1a05c8ca": {
        "path": "deploy/deploy_shop_page.py",
        "findings": 2,
        "why": (
            "the account name in a hardcoded Pass CLI path, on ONE line, matched by both "
            "the windows-home and macos-home shapes. Introduced by 70de5645, removed by "
            "0618d54b ('Derive the Pass CLI path instead of shipping the author's home "
            "directory') -- so the identifier is in history precisely BECAUSE a commit "
            "took it out of the tree. Reachable only from submission/demo-human, which is "
            "frozen until winners are announced. The sole entry here carrying an account."
        ),
    },
    "3e3e4d2ef67752e77f0aefedfd3265848a0b505e": {
        "path": "webshop-pay/build.py",
        "findings": 1,
        "why": (
            "a path into the authoring agent's own rules corpus in a module docstring. "
            "This is the incident the 'internal agent-config path' shape was written for; "
            "it shipped to the public raw URL at the time and is already documented as "
            "case 4 of the control suite. Carries no account name and no credential."
        ),
    },
    "864bdd35024b2885f3ea74fed3b56a26f66c5d3f": {
        "path": "docs/SUBMISSION-CAPTURE-RIG.md",
        "findings": 1,
        "why": (
            "the literal env-var name %USERPROFILE% in prose about whether adb had ever "
            "run. The shape is a hygiene marker for home-relative paths; the text contains "
            "no expansion and no account. The file is deliberately untracked now, as a "
            "process/rig document."
        ),
    },
    "ae06df70212a97b9a06efcddffb9217f5a548327": {
        "path": "docs/SUBMISSION-CAPTURE-RIG.md",
        "findings": 1,
        "why": "a second revision of the same document, same single %USERPROFILE% mention.",
    },
    "00f1a2a0a349312f2a3f252ff47f159433b03cc7": {
        "path": "docs/PROMPT-COMPLIANCE-LEDGER.md",
        "findings": 11,
        "why": (
            "references to the authoring agent's own always-loaded corpus while tracing "
            "which standing directive each requirement came from. Filenames and directory "
            "names only: no account, no credential, no host. Now untracked."
        ),
    },
    "9a63c61ed62b8bce9d041c70421edd474bb162f2": {
        "path": "docs/research/claude-security-review-plan.md",
        "findings": 7,
        "why": (
            "plugin-cache and hook paths under the agent config directory, in a plan "
            "evaluating a security plugin. Discloses that the tooling was authored against "
            "an internal corpus, plus some filenames. Now untracked."
        ),
    },
    "982174b1a6d03fbbe9180de4aeed6f4b4e29c132": {
        "path": "docs/research/DELEGATED-TAIL-SYNTHESIS.md",
        "findings": 1,
        "why": "one mention of the same virtualenv path as the plan above. Now untracked.",
    },
    "d5f13da6eed3c030a40c125bc73f59be11468640": {
        "path": "notes/GOAL-zeroclaw-solana-4k.md",
        "findings": 1,
        "why": (
            "one reference to the operator's standing-bar file by name. A filename outside "
            "the repo, no account and no path segment identifying a person. Now untracked."
        ),
    },
}

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
    # A path into the authoring agent's own config. Carries NO username and NO credential,
    # so every shape above misses it by construction, and it shipped to the public raw URL
    # inside a module docstring for days behind a green gate. It discloses only that the
    # tooling was authored against an internal corpus, plus a filename, which is precisely
    # why it reads as scaffolding left in rather than as a breach.
    #
    # Anchored on the `.claude/<subdir>/` shape rather than on the bare word, because
    # `.claude` alone matches this repo's own tracked `.claude/` project directory and
    # would fire on every legitimate mention of it.
    "internal agent-config path": re.compile(
        r"~[/\\]\.claude\b"
        r"|(?<![\w.-])\.claude[/\\](?:rules|skills|hooks|solutions|agents|projects)[/\\]"
        r"|~[/\\]PC[/\\]Downloads"
        r"|standing-excellence-bar",
        re.IGNORECASE,
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
#
# The `\.(?:invalid|test|example|localhost)$` arm is the RFC 2606 reserved TOP-LEVEL set,
# and it is separate from the second-level arm below it on purpose: that one matches
# `invalid` as the SLD in front of a real TLD (`something@invalid.com`) and therefore does
# NOT match `x@e.invalid`, where `invalid` IS the TLD. The history surface found exactly
# that gap -- a git fixture line `("config", "user.email", "<x>@e.invalid")` was reported
# as a personal e-mail. These four labels are permanently unregistrable, so an address
# under them cannot reach a person and cannot collide with one.
IMPERSONAL_EMAIL = re.compile(
    r"@(?:users\.noreply\.github\.com"
    r"|[A-Za-z0-9.-]*\.?(?:invalid|test|example|localhost)"
    r"|(?:example|test|invalid|localhost|domain|yourdomain|company|email)\."
    r"(?:com|org|net|tld)"
    r"|example\.(?:com|org|net)"
    r"|g\.us)$",  # WhatsApp group JIDs: a chat-room id, not a mailbox
    re.IGNORECASE,
)

# Exact addresses, matched WHOLE rather than by domain suffix. `github.com` must never
# join the regex above: that would clear `realperson@github.com` too, and the local part
# is the entire difference between a machine identity and a person.
#
# `noreply@github.com` is GitHub's own committer on web-UI edits AND on the synthetic
# merge commit it builds for every pull request. That merge commit is reachable from
# `git log --all` in an Actions checkout, is not part of this repo's history, and cannot
# be rewritten by anyone here, so without this the gate fails on EVERY pull request by
# construction. It went unnoticed only because work had been pushed straight to main.
#
# `00000000000@s.whatsapp.net` is the reserved synthetic JID for test fixtures. It has to be an
# EXACT entry rather than a domain rule: `@s.whatsapp.net` is a phone number, unlike `@g.us` above
# which is a room id, so clearing the whole domain would disable this gate for the single case it
# most exists to catch. An all-zero local part is not dialable and cannot collide with a person.
# A fixture asserting that a recipient gets redacted must contain a matching address to assert
# anything at all, so the alternative to this entry is a redaction path with no test.
IMPERSONAL_EXACT = frozenset({"noreply@github.com", "00000000000@s.whatsapp.net"})


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
        # Both allowlists, matching the metadata scan below. They disagreed until now: an address
        # cleared as impersonal in commit metadata was still reported in file content, so the same
        # string meant two different things depending on which surface carried it.
        if addr.lower() in IMPERSONAL_EXACT or IMPERSONAL_EMAIL.search(addr):
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
            if (
                not addr
                or addr.lower() in IMPERSONAL_EXACT
                or IMPERSONAL_EMAIL.search(addr)
            ):
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


def git_bytes(args, stdin=b""):
    """git, with a BINARY stdout. `cat-file --batch` streams raw blob bytes."""
    out = subprocess.run(["git", *args], cwd=ROOT, input=stdin, capture_output=True)
    if out.returncode != 0:
        raise SystemExit(
            f"git {' '.join(args)} failed with rc={out.returncode}; refusing to report a "
            f"result over a surface that was never read.\n"
            f"stderr: {out.stderr.decode('utf-8', 'replace').strip()[:400]}"
        )
    return out.stdout


# Same patterns, compiled for bytes. This is a PREFILTER only: a blob that matches nothing
# here cannot produce a finding, so it is skipped without being decoded. Measured on the
# live repo, it took the scan from 10.6s to 6.9s with byte-identical findings (69 across
# 18 blobs both ways). The str patterns below remain the thing that actually reports, so
# there is exactly one detector definition and the two surfaces cannot drift apart.
_PREFILTER = [
    re.compile(rx.pattern.encode(), rx.flags & ~re.UNICODE)
    for rx in (list(HOME_SHAPES.values()) + list(OTHER_SHAPES.values()) + [EMAIL_RE])
]

# Non-printable -> newline, at C speed. The per-byte generator the tracked-file scan uses
# is fine for a few small artifacts and is far too slow for tens of megabytes of history.
_PRINTABLE = bytes(c if 32 <= c < 127 else 10 for c in range(256))


def clone_reachable_refs():
    """The refs a `git clone` of the remote actually delivers.

    NOT `--all`, which includes local-only branches a clone never sees, and emphatically
    not `--batch-all-objects`, which includes the stash and every dangling object. Both
    over-scope into FALSE findings about a developer's own working state, which is the
    direction that gets a real gate loosened.
    """
    refs = [
        r.strip()
        for r in git(
            "for-each-ref", "--format=%(refname)", "refs/remotes/origin", "refs/tags"
        ).split("\n")
        if r.strip() and not r.strip().endswith("/HEAD")
    ]
    if refs:
        return refs, "refs/remotes/origin/* + refs/tags/*"
    # No remote-tracking refs: a fresh `git init`, or a clone with the remote removed.
    # Fall back to every local ref and SAY SO, because the scope claim changes with it.
    return ["--all"], "--all (no remote-tracking refs in this checkout)"


def scan_history_blobs(findings):
    """Surface 4: the CONTENT of every file version any clone-reachable ref carries.

    Returns (n_blobs, n_bytes, accepted_seen, stale_entries).

    Findings whose blob is in ACCEPTED_HISTORY do not go into `findings`; they are counted
    and reported separately, because folding a known exposure into a silent PASS would
    reintroduce, one layer down, the exact overclaim this surface was added to fix.
    """
    refs, scope = clone_reachable_refs()

    paths = {}
    for line in git("rev-list", "--objects", *refs).split("\n"):
        line = line.rstrip()
        if " " in line:
            sha, path = line.split(" ", 1)
            paths.setdefault(sha, set()).add(path)

    # `rev-list --objects` lists commits and trees too; keep only the blobs.
    check = git_bytes(
        ["cat-file", "--batch-check"], stdin=("\n".join(paths) + "\n").encode()
    ).decode("utf-8", "replace")
    blobs = [
        parts[0]
        for parts in (ln.split() for ln in check.split("\n"))
        if len(parts) == 3 and parts[1] == "blob"
    ]
    if len(blobs) < MIN_HISTORY_BLOBS:
        raise SystemExit(
            f"history blob walk found {len(blobs)} blob(s) over {scope}, expected at "
            f"least {MIN_HISTORY_BLOBS}. A shallow or single-branch clone produces exactly "
            f"this. Refusing to report a result over a scope this small."
        )

    stream = git_bytes(
        ["cat-file", "--batch"], stdin=("\n".join(blobs) + "\n").encode()
    )

    accepted_seen = {}
    n_blobs = n_bytes = 0
    i = 0
    while i < len(stream):
        nl = stream.find(b"\n", i)
        if nl < 0:
            break
        header = stream[i:nl].split()
        if len(header) != 3:
            break
        sha, size = header[0].decode("ascii", "replace"), int(header[2])
        body = stream[nl + 1 : nl + 1 + size]
        i = nl + 1 + size + 1
        n_blobs += 1
        n_bytes += size

        where = paths.get(sha, set())
        # Self-exclusion, same rule and same reasoning as the tracked scan: this gate's own
        # source and fixtures necessarily contain the shapes they detect. Requires EVERY
        # path the blob ever had to be a self path, so a blob shared with some other file
        # cannot be excluded by association.
        if where and where <= SELF_PATHS:
            continue

        if b"\0" in body[:8192]:
            body = body.translate(_PRINTABLE)
        if not any(rx.search(body) for rx in _PREFILTER):
            continue

        text = body.decode("utf-8", "replace")
        hits = [
            (shape, detail)
            for line in text.split("\n")
            for shape, detail in scan_line(line)
        ]
        if not hits:
            continue

        if sha in ACCEPTED_HISTORY:
            accepted_seen[sha] = len(hits)
            continue

        shown = sorted({s for s, _ in hits})
        findings.append(
            (
                f"history blob {sha[:12]} ({'; '.join(sorted(where)) or 'unnamed'})",
                ", ".join(shown),
                f"{len(hits)} finding(s) in a blob every clone receives; NOT in the "
                f"accepted register",
            )
        )

    # An accepted entry that is no longer reachable is GOOD NEWS -- the branch carrying it
    # was deleted, so the exposure is gone. It must not fail the gate; it must ask for the
    # entry to be removed, or the register rots into a list of things that stopped existing.
    stale = [sha for sha in ACCEPTED_HISTORY if sha not in accepted_seen]
    return n_blobs, n_bytes, accepted_seen, stale, scope


def main():
    findings = []
    n_files, n_bin = scan_tracked(findings)
    n_commits = scan_commit_metadata(findings)
    n_blobs, n_hbytes, accepted_seen, stale, scope = scan_history_blobs(findings)

    print(
        f"surfaces read: {n_files} tracked file(s) ({n_bin} binary), "
        f"{n_commits} commit(s) across all refs, "
        f"{n_blobs} history blob(s) / {n_hbytes:,} B over {scope}"
    )

    # An accepted exposure is REPORTED, never swallowed. A register that passes silently
    # would make the PASS line overclaim in exactly the way surface 4 was added to fix.
    if accepted_seen:
        total = sum(accepted_seen.values())
        print(
            f"\n{len(accepted_seen)} ACCEPTED historical exposure(s), {total} finding(s). "
            f"Present in history, unfixable without a rewrite, each reviewed once:"
        )
        for sha, n in sorted(accepted_seen.items()):
            entry = ACCEPTED_HISTORY[sha]
            print(f"  {sha[:12]}  {entry['path']}  ({n} finding(s))")
            print(f"      {entry['why']}")
    if stale:
        print(
            f"\n{len(stale)} accepted entr(ies) no longer reachable -- the exposure is "
            f"GONE and the register should drop them:"
        )
        for sha in sorted(stale):
            print(f"  {sha[:12]}  {ACCEPTED_HISTORY[sha]['path']}")

    # A blob's content is immutable, so a changed finding count means a DETECTOR changed
    # and this blob was cleared under a rule that no longer describes it. Re-audit rather
    # than stay silently cleared -- the one hole a bare content-addressed key would leave.
    drifted = [
        (sha, ACCEPTED_HISTORY[sha]["findings"], n)
        for sha, n in accepted_seen.items()
        if n != ACCEPTED_HISTORY[sha]["findings"]
    ]
    if drifted:
        print(
            f"\nCANNOT CHECK: {len(drifted)} accepted blob(s) now yield a different "
            f"number of findings than was reviewed. A blob cannot change, so a detector "
            f"did. Re-audit each and update its `findings` count:"
        )
        for sha, was, now in drifted:
            print(f"  {sha[:12]}  reviewed {was}, now {now}")
        return 1

    if not findings:
        if accepted_seen:
            print(
                f"\nPASS  no NEW personal identifier. Tracked tree and commit metadata "
                f"are clean; history carries {sum(accepted_seen.values())} accepted "
                f"finding(s) listed above."
            )
        else:
            print(
                "PASS  no personal identifier in the tracked tree, in commit metadata, "
                "or in any history blob a clone receives"
            )
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
    print(
        "A finding in a HISTORY BLOB is not fixable by editing the tree either, and the "
        "cheap moment is NOW: while the branch carrying it is unmerged and unpushed, "
        "`git rebase -i` or `git commit --amend` removes the blob for free. Once it is on "
        "a pushed ref the only remedies are a rewrite or an entry in ACCEPTED_HISTORY, "
        "and an entry is a judgement to argue for, not a way to make this line go away."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
