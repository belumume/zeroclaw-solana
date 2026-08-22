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
    then_clean=None,
    accept_blob_of=None,
    accept_count=None,
    expect_in_output=None,
    env_floors=None,
    local_only_files=None,
):
    """One fixture repo, one gate run, one expected exit code.

    `then_clean` overwrites the named files in a SECOND commit, which is what separates
    the history surface from the tree surface: after it, the tree is spotless and the
    only carrier of the planted identifier is a blob in history.

    `accept_blob_of` is a path whose FIRST-commit blob sha gets injected into the temp
    gate copy's ACCEPTED_HISTORY, so the register can be exercised hermetically. Pass
    `accept_count` to register a deliberately wrong finding count and prove the drift
    guard fires instead of staying silently cleared.

    `env_floors` sets individual floors AFTER `lower_floors` has lowered the rest. Floors
    refuse in order, so a case that lowers none of them only ever exercises the FIRST one
    and every later floor is untestable -- which is how the history floor was shadowed by
    the tracked-file floor and its mutation went unnoticed.

    `local_only_files` land on a branch that exists only locally, with a real bare remote
    set up alongside. A clone never receives them, so they must stay invisible: this is
    what proves the scan is scoped to clone-reachable refs rather than to `--all`.
    """
    cases.append(
        (
            name,
            want,
            files,
            author,
            n_commits,
            lower_floors,
            expect_refusal,
            then_clean,
            accept_blob_of,
            accept_count,
            expect_in_output,
            env_floors,
            local_only_files,
        )
    )


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
# RFC 2606 reserves these four labels as TOP-level, so an address under them can never
# reach a person. Found by the history surface: a git fixture line configuring a test
# identity was being reported as a personal e-mail, which is the false-positive class that
# gets a gate routed around. The pre-existing rule matched `invalid` only as the SECOND
# level in front of a real TLD, so it missed the form that actually occurs.
case(
    "an RFC 2606 reserved TLD is a placeholder, not a person",
    CLEAN,
    {
        "scripts/test_thing.py": (
            '    ("config", "user.email", "x@e.invalid"),\n'
            '    ("config", "alt.email", "someone@fixture.test"),\n'
        )
    },
)
# OVER-CORRECTION CONTROL for the case above. The reserved labels are cleared as TLDs; a
# real address at a real domain must still fire. If this goes CLEAN the arm was widened
# into a hole and the e-mail detector has stopped working.
case(
    "a real address at a real domain still fires after the reserved-TLD fix",
    FIRE,
    {
        "scripts/test_thing.py": '    ("config", "user.email", "realperson@fastmail.com"),\n'
    },
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

# ------------------------------------------------ surface 4: HISTORY BLOB CONTENT
# INCIDENT 5, and the reason surface 4 exists. Every case above plants its identifier in
# the tree, so the tree scan alone satisfies them and none of them can tell the two
# surfaces apart. Here the second commit makes the TREE spotless while history keeps the
# original blob -- which is the exact state the repo was in when the PASS line was
# measured to be overclaiming, and the state a clone still receives.

_CLEAN_BODY = "PASS_EXE = Path(os.environ['PASS_CLI'])\n"

case(
    "INCIDENT 5: identifier committed then removed from the tree, history keeps the blob",
    FIRE,
    {
        "deploy/deploy.py": f"PASS_EXE = Path(r'C:/Users/{_ACCT}/AppData/pass-cli.exe')\n"
    },
    then_clean={"deploy/deploy.py": _CLEAN_BODY},
    expect_in_output="history blob",
)
# CONTROL FOR THE CONTROL. Same two commits, same clean-up, and nothing planted. If this
# ever goes FIRE, the case above is passing because two-commit fixtures always fail rather
# than because a blob was found, and it would prove nothing at all.
case(
    "the same two-commit shape with nothing planted stays clean",
    CLEAN,
    {"deploy/deploy.py": _CLEAN_BODY},
    then_clean={"deploy/deploy.py": "PASS_EXE = Path(os.environ['PASS_CLI'])  # v2\n"},
)
# A binary artifact carrying an identifier, committed and then deleted. `git log -p` prints
# "Binary files differ" and shows NO content for this, so a patch-based history scan misses
# it by construction. Scanning blobs is what reaches it.
case(
    "INCIDENT 5b: a committed BINARY carrying the identifier, later removed",
    FIRE,
    {
        "assets/build.bin": f"\x00\x00MZ\x00fixture C:/Users/{_ACCT}/DEV/x\x00\x00trailer\n"
    },
    then_clean={
        "assets/build.bin": "\x00\x00MZ\x00fixture rebuilt clean\x00\x00trailer\n"
    },
    expect_in_output="history blob",
)

# ------------------------------------------- the ACCEPTED-EXPOSURE register, all 3 ways
# The register must clear the exposure it names, must SAY it did, and must not clear
# anything else. Silent clearance would reintroduce the overclaim one layer down.
case(
    "an ACCEPTED history blob passes, and the run says so out loud",
    CLEAN,
    {
        "deploy/deploy.py": f"PASS_EXE = Path(r'C:/Users/{_ACCT}/AppData/pass-cli.exe')\n"
    },
    then_clean={"deploy/deploy.py": _CLEAN_BODY},
    accept_blob_of="deploy/deploy.py",
    accept_count=2,  # windows home + macos home both match the one path
    expect_in_output="ACCEPTED historical exposure",
)
# OVER-CORRECTION CONTROL. Accepting one blob must not clear a DIFFERENT one. If this goes
# CLEAN the register is a blanket amnesty rather than a per-blob judgement.
case(
    "accepting one blob does not clear a second, unregistered one",
    FIRE,
    {
        "deploy/deploy.py": f"PASS_EXE = Path(r'C:/Users/{_ACCT}/AppData/pass-cli.exe')\n",
        "tools/other.sh": f"cd /home/{_ACCT}/src\n",
    },
    then_clean={
        "deploy/deploy.py": _CLEAN_BODY,
        "tools/other.sh": 'cd "$SRC"\n',
    },
    accept_blob_of="deploy/deploy.py",
    accept_count=2,
    expect_in_output="history blob",
)
# THE DRIFT GUARD, which is the whole reason an entry carries a count rather than being a
# bare sha. A blob is immutable, so a changed finding count means a DETECTOR changed and
# this blob was cleared under a rule that no longer describes it. Registering the wrong
# count here stands in for that: the gate must refuse rather than stay silently cleared.
case(
    "an accepted blob whose finding count no longer matches is CANNOT CHECK, not a pass",
    FIRE,
    {
        "deploy/deploy.py": f"PASS_EXE = Path(r'C:/Users/{_ACCT}/AppData/pass-cli.exe')\n"
    },
    then_clean={"deploy/deploy.py": _CLEAN_BODY},
    accept_blob_of="deploy/deploy.py",
    accept_count=99,
    expect_in_output="CANNOT CHECK",
)

# --------------------------------------------------------------------- the FLOORS
# These deliberately do NOT lower the floors. Without them the floor itself is untested,
# because every case above overrides it to run against a small fixture -- which is exactly
# the shape of defect this gate exists to catch one level up.

# EACH FLOOR ASSERTS ITS OWN MESSAGE, and that is the whole point of `expect_in_output`
# here. Floors refuse in order, so a case that only asks "did something refuse" is
# satisfied by whichever floor happens to fire first, and every later floor is untestable.
# Measured: with these cases asserting only a generic refusal, removing the tracked-file
# floor left the COMMIT floor refusing instead, the case still passed, and the mutation
# control reported the floor as load-bearing when it had just been deleted.
case(
    "FLOOR: a tree too small to trust is REFUSED, not passed",
    FIRE,
    {"README.md": "tiny\n"},
    lower_floors=False,
    expect_refusal=True,
    expect_in_output="discovery found",
)
# The commit floor, in isolation. This is the one a SHALLOW clone trips, and it is why CI
# checks out with fetch-depth 0; it had no case of its own until the floors were separated.
case(
    "FLOOR: a history too short to trust is REFUSED, not passed",
    FIRE,
    {"README.md": "ordinary content\n"},
    env_floors={"CHECK_IDENT_MIN_COMMITS": "50"},
    expect_refusal=True,
    expect_in_output="history walk found",
)
# The history surface needs its own floor, and it is the one a SHALLOW clone trips. A
# depth-1 checkout carries a handful of blobs, which would otherwise scan clean and print
# a PASS asserting something about a history it never read.
#
# THE OTHER TWO FLOORS ARE LOWERED HERE ON PURPOSE. Floors refuse in order, so a case that
# lowers none of them only ever exercises the tracked-file floor and every later floor is
# untestable. Written that way first, this case passed while proving nothing: its mutation
# went unnoticed because the tracked floor refused before the history floor was reached.
case(
    "FLOOR: a history too small to trust is REFUSED, not passed",
    FIRE,
    {
        "deploy/deploy.py": f"PASS_EXE = Path(r'C:/Users/{_ACCT}/AppData/pass-cli.exe')\n"
    },
    then_clean={"deploy/deploy.py": _CLEAN_BODY},
    env_floors={"CHECK_IDENT_MIN_HISTORY_BLOBS": "400"},
    expect_refusal=True,
    expect_in_output="history blob walk found",
)

# ------------------------------------------------- SCOPE: what a clone actually receives
# The scan reads `refs/remotes/origin/*` plus `refs/tags/*`, NOT `--all` and emphatically
# not the raw object store. A local-only branch, a stash and a dangling object all live in
# the store and none of them reaches a clone, so reporting one is a FALSE finding -- the
# direction that gets a real gate loosened rather than the direction that leaks.
#
# Measured on the live repo when this landed: three needle-carrying blobs existed in the
# object store and exactly one was clone-reachable. Scanning the store would have reported
# two exposures no clone can receive.
case(
    "an identifier on a LOCAL-ONLY branch is not a surface a clone receives",
    CLEAN,
    {"README.md": "ordinary content\n"},
    local_only_files={
        "wip/scratch.py": f"SCRATCH = r'C:/Users/{_ACCT}/DEV/notes.txt'\n"
    },
)


# ------------------------------------------------------------------------- harness


def build_repo(tmp, files, author, n_commits, then_clean=None, local_only_files=None):
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
    if then_clean:
        # The second commit is what makes the TREE clean while HISTORY still carries the
        # first commit's blob. Without it, a fixture cannot tell the two surfaces apart.
        for rel, body in then_clean.items():
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        g("add", "-A")
        g("commit", "-q", "-m", "clean it up in the tree, history keeps the blob")

    if local_only_files:
        # A real bare remote, so `refs/remotes/origin/*` exists and means something. main
        # is pushed; the side branch never is. A clone of that remote therefore cannot
        # receive the side branch's blobs, and neither should the gate see them.
        bare = Path(tmp).parent / (Path(tmp).name + "-origin.git")
        subprocess.run(
            ["git", "init", "-q", "--bare", str(bare)], check=True, capture_output=True
        )
        g("remote", "add", "origin", str(bare))
        g("push", "-q", "origin", "main")
        g("checkout", "-q", "-b", "local-only-work")
        for rel, body in local_only_files.items():
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        g("add", "-A")
        g("commit", "-q", "-m", "work that was never pushed")
        g("checkout", "-q", "main")


def run_case(
    name,
    want,
    files,
    author,
    n_commits,
    lower_floors,
    expect_refusal,
    then_clean=None,
    accept_blob_of=None,
    accept_count=None,
    expect_in_output=None,
    env_floors=None,
    local_only_files=None,
):
    with tempfile.TemporaryDirectory() as tmp:
        build_repo(tmp, files, author, n_commits, then_clean, local_only_files)
        gate_copy = Path(tmp) / "scripts" / GATE.name
        gate_copy.parent.mkdir(parents=True, exist_ok=True)
        source = GATE.read_text(encoding="utf-8")

        if accept_blob_of:
            # Blob shas are content-addressed, so the fixture can compute the exact key the
            # gate will see and register it. That is what makes the accepted-exposure path
            # testable without depending on this repo's real history.
            # Hash the FIRST-commit content, taken from `files`. Hashing the path on disk
            # would hash whatever `then_clean` left there, which is the clean body -- the
            # register would then name a blob that carries nothing and clear nothing, and
            # the case would fail for a reason that has nothing to do with the gate.
            #
            # BYTES, not text=True. On Windows `write_text` emits CRLF while `hash-object`
            # normalises under core.autocrlf, so a text-mode stdin hashes a different byte
            # sequence than the object store holds and the key silently never matches.
            sha = (
                subprocess.run(
                    ["git", "hash-object", "--stdin"],
                    input=files[accept_blob_of].encode("utf-8"),
                    capture_output=True,
                    check=True,
                )
                .stdout.decode("ascii")
                .strip()
            )
            n = accept_count if accept_count is not None else 1
            source = source.replace(
                "ACCEPTED_HISTORY = {",
                "ACCEPTED_HISTORY = {\n"
                f'    "{sha}": {{"path": "{accept_blob_of}", "findings": {n},'
                f' "why": "fixture"}},',
                1,
            )
        gate_copy.write_text(source, encoding="utf-8")

        env = dict(os.environ)
        if lower_floors:
            env["CHECK_IDENT_MIN_TRACKED"] = "1"
            env["CHECK_IDENT_MIN_COMMITS"] = "1"
            env["CHECK_IDENT_MIN_HISTORY_BLOBS"] = "1"
        # Applied last, so a case can raise ONE floor back up and exercise it in isolation.
        env.update(env_floors or {})
        out = subprocess.run(
            [sys.executable, str(gate_copy)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        blob = (out.stdout or "") + (out.stderr or "")
        # Case-INSENSITIVE. Two of the three floors open the sentence with "Refusing" and
        # one has it mid-sentence after a semicolon, so a case-sensitive match silently
        # reads a real refusal as an ordinary failure and the floor reads as untested.
        refused = "refusing to report" in blob.lower()
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
        if expect_in_output and expect_in_output not in blob:
            return (
                False,
                f"rc was right but the output never said {expect_in_output!r}; a gate "
                f"that reaches the right exit code by the wrong route is not controlled"
                f"\n      {blob.strip()[:300]}",
            )
        return True, ""


def main():
    print(f"gate under test: {GATE}")
    npass = nfail = 0
    for spec in cases:
        name, want = spec[0], spec[1]
        ok, why = run_case(*spec)
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
