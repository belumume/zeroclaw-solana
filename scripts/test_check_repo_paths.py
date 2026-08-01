"""Controls for check-repo-paths.py, in BOTH directions.

One direction alone is worthless here. Only-must-fire passes for a checker that flags
every reference, which teaches its reader to skip it, and this checker has already been
through that once: its first pass flagged twenty references and every one was a false
positive. Only-must-pass is the state it shipped in until 2026-07-27, where it reported
PASS while a tracked doc named a file no cloner receives.

Case 1 is the real incident shape, copied from the sentence that was live in TESTING.md,
including the "the host" prose that was part of why it slipped through. If that case ever
stops firing, this gate is blind again.

Run: python scripts/test_check_repo_paths.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Overridable so the suite can be pointed at a pre-fix copy of the gate. Driving the
# must-fire cases against the old version is what shows the fix changed something, rather
# than that the new cases happen to agree with it.
GATE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "check-repo-paths.py"

FIRE = 1
PASS = 0

cases = []


def case(name, want, doc_path, body, extra_tracked=(), on_disk_untracked=()):
    cases.append((name, want, doc_path, body, extra_tracked, on_disk_untracked))


# ---------------------------------------------------------------- must fire (rc=1)

# The exact shape that was live in TESTING.md and reported PASS. Three separate defects
# each hid it on their own: the path starts with a dot so the regex never matched it, the
# prose says "the host" so the foreign-citation exemption fired, and the reference sits in
# a doc the checker scanned but a class it could not see.
case(
    "THE INCIDENT SHAPE: undisclosed .tools path with host prose nearby",
    FIRE,
    "TESTING.md",
    "feature and the wrong-direction pre-flight assertion both live in the host and the live\n"
    "config, outside this repo's reach, which is why `.tools/demo-preflight.sh` reads the\n"
    "running daemon's own banner instead.\n",
    on_disk_untracked=(".tools/demo-preflight.sh",),
)

# A path whose own filename carries an attribution word used to exempt itself, because the
# foreign check ran against a window that still contained the path text.
case(
    "self-shielding: dot path whose own name contains 'upstream'",
    FIRE,
    "docs/upstream/whatsapp-policy-fail-open.md",
    "Body as filed: `.tools/upstream-issue-body.md` (audited before posting).\n",
    on_disk_untracked=(".tools/upstream-issue-body.md",),
)

# docs/upstream/ was skipped wholesale, so nothing filed there was ever checked.
case(
    "docs/upstream/ is no longer blanket-skipped",
    FIRE,
    "docs/upstream/some-report.md",
    "Staged at `.devnet-proof/evidence.json` for reference.\n",
    on_disk_untracked=(".devnet-proof/evidence.json",),
)

case(
    "plain undisclosed dot path",
    FIRE,
    "docs/NOTES.md",
    "The capture lives in `.demo-assets/manifest.json`.\n",
    on_disk_untracked=(".demo-assets/manifest.json",),
)

# The behaviour that already worked. If this stops firing, the rewrite broke the original.
case(
    "regression: ordinary untracked path still fires",
    FIRE,
    "docs/NOTES.md",
    "See `scripts/does-not-exist.py` for the runner.\n",
)


# ------------------------------------------------------------ must NOT fire (rc=0)

# An unshipped path may still be named. It has to say so where it is named, so a reader
# arriving at that line learns it there rather than a hundred lines earlier.
case(
    "disclosed dot path: named with its gitignored status adjacent",
    PASS,
    "TESTING.md",
    "daemon's own banner instead. That script, `.tools/demo-preflight.sh`, is gitignored and\n"
    "deliberately not in the tree: it is hardcoded to one machine's home directory.\n",
    on_disk_untracked=(".tools/demo-preflight.sh",),
)

case(
    "a dot path that IS tracked passes without any disclosure",
    PASS,
    "docs/NOTES.md",
    "Config at `.github/workflows/ci.yml` runs every layer.\n",
    extra_tracked=(".github/workflows/ci.yml",),
)

# The foreign-citation exemption has to survive the rewrite, or the checker goes back to
# flagging every legitimate citation of the host's source.
case(
    "foreign citation with attribution prose is still exempt",
    PASS,
    "docs/NOTES.md",
    "The host reads it in `crates/zeroclaw-channels/src/whatsapp_web.rs` before dispatch.\n",
)

case(
    "an ordinary tracked path passes",
    PASS,
    "docs/NOTES.md",
    "The runner is `scripts/mutation-check.sh`.\n",
    extra_tracked=("scripts/mutation-check.sh",),
)


def run_case(name, want, doc_path, body, extra_tracked, on_disk_untracked):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "scripts" / "check-repo-paths.py").write_text(
            GATE.read_text(encoding="utf-8"), encoding="utf-8"
        )
        subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)

        doc = root / doc_path
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(body, encoding="utf-8")

        for rel in extra_tracked:
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("x\n", encoding="utf-8")

        subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True)

        # Written AFTER git add, so they exist on disk and are not in the index. That is
        # the case that matters: it looks fine on the author's machine and breaks in a
        # clone, which is the whole reason this gate exists.
        for rel in on_disk_untracked:
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("x\n", encoding="utf-8")

        # Lower the discovery floor for these fixtures. They are deliberately tiny, a doc or two,
        # so the production floor would refuse every one of them and the must-fire cases would
        # then pass for the FLOOR's reason rather than their own, which is a false green. The
        # floor keeps its own dedicated cases below, driven at the real defaults.
        env = dict(os.environ)
        env["CHECK_REPO_PATHS_MIN_TRACKED"] = "0"
        env["CHECK_REPO_PATHS_MIN_DOCS"] = "0"

        out = subprocess.run(
            [sys.executable, str(root / "scripts" / "check-repo-paths.py")],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        return out.returncode, (out.stdout or "") + (out.stderr or "")


def main():
    if not GATE.exists():
        print(f"gate not found at {GATE}")
        return 2

    npass = nfail = 0
    last_want = None
    for name, want, doc_path, body, extra, ondisk in cases:
        if want != last_want:
            print(f"\nMUST {'FIRE (rc=1)' if want == FIRE else 'NOT FIRE (rc=0)'}:")
            last_want = want
        rc, output = run_case(name, want, doc_path, body, extra, ondisk)
        if rc == want:
            print(f"  ok   {name} (rc={rc})")
            npass += 1
        else:
            print(f"  FAIL {name} (rc={rc} want={want})")
            print("       " + output.strip().replace("\n", "\n       "))
            nfail += 1

    # ------------------------------------------------------ must REFUSE to report (floor)
    # Driven at the PRODUCTION defaults, unlike every case above. Until 2026-08-01 this gate
    # printed "PASS  every repo path named by a tracked doc is itself tracked" and exited 0 over
    # ZERO tracked files, byte-identical to a clean run, while running in CI. Its two siblings
    # exit non-zero on the same input, which is what showed this one was wrong rather than strict.
    # A gate that reports success because it found nothing to check is worse than an absent gate,
    # because the green badge is believed.
    print("\nMUST REFUSE TO REPORT (rc!=0), at production floors:")
    for label, setup in (
        ("empty discovery: a git repo with no files at all", "empty"),
        ("broken discovery: not a git repository", "nogit"),
    ):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "scripts").mkdir(parents=True, exist_ok=True)
            (root / "scripts" / "check-repo-paths.py").write_text(
                GATE.read_text(encoding="utf-8"), encoding="utf-8"
            )
            if setup == "empty":
                subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)
            out = subprocess.run(
                [sys.executable, str(root / "scripts" / "check-repo-paths.py")],
                cwd=root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            blob = (out.stdout or "") + (out.stderr or "")
            # Not merely non-zero: it must NOT have printed the PASS line, since the whole
            # defect was a PASS line over nothing.
            refused = out.returncode != 0 and "PASS  every repo path" not in blob
            if refused:
                print(f"  ok   {label} (rc={out.returncode})")
                npass += 1
            else:
                print(f"  FAIL {label} (rc={out.returncode}) -> {blob.strip()[:160]}")
                nfail += 1

    # OVER-CORRECTION CONTROL. The floor must not swallow the real repository: if this fails,
    # the floor is too high and every genuine run is being refused, which trades a false green
    # for a false red rather than fixing anything.
    real = subprocess.run(
        [sys.executable, str(GATE)],
        cwd=str(HERE.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if real.returncode == 0 and "PASS  every repo path" in (real.stdout or ""):
        print("  ok   over-correction control: the real repository still passes (rc=0)")
        npass += 1
    else:
        print(
            f"  FAIL over-correction control: the floor refuses the REAL repo "
            f"(rc={real.returncode}); it is set too high"
        )
        nfail += 1

    print(f"\n{npass} passed, {nfail} failed")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
