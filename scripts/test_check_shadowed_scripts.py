"""Controls for check-shadowed-scripts.py, in all three directions.

Two directions is the usual bar and it is not enough for this gate. Must-fire alone passes for a
checker that flags every pair, which teaches its reader to skip it. Must-not-fire alone is the
state the repo was already in: this gate printed a clean line on every run for as long as it
existed, while looking at 112 of 271 gitignored scripts and leaving two tracked scripts
unprotectable.

The third bucket is the one most suites omit. A gate that cannot read its own inputs must not
report the same thing as a gate that read them and found nothing, because those are
indistinguishable downstream and only one is good news. Cases 8 through 10 assert it degrades to
2 rather than to 0.

CASE 1 IS THE REAL DRIFT SHAPE, and the mapping is worth stating rather than overclaiming. The
historical incident was `webshop-pay/build.py` carrying its own stale copy of the markup while
`index.html` accumulated four fixes, which `build.py --check` is what catches. What THIS gate owns
is the second-copy half of the same class: a generator living somewhere a reader cannot reach,
diverging from the tracked one. It could not see that file at all until 2026-07-27, because the
tracked scope was two directory prefixes and `webshop-pay/` was neither. If case 1 stops firing,
the tracked side has been re-narrowed and the canonical case is out of scope again.

CASE 2 AND CASE 3 are the two halves of the ignored-side blindness. Case 2 is the repo root, where
150 of this tree's gitignored scripts actually live and the old list looked at none. Case 3 is a
path two levels deep, which the old non-recursive walk could not reach even for a directory that
WAS listed.

Run: python scripts/test_check_shadowed_scripts.py [path/to/a/copy/of/the/gate]
"""

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Overridable so the suite can be pointed at a pre-fix copy of the gate. Driving the must-fire
# cases against an older version is what shows a change did something, rather than that the new
# cases happen to agree with the new code.
GATE = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "check-shadowed-scripts.py"

FIRE = 1
CLEAN = 0
CANNOT = 2


def lines(*body):
    return "\n".join(body) + "\n"


# The tracked pay-page generator, trimmed to its load-bearing shape. Assembling from vendored
# sources is exactly the state the incident produced, so an ignored copy predating it is the
# realistic diverged sibling rather than an invented one.
BUILD_PY = lines(
    "import sys",
    "from pathlib import Path",
    "HERE = Path(__file__).resolve().parent",
    "SRC = HERE / 'src'",
    "OUT = HERE / 'index.html'",
    "def read(name):",
    "    p = SRC / name if name != 'qrcode.js' else HERE / name",
    "    if not p.is_file():",
    "        raise SystemExit(f'missing source part: {p}')",
    "    return p.read_text(encoding='utf-8')",
    "html = read('head.html') + read('body.html') + read('app.js') + read('tail.html')",
    "if '--check' in sys.argv:",
    "    if OUT.read_text(encoding='utf-8') != html:",
    "        raise SystemExit('FAIL index.html does not match its sources')",
    "    print('OK index.html matches its sources')",
    "else:",
    "    OUT.write_text(html, encoding='utf-8')",
)

# The same file before the sources were extracted: still carries the markup inline, so it shares
# most of its body with the tracked one and differs exactly where the fixes landed. This is the
# copy that reverts four fixes if anyone runs it.
BUILD_PY_STALE = lines(
    "import sys",
    "from pathlib import Path",
    "HERE = Path(__file__).resolve().parent",
    "SRC = HERE / 'src'",
    "OUT = HERE / 'index.html'",
    "def read(name):",
    "    p = SRC / name if name != 'qrcode.js' else HERE / name",
    "    if not p.is_file():",
    "        raise SystemExit(f'missing source part: {p}')",
    "    return p.read_text(encoding='utf-8')",
    "MERCHANT = 'not-pinned-yet'",
    "html = '<html><body>Pay with Solana</body></html>'",
    "if '--check' in sys.argv:",
    "    print('OK')",
    "else:",
    "    OUT.write_text(html, encoding='utf-8')",
)

# A tracked script under scripts/, which the OLD scope did cover. Present in every fixture so a
# case that fires proves the widening did it, rather than proving the gate works at all.
CHECK_REPO_PATHS = lines(
    "import subprocess",
    "import sys",
    "from pathlib import Path",
    "ROOT = Path(__file__).resolve().parent.parent",
    "def tracked():",
    "    out = subprocess.run(['git', 'ls-files'], cwd=ROOT, capture_output=True, text=True)",
    "    return set(out.stdout.split(chr(10))) - {''}",
    "def main():",
    "    files = tracked()",
    "    print(f'PASS {len(files)} tracked')",
    "    return 0",
    "sys.exit(main())",
)

GITIGNORE = lines(
    ".tools/",
    ".stage/",
    ".devnet-proof/",
    "target/",
    "node_modules/",
    ".rootcopy.sh",
    ".rootcopy.py",
)

# Every fixture carries these unless it is deliberately probing their absence. The gate refuses to
# run without them, which is the point: being in scope is what makes being compared possible.
ANCHOR = [
    (".gitignore", GITIGNORE),
    ("scripts/check-repo-paths.py", CHECK_REPO_PATHS),
    ("webshop-pay/build.py", BUILD_PY),
]

cases = []


def case(name, want, tracked, ignored):
    cases.append((name, want, tracked, ignored))


# ---------------------------------------------------------------- must fire (rc=1)

# The tracked side used to be two directory prefixes, and `webshop-pay/` was neither, so this pair
# was invisible however correct the comparison logic was.
case(
    "THE INCIDENT SHAPE: an ignored staging copy of the pay-page generator, diverged",
    FIRE,
    ANCHOR,
    [(".stage/build.py", BUILD_PY_STALE)],
)

# 150 of this tree's gitignored scripts sit at the repo root. The old list named one directory and
# the root was not it.
case(
    "THE ROOT SHAPE: a gitignored script at the repo root, not inside any listed directory",
    FIRE,
    ANCHOR,
    [(".rootcopy.py", CHECK_REPO_PATHS)],
)

# `.tools/` WAS listed, and a one-level walk still could not reach this. Listing a directory and
# scanning it are different claims.
case(
    "THE DEPTH SHAPE: two levels below an ignored directory that was already listed",
    FIRE,
    ANCHOR,
    [(".devnet-proof/oracle-arm/setup_build.sh", CHECK_REPO_PATHS)],
)


# ------------------------------------------------------------ must NOT fire (rc=0)

# A gate that flags anything sharing a few import lines is a gate nobody runs. The real tree's
# highest overlap is 0.214 against a 0.5 threshold, so this margin is the one that matters.
case(
    "an ignored script that merely shares boilerplate imports passes",
    CLEAN,
    ANCHOR,
    [
        (
            ".tools/unrelated.py",
            lines(
                "import subprocess",
                "import sys",
                "from pathlib import Path",
                "def publish(seq):",
                "    payload = {'sequence': seq, 'unit': 'celsius'}",
                "    return subprocess.run(['solana', 'confirm'], input=str(payload))",
                "for n in range(3):",
                "    publish(n)",
            ),
        )
    ],
)

# Below the floor there is no body to compare, and a two-line wrapper matching a two-line wrapper
# is a coincidence rather than a copy.
case(
    "a short ignored wrapper is not signal",
    CLEAN,
    ANCHOR,
    [(".tools/tiny.sh", lines("set -e", "exec cargo test"))],
)

# Vendored build output is not a copy of our work that will drift. Excluding it by directory name
# keeps our own new directories in scope by default.
case(
    "an identical copy inside vendored build output is out of scope",
    CLEAN,
    ANCHOR,
    [
        ("target/debug/build.py", BUILD_PY),
        ("node_modules/pkg/build.py", BUILD_PY),
    ],
)

# This is the state of a fresh clone and of every CI run, so reading it as a broken derivation
# would make the gate permanently red where it is actually deployed.
case(
    "no ignored scripts at all is a fresh clone, not a broken derivation",
    CLEAN,
    ANCHOR,
    [],
)


# ------------------------------------------- must NOT report clean when it cannot check (rc=2)

# The re-narrowing case. If the tracked scope goes back to directory prefixes, the canary is gone
# and the gate refuses rather than printing the reassuring line about a file it can no longer see.
case(
    "DEGRADE: the canonical case missing from the tracked derivation cannot pass",
    CANNOT,
    [(".gitignore", GITIGNORE), ("scripts/check-repo-paths.py", CHECK_REPO_PATHS)],
    [(".stage/build.py", BUILD_PY_STALE)],
)

# Tracked files exist and none survives the floor, so every ignored script is compared against an
# empty set and nothing can ever match. That prints clean today and asserts nothing.
case(
    "DEGRADE: nothing on the tracked side clears the line floor",
    CANNOT,
    [
        (".gitignore", GITIGNORE),
        ("scripts/check-repo-paths.py", lines("import sys")),
        ("webshop-pay/build.py", lines("import sys")),
    ],
    [(".stage/build.py", BUILD_PY_STALE)],
)

# The instrument itself failing. `git ls-files` outside a repo returns nothing on stdout, which
# used to become "0 tracked scanned" beside the same clean sentence a real pass prints.
case(
    "DEGRADE: not a git repository at all",
    CANNOT,
    None,  # skip git init entirely
    [],
)


def run_case(name, want, tracked, ignored):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "scripts" / "check-shadowed-scripts.py").write_text(
            GATE.read_text(encoding="utf-8"), encoding="utf-8"
        )

        if tracked is not None:
            subprocess.run(["git", "init", "-q"], cwd=root, capture_output=True)
            for rel, body in tracked:
                f = root / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(body, encoding="utf-8")
            subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True)

        # Written AFTER git add and matched by .gitignore, so they are on disk and absent from the
        # index. That is the case that matters: it looks fine to the author and is invisible to a
        # cloner.
        for rel, body in ignored:
            f = root / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body, encoding="utf-8")

        out = subprocess.run(
            [sys.executable, str(root / "scripts" / "check-shadowed-scripts.py")],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return out.returncode, (out.stdout or "") + (out.stderr or "")


LABEL = {
    FIRE: "FIRE (rc=1)",
    CLEAN: "NOT FIRE (rc=0)",
    CANNOT: "REFUSE TO PASS (rc=2)",
}


def main():
    if not GATE.exists():
        print(f"gate not found at {GATE}")
        return 2

    npass = nfail = 0
    last_want = None
    for name, want, tracked, ignored in cases:
        if want != last_want:
            print(f"\nMUST {LABEL[want]}:")
            last_want = want
        rc, output = run_case(name, want, tracked, ignored)
        if rc == want:
            print(f"  ok   {name} (rc={rc})")
            npass += 1
        else:
            print(f"  FAIL {name} (rc={rc} want={want})")
            print("       " + output.strip().replace("\n", "\n       "))
            nfail += 1

    print(f"\n{npass} passed, {nfail} failed")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
