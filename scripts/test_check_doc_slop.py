"""Controls for check-doc-slop.py, in all three directions.

Every exemption this gate carries is a NARROWING, and a narrowing is indistinguishable from a
disabled gate if the only evidence is that the tree went quiet. So each skip is paired here with
a case that shares its vocabulary and differs only in the discriminating feature, and that case
must still FIRE. Without the pair, the suite would prove the gate got quieter and nothing else.

The three buckets:

  MUST FIRE      slop in ordinary prose, and slop one line outside each exemption.
  MUST NOT FIRE  the exempted regions themselves, including the injection transcript verbatim.
  MUST REFUSE    a scope too small to trust, a fence that never closes, a dead vendored path.

The third bucket is the one most suites omit. A gate that could not read its inputs must not
report what a gate that read them and found nothing reports, because downstream those are the
same green and only one is good news. These assert it degrades to 2, never to 0.

CASE 4 IS THE ONE THAT MATTERS MOST. docs/transcripts/injection-refund-redirect.md is the
prompt-injection evidence the brief requires, and its six em-dashes are inside the agent's
recorded replies. If case 4 stops passing, the gate is asking someone to edit evidence. If case 5
stops firing, the blockquote skip has widened into a whole-file exemption and that document is no
longer checked at all.

Fixtures are temporary git repositories, so no case mutates the tracked tree. The two vendored
paths are copied in from the real repo, which means every fixture also exercises the vendored
baseline rather than leaving that branch to the one case that names it.

Run: python3 scripts/test_check_doc_slop.py
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
# Overridable so the suite can be pointed at a pre-fix copy of the gate. Driving the must-fire
# cases against an older build is what shows a change did something, rather than that the new
# cases happen to agree with the new code.
GATE = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else HERE / "check-doc-slop.py"

CLEAN = 0
FIRE = 1
CANNOT = 2

EM = "—"
ARROW = "→"

VENDORED = ["wit/VERSIONING.md", "wit/v0/README.md"]

results = []


def record(name, ok, detail):
    results.append((name, ok, detail))
    print(f"  {'pass' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"        {detail}")


def run_gate(cwd, min_docs=None):
    cmd = [sys.executable, str(GATE)]
    if min_docs is not None:
        cmd += ["--min-docs", str(min_docs)]
    out = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return out.returncode, (out.stdout or "") + (out.stderr or "")


def make_repo(tmp, docs):
    """A git repo whose index holds `docs` plus the two real vendored files."""
    root = Path(tmp)
    for rel in VENDORED:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, dst)
    for rel, body in docs.items():
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(body, encoding="utf-8", newline="\n")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    # Fixtures are written LF and must stay LF. Without this the suite inherits a developer's
    # global core.autocrlf and floods the run with conversion warnings, which is noise in CI and
    # would also change the bytes the gate reads on a machine configured differently.
    subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    return root


def case(name, docs, expect_code, expect_in=None, expect_not_in=None, min_docs=1):
    with tempfile.TemporaryDirectory() as tmp:
        root = make_repo(tmp, docs)
        code, out = run_gate(root, min_docs=min_docs)
        ok = code == expect_code
        detail = f"expected exit {expect_code}, got {code}; output: {out.strip()[:300]}"
        if ok and expect_in:
            ok = expect_in in out
            detail = f"expected {expect_in!r} in output; got: {out.strip()[:300]}"
        if ok and expect_not_in:
            ok = expect_not_in not in out
            detail = (
                f"did not expect {expect_not_in!r} in output; got: {out.strip()[:300]}"
            )
        record(name, ok, detail)


def main():
    print(f"controls for {GATE.name}")

    # ---------------------------------------------------------------- must not fire
    case(
        "1  clean prose passes",
        {"README.md": "# Title\n\nOrdinary prose with no markers in it at all.\n"},
        CLEAN,
        expect_in="clean",
    )

    case(
        "2  an em-dash inside a fenced code block is exempt",
        {
            "README.md": "# Title\n\nOrdinary prose.\n\n```\nzeroclaw run "
            + EM
            + " flag\n```\n"
        },
        CLEAN,
    )

    case(
        "3  an em-dash inside a blockquote is exempt",
        {
            "README.md": "# Title\n\nOrdinary prose.\n\n> quoted reply "
            + EM
            + " verbatim\n"
        },
        CLEAN,
    )

    # The real artifact, verbatim, not a minimized stand-in. Its six em-dashes are the agent's
    # recorded replies and rewriting them would falsify the evidence the brief asks for.
    transcript = (REPO / "docs/transcripts/injection-refund-redirect.md").read_text(
        encoding="utf-8"
    )
    quoted = sum(1 for line in transcript.split("\n") if line.startswith(">"))
    dashes = transcript.count(EM)
    case(
        f"4  the injection transcript verbatim ({dashes} em-dashes, {quoted} quoted lines)",
        {"docs/transcripts/injection-refund-redirect.md": transcript},
        CLEAN,
    )

    # ---------------------------------------------------------------- must fire
    case(
        "5  an em-dash in ordinary prose fires (over-correction control)",
        {"README.md": "# Title\n\nOrdinary prose " + EM + " with a planted marker.\n"},
        FIRE,
        expect_in="em_dashes",
    )

    # Case 5 shares its vocabulary with cases 2 and 3 and differs only in position. Together they
    # show the skips are scoped to the region rather than to the file.
    case(
        "6  an em-dash OUTSIDE a fence in a fenced document still fires",
        {
            "README.md": "# Title\n\nProse "
            + EM
            + " planted.\n\n```\nzeroclaw run "
            + EM
            + "\n```\n"
        },
        FIRE,
        expect_in="em_dashes",
    )

    case(
        "7  an em-dash OUTSIDE a blockquote in a quoted document still fires",
        {
            "README.md": "# Title\n\nProse "
            + EM
            + " planted.\n\n> quoted "
            + EM
            + " reply\n"
        },
        FIRE,
        expect_in="em_dashes",
    )

    # The blockquote skip must not turn the required transcript into an unchecked file.
    case(
        "8  slop added to the transcript OUTSIDE its quotes still fires",
        {
            "docs/transcripts/injection-refund-redirect.md": transcript
            + "\n\nA later note "
            + EM
            + " added outside every quote.\n"
        },
        FIRE,
        expect_in="injection-refund-redirect",
    )

    case(
        "9  flagged vocabulary in ordinary prose fires",
        {"README.md": "# Title\n\nThis is a robust and comprehensive result.\n"},
        FIRE,
        expect_in="flagged_vocab",
    )

    case(
        "10 rogue unicode in ordinary prose fires",
        {"README.md": "# Title\n\nfirst " + ARROW + " second\n"},
        FIRE,
        expect_in="rogue_unicode",
    )

    # ---------------------------------------------------------------- vendored, bounded not skipped
    # The vendored files are copied verbatim into every fixture above and never appear in a
    # finding, which is the at-baseline half. This is the other half: one em-dash ABOVE the
    # recorded upstream count is ours, and is reported. Without this case the vendored entry
    # would be a blanket exemption that silently stops checking those two files forever.
    vendored_plus = (REPO / "wit/VERSIONING.md").read_text(encoding="utf-8") + (
        "\n\nA local addition " + EM + " beyond the upstream baseline.\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = make_repo(tmp, {})
        (root / "wit/VERSIONING.md").write_text(
            vendored_plus, encoding="utf-8", newline="\n"
        )
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        code, out = run_gate(root, min_docs=1)
        ok = code == FIRE and "VERSIONING.md" in out
        record(
            "11 an em-dash ABOVE the vendored baseline is reported",
            ok,
            f"expected exit {FIRE} naming VERSIONING.md, got {code}: {out.strip()[:300]}",
        )

    # ---------------------------------------------------------------- line endings
    # This project has been bitten by line endings repeatedly, and the two sides disagree here:
    # the developer machine carries core.autocrlf=true while the runner checks out LF. If the
    # exemptions were sensitive to a trailing carriage return, a document exempt on one machine
    # would be reported on the other, which is the worst shape for a gate. Both directions are
    # driven on CRLF bytes so the answer is shown to be the same rather than assumed.
    with tempfile.TemporaryDirectory() as tmp:
        root = make_repo(tmp, {})
        crlf_exempt = (
            "# Title\r\n\r\nProse.\r\n\r\n> quoted " + EM + " reply\r\n"
        ).encode()
        (root / "README.md").write_bytes(crlf_exempt)
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        code_a, out_a = run_gate(root, min_docs=1)

        crlf_fires = ("# Title\r\n\r\nProse " + EM + " planted.\r\n").encode()
        (root / "README.md").write_bytes(crlf_fires)
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        code_b, out_b = run_gate(root, min_docs=1)

        ok = code_a == CLEAN and code_b == FIRE
        record(
            "12 CRLF bytes give the same verdict as LF, both directions",
            ok,
            f"quoted CRLF expected {CLEAN} got {code_a} ({out_a.strip()[:120]}); "
            f"prose CRLF expected {FIRE} got {code_b} ({out_b.strip()[:120]})",
        )

    # ---------------------------------------------------------------- must refuse
    case(
        "13 a fence that never closes is refused, not reported clean",
        {
            "README.md": "# Title\n\n```\nunclosed fence\n\nlater prose "
            + EM
            + " hidden by it\n"
        },
        CANNOT,
        expect_in="UNBALANCED FENCE",
    )

    case(
        "14 a truncated scope is refused by the floor",
        {"README.md": "# Title\n\nOrdinary prose.\n"},
        CANNOT,
        expect_in="FLOOR",
        min_docs=None,  # the shipped default, which is the value CI runs with
    )

    with tempfile.TemporaryDirectory() as tmp:
        root = make_repo(tmp, {"README.md": "# Title\n\nProse.\n"})
        (root / "wit/VERSIONING.md").unlink()
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        code, out = run_gate(root, min_docs=1)
        ok = code == CANNOT and "baseline is dead" in out
        record(
            "15 a vendored path that is no longer tracked is refused",
            ok,
            f"expected exit {CANNOT} and a dead-baseline line, got {code}: {out.strip()[:300]}",
        )

    # ---------------------------------------------------------------- the live tree
    code, out = run_gate(REPO)
    ok = code == CLEAN
    record(
        "16 the real repository is clean under the shipped default floor",
        ok,
        f"expected exit {CLEAN}, got {code}: {out.strip()[:300]}",
    )

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} controls pass")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
