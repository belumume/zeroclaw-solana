"""Controls for webshop-pay/build.py --check, in all three directions.

Two directions is the usual bar and it is not enough for this gate. Must-fire alone passes for a
checker that flags every page, which teaches its reader to skip it. Must-not-fire alone is the
state this gate was already in: it ran in ci.yml as the only step in publish-gates with no paired
control, while all six of its siblings there had one. It has been shown to work by hand, once, in
the session that noticed the asymmetry. Nothing repeatable had ever shown it could fail, and a
gate nobody has watched fail is indistinguishable from a gate that cannot.

THIS GATE CANNOT USE THE rc=2 THIRD BUCKET ITS SIBLINGS USE, and inventing one would be worse than
saying so. build.py raises SystemExit with a message for every refusal, so drift, an absent
artifact and an absent source part all exit 1. A bare rc assertion therefore cannot tell a gate
that caught the planted defect from a gate that fell over because the fixture was built wrong.
Every case here asserts an expected MARKER in the output as well as the exit code, which is the
convention scripts/mutation-check-offline-proof.sh already uses for the same reason. The third
direction is still present: cases 8 through 10 are refusals that must name the input the gate
could not read, rather than reporting agreement it never established.

CASE 1 IS THE MONEY SHAPE, and it is the reason this file exists rather than a demonstration that
string comparison works. The deployed page's pinned merchant address is swapped for
9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM, which is not an invented decoy: it is the wallet a
real wrong-recipient payment link pointed at on this project, and it is already carried as
ATTACKER_FROM_REAL_INCIDENT in skills/solana-pay/scripts/test_pay_link.py. Both addresses are 44
characters, so case 1 also pins that the comparison is not the character count the FAIL message
happens to print. If case 1 stops firing, the one control that stops a customer paying a wallet
this shop does not own is no longer being checked by anything.

CASE 2 IS THE HISTORICAL DIRECTION. build.py's own docstring records that index.html accumulated
four fixes while the generator held the version from before them, so the artifact was ahead and
running the generator would have reverted it. Case 1 moves the artifact, case 2 moves the source,
and the gate has to see both because drift has no preferred direction.

scripts/test_check_shadowed_scripts.py deliberately does not cover this file. Its own docstring
says the pay-page incident is "which build.py --check is what catches" and scopes itself to the
second-copy half of the class. That was an accurate division of labour and it left this half with
no controls at all until now.

THE REAL webshop-pay/index.html IS NEVER WRITTEN TO. Every case builds a byte-for-byte fixture in
a temporary directory and plants its defect there. The suite additionally digests every real file
it reads before and after the run and refuses to report a result if any digest moved, which is a
stronger claim than restoring them would be: it shows nothing was written rather than that a write
was undone.

Run: python scripts/test_check_build_py.py
"""

import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PAGE = ROOT / "webshop-pay"
# Overridable so the suite can be pointed at a pre-fix copy of the gate. Driving the must-fire
# cases against an older version is what shows a change did something, rather than that the new
# cases happen to agree with the new code.
GATE = Path(sys.argv[1]) if len(sys.argv) > 1 else PAGE / "build.py"

# The generator resolves every path from its own location, so a faithful fixture is these files
# under one directory and nothing else. Copied as BYTES: a default text write applies the platform
# line ending, which would silently rewrite the artifact the fixture is supposed to reproduce.
PARTS = [
    "index.html",
    "qrcode.js",
    "src/app.js",
    "src/body.html",
    "src/head.html",
    "src/style.css",
    "src/tail.html",
]

MERCHANT = b"C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ"
ATTACKER_FROM_REAL_INCIDENT = b"9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM"

# (printed banner, expected exit code, expected marker in output)
DRIFT = ("FIRE ON DRIFT (rc=1)", 1, "does not match its sources")
AGREE = ("NOT FIRE (rc=0)", 0, "OK index.html matches its sources")
NO_ARTIFACT = ("REFUSE, artifact unreadable (rc=1)", 1, "does not exist")
NO_SOURCE = ("REFUSE, source unreadable (rc=1)", 1, "missing source part")


def swap(rel, find, repl):
    return ("swap", rel, find, repl)


def drop(rel):
    return ("drop", rel, b"", b"")


def endings(rel, style):
    return ("endings", rel, style, b"")


cases = []


def case(name, want, ops):
    cases.append((name, want, ops))


# ---------------------------------------------------------------- must fire (rc=1)
#
# EVERY SWAP IN THIS BUCKET IS THE SAME LENGTH IN AND OUT, and that is deliberate rather than
# incidental. build.py's FAIL message prints the two character counts, which is exactly the shape
# that invites someone to "simplify" the comparison into len(current) != len(html). Against that
# gate a same-length edit is invisible, so an all-same-length bucket is what detects it: pointed at
# a length-comparing copy of build.py, all four of these go red instead of three. The property is
# asserted below rather than left to this comment, because a later case written with a
# different-length edit would quietly give the detection back.
case(
    "THE MONEY SHAPE: the page's pinned merchant address swapped for the real incident wallet",
    DRIFT,
    [swap("index.html", MERCHANT, ATTACKER_FROM_REAL_INCIDENT)],
)

# The other direction, and the historical one. A source part carries a fix the artifact has not
# been rebuilt with, so the deployed page is serving the address nobody corrected.
case(
    "THE DRIFT SHAPE: the merchant address fixed in src/app.js and the page not rebuilt",
    DRIFT,
    [swap("src/app.js", MERCHANT, ATTACKER_FROM_REAL_INCIDENT)],
)

# One character, in a region assembled from style.css rather than app.js. Pins two things at once:
# the comparison is exact rather than approximate, and its scope is the whole assembled page rather
# than the script block, which is the part a narrowing refactor would keep and the rest it would
# drop.
case(
    "a single character altered in the region assembled from style.css",
    DRIFT,
    [swap("index.html", b"min-height:100vh", b"min-height:101vh")],
)

# qrcode.js is the one part read from the generator's own directory instead of src/, so it is the
# branch a refactor that walked src/ would silently stop covering. A vendored dependency dropping
# out of the deployed page unnoticed is how a checkout page stops rendering its QR code.
case(
    "the vendored qrcode.js region altered, the one part whose source path is not src/",
    DRIFT,
    [
        swap(
            "index.html",
            b"QR Code Generator for JavaScript",
            b"QR Code Generator for Javascript",
        )
    ],
)


# ------------------------------------------------------------ must NOT fire (rc=0)

# A gate that flags an untouched page is a gate that gets its step deleted. This also proves the
# fixture reproduces the real layout, without which every case above would pass for the wrong
# reason.
case(
    "an untouched byte-for-byte copy of the deployed page agrees with its sources",
    AGREE,
    [],
)

# build.py compares TEXT rather than bytes on purpose, and its docstring says why: write_text
# applies the platform ending, which is how the deployed file came to be CRLF. This is not a
# hypothetical. The committed blob is LF and .gitattributes sets eol=lf, so a Linux runner checks
# out LF, while core.autocrlf gives a Windows working tree CRLF. A byte comparison would pass in
# ci and fail on every developer machine, which is the direction nobody notices.
case(
    "the page with CRLF endings still agrees, which is the Windows working-tree form",
    AGREE,
    [endings("index.html", "crlf")],
)

# The other half of the same decision, so it is pinned in both directions rather than in whichever
# one this platform happens to produce.
case(
    "the page with LF endings still agrees, which is the committed and ci form",
    AGREE,
    [endings("index.html", "lf")],
)


# ------------------------------- must NOT report agreement when it cannot check (rc=1 + marker)

# A clone that has never run the generator has no page to compare. Reporting that as agreement
# would tell a reader the deployed artifact matches when there is no artifact.
case(
    "DEGRADE: no index.html at all is refused by name, not reported as agreement",
    NO_ARTIFACT,
    [drop("index.html")],
)

# build.py's read() refuses a missing part deliberately, because a silently empty section produces
# a page that still loads and quietly does less than it claims. This is the case that keeps that
# refusal honest.
case(
    "DEGRADE: a missing source part is refused rather than assembled as empty",
    NO_SOURCE,
    [drop("src/app.js")],
)

# The odd-path part again, this time absent. read() special-cases qrcode.js, and a special case is
# where leniency gets added by accident.
case(
    "DEGRADE: the missing part is qrcode.js, the special-cased path",
    NO_SOURCE,
    [drop("qrcode.js")],
)


def apply_ops(root, ops):
    """Plant the fixture's defects, refusing loudly if a plant did nothing.

    A mutation whose anchor no longer matches produces a mutant byte-identical to the original, so
    the case passes while testing nothing. This project has shipped that exact fake control twice.
    For a swap both halves are asserted, that the anchor was found and that the bytes actually
    moved, because an anchor check alone still passes when the replacement equals the anchor.

    Each op carries the strongest assertion that is TRUE for it rather than the same one applied
    everywhere. Bytes-moved is right for a swap and wrong for a line-ending normalization, where a
    file already in the target form is the ordinary state on one of the two platforms this runs on.
    The endings arm asserts the resulting form instead, which is what the case actually needs.
    """
    for kind, rel, a, b in ops:
        target = root / rel
        if kind == "drop":
            if not target.is_file():
                raise RuntimeError(
                    f"PLANT FAILED: {rel} was already absent, nothing was dropped"
                )
            target.unlink()
            continue

        before = target.read_bytes()
        if kind == "swap":
            if a not in before:
                raise RuntimeError(f"PLANT FAILED: anchor not found in {rel}: {a!r}")
            after = before.replace(a, b, 1)
            # A swap that moves nothing means the replacement equals the anchor, so the mutant is
            # the original and the case would pass against unmutated code.
            if after == before:
                raise RuntimeError(
                    f"PLANT FAILED: swap on {rel} changed nothing; the case is fake"
                )
        elif kind == "endings":
            lf = before.replace(b"\r\n", b"\n")
            after = lf if a == "lf" else lf.replace(b"\n", b"\r\n")
            # Deliberately NOT the bytes-moved assertion the swap arm uses, and the reason is worth
            # keeping: a file already in the requested form is the normal state on one platform and
            # rewriting it is genuinely a no-op there. This machine's working tree is CRLF under
            # core.autocrlf while a Linux runner checks out LF, so a bytes-moved rule would make
            # whichever case matches the local form fail, on every platform, forever. It fired here
            # on the first run. The assertion that carries the case is the POST-CONDITION: the
            # fixture is in the form the case names, however it got there.
            if a == "lf" and b"\r\n" in after:
                raise RuntimeError(
                    f"PLANT FAILED: {rel} still holds CRLF after normalizing to LF"
                )
            if a == "crlf" and (
                b"\r\n" not in after or b"\n" in after.replace(b"\r\n", b"")
            ):
                raise RuntimeError(
                    f"PLANT FAILED: {rel} is not uniformly CRLF after expanding"
                )
        else:
            raise RuntimeError(f"PLANT FAILED: unknown op {kind!r}")

        target.write_bytes(after)


def same_length_violations():
    """Every must-fire swap has to be length-preserving, or the bucket stops detecting a gate that
    compares character counts. Checked rather than trusted to a comment, because the weakening is
    invisible: a different-length case still goes red against the real gate and still reads as a
    perfectly good case, and only the length-comparing mutant can tell the difference."""
    bad = []
    for name, (banner, _rc, _marker), ops in cases:
        if banner != DRIFT[0]:
            continue
        for kind, rel, a, b in ops:
            if kind == "swap" and len(a) != len(b):
                bad.append(f"{name}: {rel} swap is {len(a)} -> {len(b)} characters")
    return bad


def run_case(ops):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "src").mkdir(parents=True, exist_ok=True)
        (root / "build.py").write_bytes(GATE.read_bytes())
        for rel in PARTS:
            shutil.copyfile(PAGE / rel, root / rel)

        apply_ops(root, ops)

        out = subprocess.run(
            [sys.executable, str(root / "build.py"), "--check"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return out.returncode, (out.stdout or "") + (out.stderr or "")


def digests():
    """Digest every real file this suite reads, so an accidental write cannot go unreported."""
    d = {}
    for rel in ["build.py", *PARTS]:
        p = PAGE / rel
        d[rel] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "ABSENT"
    return d


def main():
    if not GATE.exists():
        print(f"gate not found at {GATE}")
        return 2
    bad = same_length_violations()
    if bad:
        print(
            "a must-fire swap is not length-preserving, so this bucket no longer detects a"
        )
        print("gate that compares character counts:")
        for b in bad:
            print(f"  {b}")
        return 2
    missing = [rel for rel in PARTS if not (PAGE / rel).is_file()]
    if missing:
        print(
            f"cannot build a faithful fixture, these are absent: {', '.join(missing)}"
        )
        return 2

    before = digests()

    npass = nfail = 0
    last_banner = None
    for name, (banner, want_rc, want_marker), ops in cases:
        if banner != last_banner:
            print(f"\nMUST {banner}:")
            last_banner = banner
        try:
            rc, output = run_case(ops)
        except RuntimeError as e:
            print(f"  FAIL {name}\n       {e}")
            nfail += 1
            continue
        if rc == want_rc and want_marker in output:
            print(f"  ok   {name} (rc={rc})")
            npass += 1
        elif rc == want_rc:
            print(f"  FAIL {name} (rc={rc} as wanted, but not by the expected control)")
            print(f"       wanted marker: {want_marker}")
            print("       " + output.strip().replace("\n", "\n       "))
            nfail += 1
        else:
            print(f"  FAIL {name} (rc={rc} want={want_rc})")
            print("       " + output.strip().replace("\n", "\n       "))
            nfail += 1

    after = digests()
    moved = [rel for rel in before if before[rel] != after[rel]]
    print(f"\nreal webshop-pay/index.html sha256 {after['index.html']}")
    if moved:
        print(
            f"REAL TREE WRITTEN TO: {', '.join(moved)}; no result below is trustworthy"
        )
        return 2
    print(
        "real tree untouched: all 8 source and artifact digests unchanged across the run"
    )

    print(f"\n{npass} passed, {nfail} failed")
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
