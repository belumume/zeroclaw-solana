#!/usr/bin/env python3
"""Ten checks answering one question: is this cut safe to export, and safe to post?

WHY IT LIVES IN demo/ AND NOT scripts/. It sits with the other demo tooling (take.py,
x402_earnings.py, chain_history.py, verify_qr_scannable.py) because it is part of the same
capture-and-export path. Consequence worth stating rather than discovering:
`scripts/check-all.py` discovers gates from `git ls-files scripts/check-*.py`,
so this gate is NOT in that sweep and has to be run by name. It runs check-all itself as
check 9, so the relationship is one-directional and deliberate.

IT FAILS CLOSED. This is a publish gate: the cost of a false green is a disqualifier or an
operator identifier in a public video, and the cost of a false red is re-running it. So an
unhandled exception exits 2 with its traceback rather than exiting 0 with a shrug. That is
the opposite posture from a productivity guard, and it is chosen for that reason.

A MISSING OPTIONAL INPUT IS "NOT CHECKED", NEVER "PASSED". Tesseract absent, network
absent, the superseded cut already deleted -- each of those makes a check unanswerable, and
an unanswerable check must not read as green. They get their own verdict and their own exit
code, because collapsing "I looked and it was fine" into "I could not look" is how a gate
starts lying.

  0  every check ran and passed          -> safe to export, safe to post
  1  at least one check FAILED           -> do not export
  2  the gate could not run at all       -> fail closed; nothing was verified
  3  nothing failed, something was NOT CHECKED  -> incomplete, not clean

WHAT THIS GATE DELIBERATELY DOES NOT CHECK, said out loud so its silence is not read as
coverage. "No slides" is not mechanically gated: a terminal beat holding output is static
for seconds at a time and any frozen-frame threshold that catches a slide also fails a good
take. "Real voice, not synthetic" is not gated either -- check 4 refuses the one known
synthetic artifact by content hash, which is a fact about that file and not a detector for
the class. Both remain human judgement and are checked by a person before export.

  python demo/pre_export_gate.py <video.mp4>
  python demo/pre_export_gate.py <video.mp4> --fps 2 --no-network
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESSERACT = Path("C:/Program Files/Tesseract-OCR/tesseract.exe")  # installed, off PATH

PASS, FAIL, NOT_CHECKED = "PASS", "FAIL", "n/a "

# The listing, verbatim: "A video, 3 minutes or less". Not 3:00 and change.
MAX_SECONDS = 180.0

# The cut this rebuild replaces shipped at 1280x720 and its full-screen terminal text was
# soft for exactly that reason. take.py already warns on any beat captured below this, so
# the floor is the same number in both places.
MIN_W, MIN_H = 1920, 1080

# Integrated loudness. YouTube normalises toward -14 LUFS, EBU R128 broadcast is -23, and
# this project's own mastering chain lands at -16.1 (demo/voice-post.py, measured). The band
# is wide enough to admit any of those and narrow enough to catch the two failures that
# actually happen: a raw unmastered take (around -25 and quiet) and an over-limited one.
LUFS_MIN, LUFS_MAX = -24.0, -12.0
# True peak. -1 dBTP is the ceiling every lossy-encoding platform asks for; above it,
# transcoding to AAC/Opus introduces intersample clipping the master never had.
TRUE_PEAK_MAX = -1.0
# Below this the track is not audio, whatever the container says it is.
SILENCE_LUFS = -60.0

# The superseded AI-narrated cut. Read as a REFERENCE at runtime rather than pinned as a
# hash, because a pinned hash is a claim with no expiry and this file is meant to outlive
# that artifact. When it is finally deleted the check becomes unanswerable, which is
# NOT_CHECKED and not a pass.
VOID_CUT = REPO / ".demo-assets" / "cut" / "zeroclaw-solana-demo.mp4"

# C2 forbids filming or linking a devnet EXPLORER PAGE. It does NOT forbid devnet, and the
# distinction is load-bearing: the submission's honest claim is mainnet settlement over
# devnet data, so several beats legitimately print the word. Gating on bare "devnet" would
# fail good takes -- the over-broad-matcher trap this repo has hit repeatedly. These are
# third-party explorer surfaces we neither control nor can re-verify from a frame.
EXPLORER_MARKERS = (
    "cluster=devnet",
    "cluster%3ddevnet",
    "explorer.solana.com",
    "solscan.io",
    "solana.fm",
    "solanabeach.io",
)

# Third identifier class, and it is what a THIRD PARTY'S page prints about this machine
# rather than what this machine knows about itself, so these are literals where the account
# name below is not. Same list as take.py's frame gate, kept in step deliberately: a leak
# the take runner catches per-beat must not pass the whole-cut sweep. Word-shaped only; a
# bare "WAT" would fire on WATCH.
TZ_MARKERS = (
    "west africa",
    "africa/lagos",
    "utc+1",
    "utc+01",
    "gmt+1",
    "gmt+01",
    " wat ",
)

# Surfaces that hand a judge a link. Derived from the files rather than listed as URLs,
# because a hand-kept URL list does not grow when a surface gains a link, and the surface
# gaining a link is exactly when a dead one ships.
LINK_SURFACES = (
    "docs/ONE-PAGER.md",  # submission form field 4
    "index.html",  # the landing page, form field 5
    "README.md",  # what a judge reaches from the repo link
    "docs/SUBMISSION-PLAN.md",  # the form-field map itself
)
# Floor, same reasoning as the sibling gates: a broken extraction returns an empty set, the
# loop is skipped, and the result is byte-identical to a clean sweep. Live count is ~12.
MIN_LINKS = 5

# `<` is in the negated class for a measured reason. Without it, `curl https://host/price</code>`
# in index.html yielded `https://host/price</code` -- a malformed URL that 404s, i.e. a dead-link
# FAIL invented by the extractor rather than found in the corpus. Caught by running this over the
# real surfaces before the gate was wired up, which is the only place it could have been caught.
URL_RE = re.compile(r"https://[^\s<>()\"'`\[\]]+")
# Trailing punctuation that belongs to the prose, not the URL.
URL_TRAILING = ".,;:!?*\\"

# Mirrors scripts/verify-proof.py's is_transport_error exactly. A 402 is NOT in either
# bucket: x402.perfpilot.dev/price answers 402 BY DESIGN and the repo advertises that as the
# thing to curl, so treating it as a dead link would red the gate on a correct link.
TRANSPORT_CODES = frozenset({408, 429})
RESOLVES_CODES = frozenset({402})


class CannotRun(Exception):
    """The gate cannot answer anything. Distinct from a check that answered FAIL."""


def run(argv, **kw):
    return subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw
    )


# ---------------------------------------------------------------- extraction


def probe(path: Path) -> dict:
    r = run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration,size",
            "-show_entries",
            "stream=index,codec_type,codec_name,width,height,channels,sample_rate",
            "-of",
            "json",
            str(path),
        ]
    )
    if r.returncode != 0:
        raise CannotRun(f"ffprobe rejected {path.name}: {r.stderr.strip()[:300]}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise CannotRun(f"ffprobe emitted unparseable json: {e}") from e


def atom_order(path: Path) -> list[str]:
    """Top-level MP4 box types in file order, so moov-before-mdat is checkable."""
    out: list[str] = []
    with path.open("rb") as f:
        off = 0
        for _ in range(64):
            f.seek(off)
            hdr = f.read(8)
            if len(hdr) < 8:
                break
            size = int.from_bytes(hdr[:4], "big")
            typ = hdr[4:8].decode("ascii", "replace")
            if size == 1:
                ext = f.read(8)
                if len(ext) < 8:
                    break
                size = int.from_bytes(ext, "big")
            elif size == 0:
                out.append(typ)  # extends to EOF
                break
            if size < 8:
                break
            out.append(typ)
            off += size
    return out


def measure_loudness(path: Path) -> tuple[float | None, float | None]:
    """(integrated LUFS, true peak dBFS). None where ffmpeg did not report it."""
    r = run(
        [
            "ffmpeg",
            "-hide_banner",
            "-nostats",
            "-i",
            str(path),
            "-af",
            "ebur128=peak=true",
            "-f",
            "null",
            "-",
        ]
    )
    body = (r.stderr or "") + (r.stdout or "")
    tail = body[-4000:]  # the Summary block is last; per-frame lines are noise
    lufs = peak = None
    m = re.search(r"Integrated loudness:\s*\n\s*I:\s*(-?[\d.]+|-inf)\s*LUFS", tail)
    if m:
        lufs = float("-inf") if m.group(1) == "-inf" else float(m.group(1))
    m = re.search(r"True peak:\s*\n\s*Peak:\s*(-?[\d.]+|-inf)\s*dBFS", tail)
    if m:
        peak = float("-inf") if m.group(1) == "-inf" else float(m.group(1))
    return lufs, peak


def sample_frames(path: Path, outdir: Path, fps: float, cap: int) -> list[Path]:
    run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(path),
            "-vf",
            f"fps={fps}",
            "-frames:v",
            str(cap),
            str(outdir / "f%05d.png"),
        ]
    )
    return sorted(outdir.glob("f*.png"))


def ocr(png: Path) -> str:
    """Union of both page-segmentation modes.

    take.py records the measurement behind this: psm 11 alone read "RESH" and dropped a
    leading glyph on a frame psm 6 read correctly. A leak sweep wants recall, so both.
    """
    parts = []
    for psm in ("6", "11"):
        r = run([str(TESSERACT), str(png), "stdout", "--psm", psm])
        parts.append(r.stdout or "")
    return "\n".join(parts)


def judge_links() -> list[str]:
    seen: dict[str, None] = {}
    for rel in LINK_SURFACES:
        p = REPO / rel
        if not p.is_file():
            continue
        for m in URL_RE.finditer(p.read_text(encoding="utf-8", errors="replace")):
            seen.setdefault(m.group(0).rstrip(URL_TRAILING), None)
    return sorted(seen)


def fetch_status(url: str) -> tuple[str, str]:
    """('ok'|'claim'|'transport', detail). Logged out: no cookie jar, no credential."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return "ok", f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        if e.code in RESOLVES_CODES:
            return "ok", f"HTTP {e.code} (documented response)"
        if e.code >= 500 or e.code in TRANSPORT_CODES:
            return "transport", f"HTTP {e.code}"
        return "claim", f"HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
        return "transport", f"{type(e).__name__}: {e}"


# ------------------------------------------------------------- pure checks
# Each takes already-extracted facts and returns (verdict, detail). Pure so the suite can
# drive every branch without a fixture per branch, and so the extraction layer above can be
# mutated independently -- a control on the detector alone proves nothing about whether the
# facts ever reached it.


def check_duration(seconds):
    if seconds is None:
        return NOT_CHECKED, "ffprobe reported no duration"
    if seconds >= MAX_SECONDS:
        over = seconds - MAX_SECONDS
        return FAIL, f"{seconds:.3f}s is {over:.3f}s over the {MAX_SECONDS:.0f}s limit"
    return PASS, f"{seconds:.3f}s, {MAX_SECONDS - seconds:.3f}s of headroom"


def check_resolution(w, h):
    if not w or not h:
        return NOT_CHECKED, "no video stream dimensions"
    if w < MIN_W or h < MIN_H:
        return FAIL, f"{w}x{h} is below the {MIN_W}x{MIN_H} floor"
    return PASS, f"{w}x{h}"


def check_container(vcodec, acodec, atoms):
    bad = []
    if vcodec != "h264":
        bad.append(f"video codec {vcodec!r}, expected h264")
    if acodec != "aac":
        bad.append(f"audio codec {acodec!r}, expected aac")
    if "moov" not in atoms:
        bad.append("no moov atom")
    elif "mdat" in atoms and atoms.index("moov") > atoms.index("mdat"):
        bad.append(
            "moov follows mdat: not faststart, so it cannot stream progressively"
        )
    if bad:
        return FAIL, "; ".join(bad)
    return PASS, f"h264+aac, faststart, atoms {'/'.join(atoms[:5])}"


def check_not_void_cut(target_digest, void_digest):
    if void_digest is None:
        return NOT_CHECKED, f"{VOID_CUT.name} is not in the tree to compare against"
    if target_digest == void_digest:
        return FAIL, (
            "byte-identical to the superseded AI-narrated cut, which the human-voice "
            "constraint disqualifies outright"
        )
    return PASS, "not the superseded synthetic-narration cut"


def check_audio_present(acodec, channels, lufs):
    if not acodec:
        return FAIL, "no audio stream at all"
    if lufs is None:
        return NOT_CHECKED, "ffmpeg reported no integrated loudness"
    if lufs == float("-inf") or lufs < SILENCE_LUFS:
        return FAIL, f"integrated loudness {lufs} LUFS: the track is silent"
    return PASS, f"{acodec}, {channels} channel(s), audible"


def check_loudness(lufs, peak):
    if lufs is None:
        return NOT_CHECKED, "ffmpeg reported no integrated loudness"
    bad = []
    if not (LUFS_MIN <= lufs <= LUFS_MAX):
        bad.append(f"integrated {lufs} LUFS outside [{LUFS_MIN}, {LUFS_MAX}]")
    if peak is not None and peak > TRUE_PEAK_MAX:
        bad.append(f"true peak {peak} dBFS above {TRUE_PEAK_MAX} dBTP")
    if bad:
        return FAIL, "; ".join(bad)
    return PASS, f"integrated {lufs} LUFS, true peak {peak} dBFS"


def _spans(stamps):
    """'19.0-27.0s, 102.0-115.0s' -- what an editor needs in order to go fix it.

    A bare count cannot drive a cut. The first version of these two checks put the SCANNED
    count in the failure line ("159 frame(s) carry: ..."), which is one number wearing
    another's meaning: 159 frames were read and 23 carried the leak. Timestamps are both
    honest and actionable, so they replaced it.
    """
    if not stamps:
        return ""
    out, start, prev = [], stamps[0], stamps[0]
    for t in stamps[1:]:
        if t - prev > 2.5:  # a gap wider than a couple of samples starts a new span
            out.append((start, prev))
            start = t
        prev = t
    out.append((start, prev))
    return ", ".join(f"{a:.1f}s" if a == b else f"{a:.1f}-{b:.1f}s" for a, b in out)


def _scan(frames, needles):
    """[(label, [timestamps])] for every needle appearing in any frame."""
    found: dict[str, list[float]] = {}
    for ts, text in frames:
        low = text.lower()
        for label, needle in needles:
            if needle and needle in low:
                found.setdefault(label, []).append(ts)
    return sorted(found.items())


def check_identifiers(frames):
    """Account name and home-directory basename come from the ENVIRONMENT.

    Never written into this file. Writing the name into the file that screens for it would
    publish it in a tracked, public-bound artifact -- the same reasoning take.py records.
    """
    if frames is None:
        return NOT_CHECKED, "tesseract unavailable, so no frame was read"
    home = os.environ.get("USERPROFILE", "")
    needles = [
        ("os account name", os.environ.get("USERNAME", "").lower()),
        ("home-directory basename", Path(home).name.lower() if home else ""),
        ("full home path", home.lower()),
    ] + [(f"timezone marker {m.strip()!r}", m) for m in TZ_MARKERS]
    found = _scan(frames, needles)
    if found:
        detail = "; ".join(f"{label} at {_spans(ts)}" for label, ts in found)
        return FAIL, f"{len(frames)} frame(s) scanned -- {detail}"
    return (
        PASS,
        f"{len(frames)} frame(s), no account name, home path or timezone marker",
    )


def check_explorer(frames):
    """Keys on URL-shaped and domain-shaped markers only.

    HONEST CEILING, and it is measured rather than theoretical. The superseded cut films
    two Solana Explorer transaction pages and this check PASSED on it, because the URL bar
    sat outside the crop so no domain string ever reached a frame. The IDENTIFIER check
    caught them instead, via the explorer's own "West Africa Time" timestamp line. So a
    PASS here means no explorer URL was legible, NOT that no explorer page was filmed.
    Widening this to the explorer's UI chrome ("Transaction", "Timestamp", "Block") was
    considered and rejected: those words are far too common and would red every good take.
    """
    if frames is None:
        return NOT_CHECKED, "tesseract unavailable, so no frame was read"
    found = _scan(frames, [(m, m) for m in EXPLORER_MARKERS])
    if found:
        detail = "; ".join(f"{label} at {_spans(ts)}" for label, ts in found)
        return FAIL, f"{len(frames)} frame(s) scanned -- {detail}"
    return PASS, f"{len(frames)} frame(s), no explorer URL legible"


def check_repo_gates(rc, tail):
    if rc is None:
        return NOT_CHECKED, "scripts/check-all.py was not run"
    if rc != 0:
        return FAIL, f"check-all.py rc={rc}: {tail}"
    return PASS, f"check-all.py rc=0: {tail}"


def check_links(results):
    """results: list of (url, kind, detail)."""
    if not results:
        return NOT_CHECKED, "link checking was skipped"
    dead = [(u, d) for u, k, d in results if k == "claim"]
    unknown = [(u, d) for u, k, d in results if k == "transport"]
    ok = [u for u, k, _ in results if k == "ok"]
    if dead:
        return FAIL, "; ".join(f"{u} -> {d}" for u, d in dead)
    if unknown and not ok:
        return NOT_CHECKED, f"every fetch hit a transport error, e.g. {unknown[0][1]}"
    if unknown:
        return NOT_CHECKED, (
            f"{len(ok)} resolved, {len(unknown)} unreachable for transport reasons "
            f"(e.g. {unknown[0][0]} -> {unknown[0][1]}); re-run before posting"
        )
    return PASS, f"{len(ok)} link(s) resolve logged out"


# ------------------------------------------------------------------- driver


def gate(video: Path, fps: float, frame_cap: int, network: bool, gates: bool) -> list:
    if not video.is_file():
        raise CannotRun(f"no such file: {video}")
    for tool in ("ffprobe", "ffmpeg"):
        if not shutil.which(tool):
            raise CannotRun(
                f"{tool} is not on PATH; nothing about the video is knowable"
            )

    meta = probe(video)
    fmt = meta.get("format", {})
    streams = meta.get("streams", [])
    duration = float(fmt["duration"]) if fmt.get("duration") else None
    vs = next((s for s in streams if s.get("codec_type") == "video"), {})
    aud = next((s for s in streams if s.get("codec_type") == "audio"), {})

    digest = hashlib.sha256(video.read_bytes()).hexdigest()
    void = (
        hashlib.sha256(VOID_CUT.read_bytes()).hexdigest()
        if VOID_CUT.is_file()
        else None
    )
    lufs, peak = measure_loudness(video)

    # [(timestamp_seconds, ocr_text)], so a finding can name WHERE rather than only that
    # something leaked somewhere in three minutes of video.
    frames_text = None
    if TESSERACT.exists():
        with tempfile.TemporaryDirectory(prefix="zcx-gate-") as td:
            pngs = sample_frames(video, Path(td), fps, frame_cap)
            # ffmpeg's fps filter emits frame n at n/fps seconds, 1-indexed on disk.
            frames_text = [((i - 1) / fps, ocr(p)) for i, p in enumerate(pngs, 1)]
        if not frames_text:
            # Extraction produced nothing. That is not a clean sweep, and reporting it as
            # one is the exact false-green this gate's exit codes exist to separate.
            frames_text = None

    rc, tail = None, ""
    if gates:
        # Read the returncode directly. A pipe would report the pager's status and this
        # repo has already taken that exact false green once.
        r = run([sys.executable, str(REPO / "scripts" / "check-all.py")], cwd=str(REPO))
        rc = r.returncode
        lines = [ln for ln in (r.stdout or r.stderr or "").split("\n") if ln.strip()]
        tail = lines[-1][:150] if lines else "(no output)"

    links = []
    if network:
        urls = judge_links()
        if len(urls) < MIN_LINKS:
            raise CannotRun(
                f"link extraction found {len(urls)} url(s) across {len(LINK_SURFACES)} "
                f"surface(s), expected at least {MIN_LINKS}. The walk is broken, so a "
                f"clean link result would mean nothing."
            )
        for u in urls:
            kind, detail = fetch_status(u)
            links.append((u, kind, detail))

    return [
        ("1  duration under 3:00", *check_duration(duration)),
        ("2  resolution", *check_resolution(vs.get("width"), vs.get("height"))),
        (
            "3  container is playable",
            *check_container(
                vs.get("codec_name"), aud.get("codec_name"), atom_order(video)
            ),
        ),
        ("4  not the superseded cut", *check_not_void_cut(digest, void)),
        (
            "5  audio present and audible",
            *check_audio_present(aud.get("codec_name"), aud.get("channels"), lufs),
        ),
        ("6  loudness in range", *check_loudness(lufs, peak)),
        ("7  no identifier in frame", *check_identifiers(frames_text)),
        ("8  no explorer url in frame", *check_explorer(frames_text)),
        ("9  repo gates green", *check_repo_gates(rc, tail)),
        ("10 links resolve logged out", *check_links(links)),
    ]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("video", help="the exported cut")
    ap.add_argument("--fps", type=float, default=1.0, help="frame sample rate for OCR")
    ap.add_argument("--frame-cap", type=int, default=400)
    ap.add_argument("--no-network", action="store_true", help="skip the link check")
    ap.add_argument("--no-gates", action="store_true", help="skip scripts/check-all.py")
    a = ap.parse_args(argv)

    video = Path(a.video).resolve()
    print(f"pre-export gate: {video}")
    print(
        f"sampling {a.fps} fps for OCR (a leak shorter than {1 / a.fps:.2f}s can be missed)\n"
    )

    rows = gate(video, a.fps, a.frame_cap, not a.no_network, not a.no_gates)

    for name, verdict, detail in rows:
        print(f"  {verdict}  {name:<30} {detail}")

    failed = [r for r in rows if r[1] == FAIL]
    unknown = [r for r in rows if r[1] == NOT_CHECKED]

    if failed:
        print(f"\n{len(failed)} check(s) FAILED. This cut does not export.")
        return 1
    if unknown:
        print(
            f"\nNothing failed, but {len(unknown)} check(s) could NOT be run. That is "
            f"incomplete, not clean; a check that did not run has not passed."
        )
        return 3
    print(f"\nall {len(rows)} check(s) pass: safe to export and safe to post")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CannotRun as exc:
        # Fail CLOSED, and say which of the three "not zero" things happened.
        print(f"\nCANNOT RUN  {exc}", file=sys.stderr)
        print("Nothing was verified. Do not read this as a pass.", file=sys.stderr)
        sys.exit(2)
    except Exception:
        # The traceback, never a generic sentence: a fail-closed handler that swallows its
        # cause turns a recurring defect into an undiagnosable one.
        traceback.print_exc()
        print(
            "\nCANNOT RUN  the gate crashed. Failing closed; nothing was verified.",
            file=sys.stderr,
        )
        sys.exit(2)
