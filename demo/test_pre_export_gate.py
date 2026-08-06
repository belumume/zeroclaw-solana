#!/usr/bin/env python3
"""Controls for demo/pre_export_gate.py -- proves every check can FAIL, not only pass.

A publish gate that has only ever been seen green has not been shown to work, and this one
guards the two things that cannot be undone after posting: a disqualifier and an operator
identifier in a public video. So each of the ten checks is driven in BOTH directions.

THREE LAYERS, because a control on one proves nothing about the others.

  1. PURE CHECKS. Every check is a function over already-extracted facts, so each branch
     (pass / fail / not-checked) is driven directly. Several carry an OVER-CORRECTION
     control: a bare "devnet" and the word "WATCH" must NOT fire, or the narrowing that
     stopped a false positive would have silently disabled the detector.

  2. REAL FIXTURES. Layer 1 can be entirely green while the extraction layer never delivers
     a fact to it. So ffmpeg builds actual mp4s -- 1080p, 720p, moov-at-the-end, silent,
     audio-less -- and the extractors are required to read the right values off real files.

  3. MUTATION CONTROLS. Two detectors are disabled in memory and the matching case is
     REQUIRED to flip green. Each asserts its target string is present in the source first,
     so a control that has gone stale fails loudly instead of certifying an unmodified
     detector.

Case E1 is the incident shape: the superseded 720p cut, which must be refused.

  python demo/test_pre_export_gate.py
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pre_export_gate as g

CHECKS = 0
FAILS = 0
SKIPPED = 0

PASS, FAIL, NC = g.PASS, g.FAIL, g.NOT_CHECKED


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS, FAILS
    CHECKS += 1
    if cond:
        print(f"  ok   {name}")
    else:
        FAILS += 1
        print(f"  FAIL {name}  {detail}")


def fr(*texts):
    """Frame list in the shape the checks now take: [(timestamp_seconds, ocr_text)].

    One frame per argument at one-second spacing, so a case can place a leak at a known
    time and assert the reported span.
    """
    return [(float(i), t) for i, t in enumerate(texts)]


def verdict(result):
    return result[0]


# ============================================================ 1. PURE CHECKS

print("pre-export gate controls\n\nlayer 1: pure checks, both directions")

# --- 1 duration -------------------------------------------------------------
check("1 duration 179.9s passes", verdict(g.check_duration(179.9)) == PASS)
check("1 duration exactly 180.0s FAILS", verdict(g.check_duration(180.0)) == FAIL)
check("1 duration 200s FAILS", verdict(g.check_duration(200.0)) == FAIL)
check("1 duration names the overage", "20.000s over" in g.check_duration(200.0)[1])
check("1 duration None is NOT CHECKED", verdict(g.check_duration(None)) == NC)

# --- 2 resolution -----------------------------------------------------------
check("2 1920x1080 passes", verdict(g.check_resolution(1920, 1080)) == PASS)
check("2 3840x2160 passes", verdict(g.check_resolution(3840, 2160)) == PASS)
check("2 1280x720 FAILS (the old cut)", verdict(g.check_resolution(1280, 720)) == FAIL)
# One pixel short on the minor axis. A >= written as > would pass this.
check("2 1920x1079 FAILS", verdict(g.check_resolution(1920, 1079)) == FAIL)
check(
    "2 missing dimensions is NOT CHECKED", verdict(g.check_resolution(None, None)) == NC
)

# --- 3 container ------------------------------------------------------------
FAST = ["ftyp", "moov", "free", "mdat"]
SLOW = ["ftyp", "mdat", "moov"]
check(
    "3 h264+aac+faststart passes",
    verdict(g.check_container("h264", "aac", FAST)) == PASS,
)
check(
    "3 moov after mdat FAILS", verdict(g.check_container("h264", "aac", SLOW)) == FAIL
)
check(
    "3 non-faststart says why",
    "cannot stream progressively" in g.check_container("h264", "aac", SLOW)[1],
)
check("3 vp9 FAILS", verdict(g.check_container("vp9", "aac", FAST)) == FAIL)
check("3 no audio codec FAILS", verdict(g.check_container("h264", None, FAST)) == FAIL)
check(
    "3 no moov atom FAILS",
    verdict(g.check_container("h264", "aac", ["ftyp", "mdat"])) == FAIL,
)

# --- 4 not the superseded cut ----------------------------------------------
check(
    "4 a different digest passes", verdict(g.check_not_void_cut("aaa", "bbb")) == PASS
)
check(
    "4 an identical digest FAILS", verdict(g.check_not_void_cut("aaa", "aaa")) == FAIL
)
check(
    "4 identical names the constraint",
    "human-voice" in g.check_not_void_cut("aaa", "aaa")[1],
)
# The superseded cut is scheduled for deletion. Absent reference must NOT read as a pass.
check(
    "4 absent reference is NOT CHECKED",
    verdict(g.check_not_void_cut("aaa", None)) == NC,
)

# --- 5 audio present and audible -------------------------------------------
check(
    "5 aac at -16 LUFS passes", verdict(g.check_audio_present("aac", 2, -16.0)) == PASS
)
check(
    "5 no audio stream FAILS", verdict(g.check_audio_present(None, None, -16.0)) == FAIL
)
check(
    "5 -inf LUFS FAILS", verdict(g.check_audio_present("aac", 1, float("-inf"))) == FAIL
)
# ffmpeg reports digital silence as -70.0 rather than -inf. Measured, not assumed: an
# anullsrc track through ebur128 returns exactly -70.0, so a check keyed only on -inf
# would call a silent track audible.
check(
    "5 -70.0 LUFS (measured silence) FAILS",
    verdict(g.check_audio_present("aac", 1, -70.0)) == FAIL,
)
check(
    "5 -59 LUFS still passes (just above the floor)",
    verdict(g.check_audio_present("aac", 1, -59.0)) == PASS,
)
check(
    "5 no loudness reading is NOT CHECKED",
    verdict(g.check_audio_present("aac", 1, None)) == NC,
)

# --- 6 loudness -------------------------------------------------------------
check(
    "6 -16.0 LUFS / -11.4 dBFS passes", verdict(g.check_loudness(-16.0, -11.4)) == PASS
)
check("6 -23 LUFS (EBU R128) passes", verdict(g.check_loudness(-23.0, -3.0)) == PASS)
check("6 -14 LUFS (YouTube) passes", verdict(g.check_loudness(-14.0, -2.0)) == PASS)
check(
    "6 -25.8 LUFS (an unmastered take) FAILS",
    verdict(g.check_loudness(-25.8, -8.2)) == FAIL,
)
check("6 -5 LUFS (over-limited) FAILS", verdict(g.check_loudness(-5.0, -2.0)) == FAIL)
check("6 true peak -0.5 dBFS FAILS", verdict(g.check_loudness(-16.0, -0.5)) == FAIL)
check("6 true peak names the ceiling", "dBTP" in g.check_loudness(-16.0, -0.5)[1])
check("6 no reading is NOT CHECKED", verdict(g.check_loudness(None, None)) == NC)

# --- 7 identifiers ----------------------------------------------------------
# Derived from the environment at runtime and never written into either file. Hardcoding
# the name into the screen that looks for it would publish it in a tracked, public repo.
USER = os.environ.get("USERNAME", "")
HOME = os.environ.get("USERPROFILE", "")
BASE = Path(HOME).name if HOME else ""

check(
    "7 clean frame text passes",
    verdict(g.check_identifiers(fr("zeroclaw> FRESH seq=812"))) == PASS,
)
check(
    "7 tesseract unavailable is NOT CHECKED",
    verdict(g.check_identifiers(None)) == NC,
)

if USER:
    check(
        "7 the os account name FAILS",
        verdict(g.check_identifiers(fr(f"C:\\path\\{USER}\\DEV out"))) == FAIL,
    )
else:
    SKIPPED += 1
    print("  SKIP 7 os account name: no USERNAME in this environment")

if BASE:
    check(
        "7 the home-directory basename FAILS",
        verdict(g.check_identifiers(fr(f"prompt {BASE} something"))) == FAIL,
    )
    # The audit that found the pushed leak first searched the account name, got a false
    # clean, and only a positive control exposed that the account name and the home
    # basename are two DIFFERENT strings on this box. Both are checked for that reason.
    check(
        "7 basename and account name are checked separately",
        "home-directory basename" in g.check_identifiers(fr(f"x {BASE} y"))[1],
    )
else:
    SKIPPED += 2
    print("  SKIP 7 home basename: no USERPROFILE in this environment")

# A finding must say WHERE, or it cannot drive a cut. Two clean frames, then a leak, then
# clean again: the span must name 2.0s and must NOT name the clean frames.
_located = g.check_identifiers(
    fr("clean", "clean", "Aug 6, 2026 at 09:52 West Africa Time", "clean")
)
check("7 a finding reports the timestamp", "2.0s" in _located[1], str(_located))
check(
    "7 a finding counts frames scanned, not frames hit",
    "4 frame(s) scanned" in _located[1],
    str(_located),
)
# Two separate runs must read as two spans rather than one long one. This is the shape the
# superseded cut actually has: two explorer pages, ~19-27s and ~102-115s.
_two = g.check_identifiers(
    fr(*(["West Africa Time"] * 3 + ["clean"] * 6 + ["West Africa Time"] * 2))
)
check(
    "7 two separate leaks read as two spans",
    "0.0-2.0s, 9.0-10.0s" in _two[1],
    str(_two),
)

check(
    "7 a timezone marker FAILS",
    verdict(g.check_identifiers(fr("Aug 6, 2026 at 09:52 West Africa Time"))) == FAIL,
)
# OVER-CORRECTION CONTROLS. The marker is " wat " with spaces precisely so these pass; a
# bare "wat" would fire on both and the gate would red every take carrying ordinary words.
check(
    "7 OVER-CORRECTION: 'WATCH' does not fire",
    verdict(g.check_identifiers(fr("payment WATCH armed"))) == PASS,
)
check(
    "7 OVER-CORRECTION: 'WATCHER' does not fire",
    verdict(g.check_identifiers(fr("the WATCHER loop"))) == PASS,
)

# --- 8 devnet explorer ------------------------------------------------------
check(
    "8 clean frame text passes",
    verdict(g.check_explorer(fr("settled 1.000000 USDC"))) == PASS,
)
check(
    "8 cluster=devnet FAILS",
    verdict(g.check_explorer(fr("...?cluster=devnet"))) == FAIL,
)
check(
    "8 explorer.solana.com FAILS",
    verdict(g.check_explorer(fr("explorer.solana.com/tx/3TL"))) == FAIL,
)
check("8 solscan.io FAILS", verdict(g.check_explorer(fr("solscan.io/tx/abc"))) == FAIL)
check("8 tesseract unavailable is NOT CHECKED", verdict(g.check_explorer(None)) == NC)
# OVER-CORRECTION CONTROLS, and these are the reason the check is scoped to explorer PAGES
# rather than to the word. The submission's honest claim is mainnet settlement over devnet
# data, so several beats legitimately print "devnet". A bare-word gate fails good takes.
check(
    "8 OVER-CORRECTION: '25 devnet USDC' passes",
    verdict(g.check_explorer(fr("Mesa 4 - 25 devnet USDC"))) == PASS,
)
check(
    "8 OVER-CORRECTION: an rpc host passes",
    verdict(g.check_explorer(fr("RPC https://api.devnet.solana.com"))) == PASS,
)
check(
    "8 OVER-CORRECTION: a CAIP-2 network id passes",
    verdict(g.check_explorer(fr("network solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1")))
    == PASS,
)

# --- 9 repo gates -----------------------------------------------------------
check("9 rc=0 passes", verdict(g.check_repo_gates(0, "all 10 gate(s) pass")) == PASS)
check("9 rc=1 FAILS", verdict(g.check_repo_gates(1, "1 gate(s) FAILED")) == FAIL)
check("9 rc=2 FAILS", verdict(g.check_repo_gates(2, "discovery broken")) == FAIL)
check("9 not run is NOT CHECKED", verdict(g.check_repo_gates(None, "")) == NC)

# --- 10 links ---------------------------------------------------------------
OK3 = [
    ("https://a", "ok", "HTTP 200"),
    ("https://b", "ok", "HTTP 200"),
    ("https://c", "ok", "HTTP 402"),
]
check("10 all resolving passes", verdict(g.check_links(OK3)) == PASS)
check(
    "10 one dead link FAILS",
    verdict(g.check_links(OK3 + [("https://d", "claim", "HTTP 404")])) == FAIL,
)
check(
    "10 the dead link is named",
    "https://d" in g.check_links(OK3 + [("https://d", "claim", "HTTP 404")])[1],
)
check("10 empty result is NOT CHECKED", verdict(g.check_links([])) == NC)
check(
    "10 all-transport is NOT CHECKED, never a pass",
    verdict(g.check_links([("https://a", "transport", "HTTP 429")])) == NC,
)
check(
    "10 a partial transport failure is NOT CHECKED, never a pass",
    verdict(g.check_links(OK3 + [("https://d", "transport", "HTTP 503")])) == NC,
)

# --- fetch_status classification, driven without network --------------------
# The 402 boundary is the one that matters: x402.perfpilot.dev/price answers 402 BY DESIGN
# and the repo tells a judge to curl it, so classifying 402 as dead would red the gate on a
# correct link. Verified live at 2026-08-06: /price -> 402, /health -> 200.
_orig_urlopen = g.urllib.request.urlopen


def _raise(code):
    def _f(_req, timeout=None):
        raise urllib.error.HTTPError("https://x", code, "sim", {}, None)

    return _f


for code, want in (
    (402, "ok"),
    (404, "claim"),
    (403, "claim"),
    (410, "claim"),
    (429, "transport"),
    (408, "transport"),
    (500, "transport"),
    (503, "transport"),
):
    g.urllib.request.urlopen = _raise(code)
    got = g.fetch_status("https://x")[0]
    check(f"10 HTTP {code} classifies as {want}", got == want, f"got {got}")


def _raise_url(_req, timeout=None):
    raise urllib.error.URLError("dns")


g.urllib.request.urlopen = _raise_url
check(
    "10 URLError classifies as transport", g.fetch_status("https://x")[0] == "transport"
)
g.urllib.request.urlopen = _orig_urlopen

# --- URL extraction ---------------------------------------------------------
# THE MEASURED DEFECT, pinned. Before `<` was excluded from the character class, an
# index.html line `curl https://host/price</code>` yielded `https://host/price</code`,
# a malformed URL that 404s -- a dead-link FAIL manufactured by the extractor. Found by
# running the extractor over the real surfaces before wiring the gate up.
_html = "<pre><code>curl -i https://x402.perfpilot.dev/price</code></pre>"
_hits = [m.group(0) for m in g.URL_RE.finditer(_html)]
check(
    "URL extraction strips a closing html tag",
    _hits == ["https://x402.perfpilot.dev/price"],
    str(_hits),
)
_md = (
    "see [the one-pager](https://github.com/o/r/blob/main/docs/ONE-PAGER.md) and stop."
)
check(
    "URL extraction strips markdown parens and a trailing period",
    [m.group(0).rstrip(g.URL_TRAILING) for m in g.URL_RE.finditer(_md)]
    == ["https://github.com/o/r/blob/main/docs/ONE-PAGER.md"],
)
_live = g.judge_links()
check(
    f"URL extraction clears the floor on the real tree ({len(_live)} urls)",
    len(_live) >= g.MIN_LINKS,
)
check(
    "URL extraction yields no malformed url",
    not any("<" in u or ">" in u for u in _live),
    str(_live),
)


# ========================================================= 2. REAL FIXTURES

print("\nlayer 2: real fixtures, so the extraction path is exercised")


def build(td: Path):
    """Real mp4s. Layer 1 can be green while no fact ever reaches it."""
    made = {}
    common = [
        "-c:v",
        "libx264",
        "-preset",
        "ultrafast",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
    ]
    sine = "sine=frequency=440:sample_rate=48000"
    # good: 1080p, faststart, audio normalised to -16 LUFS / -2 dBTP (measured: I -16.0,
    # true peak -11.4). A raw full-scale sine cannot satisfy both the loudness band and the
    # peak ceiling, because a sine's crest factor is ~3 dB against speech's 12-18.
    made["good"] = td / "good.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=1920x1080:rate=10",
            "-f",
            "lavfi",
            "-i",
            sine,
            "-t",
            "2",
            "-af",
            "loudnorm=I=-16:TP=-2:LRA=7",
            *common,
            "-movflags",
            "+faststart",
            str(made["good"]),
        ],
        capture_output=True,
    )
    made["small"] = td / "small.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=1280x720:rate=10",
            "-f",
            "lavfi",
            "-i",
            sine,
            "-t",
            "2",
            "-af",
            "loudnorm=I=-16:TP=-2:LRA=7",
            *common,
            "-movflags",
            "+faststart",
            str(made["small"]),
        ],
        capture_output=True,
    )
    # No +faststart: the mp4 muxer writes moov at the END by default, which is the defect.
    made["slow"] = td / "slow.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=1920x1080:rate=10",
            "-f",
            "lavfi",
            "-i",
            sine,
            "-t",
            "2",
            "-af",
            "loudnorm=I=-16:TP=-2:LRA=7",
            *common,
            str(made["slow"]),
        ],
        capture_output=True,
    )
    made["silent"] = td / "silent.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=1920x1080:rate=10",
            "-f",
            "lavfi",
            "-i",
            "anullsrc=r=48000:cl=stereo",
            "-t",
            "2",
            *common,
            "-movflags",
            "+faststart",
            str(made["silent"]),
        ],
        capture_output=True,
    )
    made["noaudio"] = td / "noaudio.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=1920x1080:rate=10",
            "-t",
            "2",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            str(made["noaudio"]),
        ],
        capture_output=True,
    )
    return made


def facts(path: Path):
    meta = g.probe(path)
    fmt, streams = meta.get("format", {}), meta.get("streams", [])
    vs = next((s for s in streams if s.get("codec_type") == "video"), {})
    aud = next((s for s in streams if s.get("codec_type") == "audio"), {})
    lufs, peak = g.measure_loudness(path)
    return {
        "duration": float(fmt["duration"]) if fmt.get("duration") else None,
        "w": vs.get("width"),
        "h": vs.get("height"),
        "v": vs.get("codec_name"),
        "a": aud.get("codec_name"),
        "ch": aud.get("channels"),
        "atoms": g.atom_order(path),
        "lufs": lufs,
        "peak": peak,
    }


with tempfile.TemporaryDirectory(prefix="zcx-gate-test-") as _td:
    F = build(Path(_td))
    missing = [k for k, v in F.items() if not v.is_file() or v.stat().st_size == 0]
    if missing:
        check("fixtures build", False, f"ffmpeg produced nothing for {missing}")
    else:
        good = facts(F["good"])
        check(
            "F good: ffprobe reads 1920x1080",
            (good["w"], good["h"]) == (1920, 1080),
            str(good),
        )
        check(
            "F good: resolution check passes on it",
            verdict(g.check_resolution(good["w"], good["h"])) == PASS,
        )
        check(
            "F good: duration read as ~2s",
            1.5 < (good["duration"] or 0) < 3.0,
            str(good["duration"]),
        )
        check(
            "F good: duration check passes",
            verdict(g.check_duration(good["duration"])) == PASS,
        )
        check(
            "F good: atoms report faststart",
            good["atoms"].index("moov") < good["atoms"].index("mdat"),
            str(good["atoms"]),
        )
        check(
            "F good: container check passes",
            verdict(g.check_container(good["v"], good["a"], good["atoms"])) == PASS,
        )
        check(
            "F good: ebur128 lands in band",
            -24.0 <= (good["lufs"] or -99) <= -12.0,
            str(good["lufs"]),
        )
        check(
            "F good: loudness check passes",
            verdict(g.check_loudness(good["lufs"], good["peak"])) == PASS,
        )
        check(
            "F good: audio-present check passes",
            verdict(g.check_audio_present(good["a"], good["ch"], good["lufs"])) == PASS,
        )

        small = facts(F["small"])
        check(
            "F small: ffprobe reads 1280x720",
            (small["w"], small["h"]) == (1280, 720),
            str(small),
        )
        check(
            "F small: resolution check FAILS on it",
            verdict(g.check_resolution(small["w"], small["h"])) == FAIL,
        )

        slow = facts(F["slow"])
        check(
            "F slow: atoms really report moov AFTER mdat",
            slow["atoms"].index("moov") > slow["atoms"].index("mdat"),
            str(slow["atoms"]),
        )
        check(
            "F slow: container check FAILS on it",
            verdict(g.check_container(slow["v"], slow["a"], slow["atoms"])) == FAIL,
        )

        silent = facts(F["silent"])
        check(
            "F silent: ebur128 reads silence",
            (silent["lufs"] or 0) <= g.SILENCE_LUFS,
            str(silent["lufs"]),
        )
        check(
            "F silent: audio-present check FAILS on it",
            verdict(g.check_audio_present(silent["a"], silent["ch"], silent["lufs"]))
            == FAIL,
        )

        noaudio = facts(F["noaudio"])
        check(
            "F noaudio: ffprobe reports no audio codec",
            noaudio["a"] is None,
            str(noaudio),
        )
        check(
            "F noaudio: audio-present check FAILS on it",
            verdict(g.check_audio_present(noaudio["a"], noaudio["ch"], noaudio["lufs"]))
            == FAIL,
        )

        # END TO END on a real file: main() must return 1 and print the failing check.
        _argv = [str(F["small"]), "--no-network", "--no-gates", "--fps", "1"]
        _o, _e = io.StringIO(), io.StringIO()
        with redirect_stdout(_o), redirect_stderr(_e):
            _rc = g.main(_argv)
        _body = _o.getvalue()
        check("F e2e: a 720p file exits 1", _rc == 1, f"rc={_rc}")
        check(
            "F e2e: the resolution row reads FAIL",
            f"{FAIL}  2  resolution" in _body,
            _body,
        )
        check(
            "F e2e: the summary says it does not export",
            "does not export" in _body,
            _body,
        )

        # THE OTHER DIRECTION, in two parts, because the first draft of this case asserted
        # rc==0 while passing --no-network --no-gates and the suite went red. The gate was
        # right and the case was wrong: two checks genuinely could not run, so 3 is the
        # correct answer and 0 would have been the gate lying. Kept split, because the two
        # halves prove different things.
        #
        # E2a: a clean file with two checks switched OFF must reach 3, never 0.
        _o2 = io.StringIO()
        with redirect_stdout(_o2), redirect_stderr(io.StringIO()):
            _rc2 = g.main([str(F["good"]), "--no-network", "--no-gates", "--fps", "1"])
        _body2 = _o2.getvalue()
        _expect_off = 2 if g.TESSERACT.exists() else 4  # OCR off adds two more
        check("F e2e: a good fixture never FAILS", _rc2 != 1, f"rc={_rc2}\n{_body2}")
        check(
            "F e2e: switched-off checks yield 3, not 0",
            _rc2 == 3,
            f"rc={_rc2}\n{_body2}",
        )
        check(
            f"F e2e: exactly {_expect_off} row(s) read NOT CHECKED",
            _body2.count(f"  {NC}  ") == _expect_off,
            _body2,
        )
        check(
            "F e2e: the summary refuses to call it clean",
            "could NOT be run" in _body2 and "incomplete, not clean" in _body2,
            _body2,
        )
        if g.TESSERACT.exists():
            check(
                "F e2e: the OCR rows really ran",
                f"{PASS}  7  no identifier" in _body2,
                _body2,
            )

        # E2b: and rc 0 MUST be reachable, or the gate can never say "safe to export" and
        # every green above would be describing a verdict nothing can obtain. The two slow
        # checks are stubbed rather than skipped, so main()'s success branch is the thing
        # under test here -- their own logic is covered by cases 9 and 10 above.
        _real_gates, _real_fetch = g.check_repo_gates, g.fetch_status
        g.check_repo_gates = lambda rc, tail: (PASS, "stubbed for the rc-0 path")
        g.fetch_status = lambda url: ("ok", "HTTP 200 (stubbed)")
        try:
            _o4 = io.StringIO()
            with redirect_stdout(_o4), redirect_stderr(io.StringIO()):
                _rc4 = g.main([str(F["good"]), "--fps", "1"])
            _body4 = _o4.getvalue()
        finally:
            g.check_repo_gates, g.fetch_status = _real_gates, _real_fetch
        check(
            "F e2e: rc 0 is reachable on a clean cut", _rc4 == 0, f"rc={_rc4}\n{_body4}"
        )
        check(
            "F e2e: all ten rows PASS on the clean path",
            _body4.count(f"  {PASS}  ") == 10,
            _body4,
        )
        check(
            "F e2e: and it says so",
            "safe to export and safe to post" in _body4,
            _body4,
        )


# ==================================================== 3. MUTATION CONTROLS

print("\nlayer 3: mutation controls, so the greens above are not vacuous")

_src = Path(g.__file__).read_text(encoding="utf-8")


def mutate(target: str, replacement: str):
    assert target in _src, (
        f"mutation target {target!r} is not in the source -- control is stale"
    )
    ns: dict = {"__name__": "mutated_gate", "__file__": g.__file__}
    exec(compile(_src.replace(target, replacement, 1), g.__file__, "exec"), ns)
    return ns


# M1 -- disable the resolution comparison; the 720p case MUST stop failing.
_m1 = mutate("if w < MIN_W or h < MIN_H:", "if False:")
check(
    "M1 mutant does NOT catch 720p",
    verdict(_m1["check_resolution"](1280, 720)) == PASS,
    "detector was not load-bearing",
)
check(
    "M1 real detector still catches 720p",
    verdict(g.check_resolution(1280, 720)) == FAIL,
)

# M2 -- disable the identifier lookup; the leak case MUST stop failing. Keyed on the
# env-read rather than on a name, for the same reason the check itself is.
# RE-KEYED 2026-08-06 after check_identifiers was refactored to report timestamps. The old
# target string vanished with the refactor and this assertion FIRED, which is the control
# doing its job: without it, M2 would have silently exec'd an unmodified detector and the
# green below would have meant nothing.
_m2 = mutate(
    '("os account name", os.environ.get("USERNAME", "").lower()),',
    '("os account name", ""),',
)
if USER:
    _leak = f"C:\\path\\{USER}\\DEV out"
    check(
        "M2 mutant does NOT catch the account name",
        verdict(_m2["check_identifiers"](fr(_leak))) == PASS,
        "detector was not load-bearing",
    )
    check(
        "M2 real detector still catches it",
        verdict(g.check_identifiers(fr(_leak))) == FAIL,
    )
else:
    SKIPPED += 2
    print("  SKIP M2: no USERNAME in this environment")

# M3 -- disable the explorer scan; cluster=devnet MUST stop failing.
# Re-keyed by the same refactor, and it fired for the same reason. Two stale controls
# caught in one run is the strongest evidence available that the assert-before-mutating
# step is worth its line: both would otherwise have gone green against real detectors.
_m3 = mutate(
    "found = _scan(frames, [(m, m) for m in EXPLORER_MARKERS])",
    "found = []",
)
check(
    "M3 mutant does NOT catch cluster=devnet",
    verdict(_m3["check_explorer"](fr("?cluster=devnet"))) == PASS,
    "detector was not load-bearing",
)
check(
    "M3 real detector still catches it",
    verdict(g.check_explorer(fr("?cluster=devnet"))) == FAIL,
)


# ==================================== 4. THE INCIDENT SHAPE, pinned as E1

print("\nlayer 4: the incident shape")

if g.VOID_CUT.is_file():
    _o3 = io.StringIO()
    with redirect_stdout(_o3), redirect_stderr(io.StringIO()):
        # 0.05 fps keeps this to ~8 frames. The claim here is that the extraction path runs
        # on a real 159s file, NOT that 8 frames are leak coverage.
        _rc3 = g.main([str(g.VOID_CUT), "--no-network", "--no-gates", "--fps", "0.05"])
    _b3 = _o3.getvalue()
    check("E1 the superseded cut is REFUSED", _rc3 == 1, f"rc={_rc3}\n{_b3}")
    # MEASURED 2026-08-06 at fps=1: 159 frames scanned, and a Solana Explorer lower third
    # reading "Timestamp ... West Africa Time" in THREE spans -- 18.0-26.0s, 51.0-55.0s and
    # 101.0-114.0s. Three separate explorer pages, in the cut currently live on Pages.
    #
    # The count was wrong once and the correction is the useful half. A hand sweep using
    # `--psm 6` alone found only the first and third spans; the middle one at 51-55s is
    # legible to psm 11 and invisible to psm 6, confirmed by reading those five frames both
    # ways. So the psm union in ocr() is not symmetry, it is recall, and the manual
    # instrument was the weaker one. take.py records the same lesson pointing the other way
    # (psm 11 dropping a leading glyph psm 6 read fine), which is why both run.
    # This is a real leak in the video currently live on GitHub Pages, and check 7 is what
    # found it. At 0.05 fps this case samples only ~8 frames and may miss it, so the
    # assertion is deliberately conditional: it pins the finding when the sample lands on
    # it and never manufactures a red when it does not.
    if "timezone marker" in _b3:
        check(
            "E1 the timezone leak is reported with a span",
            "s" in _b3.split("timezone marker")[1][:80],
        )
    check(
        "E1 check 8 does NOT catch those explorer pages (the measured blind spot)",
        f"{PASS}  8 " in _b3,
        "if this flipped to FAIL the ceiling documented in check_explorer has changed",
    )
    check("E1 refused on resolution", f"{FAIL}  2  resolution" in _b3, _b3)
    check(
        "E1 refused as the superseded cut", f"{FAIL}  4  not the superseded" in _b3, _b3
    )
    check(
        "E1 its duration is inside the limit, so that row passes",
        f"{PASS}  1  duration" in _b3,
        _b3,
    )
else:
    SKIPPED += 4
    print(
        f"  SKIP E1: {g.VOID_CUT.name} is no longer in the tree (its planned end state)."
    )
    print("       Re-pin this case against the shipped cut when one exists.")

print(f"\n{CHECKS - FAILS}/{CHECKS} checks passed, {SKIPPED} skipped")
sys.exit(1 if FAILS else 0)
