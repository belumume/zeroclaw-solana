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
import shutil
import subprocess
import sys
import tempfile
import urllib.error
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pre_export_gate as g

CHECKS = 0
FAILS = 0
SKIPPED = 0
# Whole layers that a missing tool took off the table. Named rather than counted, because a
# hardcoded case count is a number that drifts every time a case is added and nothing
# reports the drift. The summary prints these, so "110/110" can never read as full coverage
# when a layer never ran.
NOT_RUN: list[str] = []

# The module constant as it stood at import, before any case moved it. Layer 2 points
# VOID_CUT at a stand-in; this is what it must be back to afterwards, and asserting that is
# how the restore is shown to have fired rather than assumed to have.
VOID_AT_IMPORT = g.VOID_CUT

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
    "4 a different digest passes",
    verdict(g.check_not_void_cut("aaa", ["bbb"], "the working tree")) == PASS,
)
check(
    "4 an identical digest FAILS",
    verdict(g.check_not_void_cut("aaa", ["aaa"], "the working tree")) == FAIL,
)
check(
    "4 identical names the constraint",
    "human-voice" in g.check_not_void_cut("aaa", ["aaa"], "the working tree")[1],
)
# The superseded cut WAS deleted. Absent reference must NOT read as a pass.
check(
    "4 absent reference is NOT CHECKED",
    verdict(g.check_not_void_cut("aaa", [], "shallow clone")) == NC,
)
# The path carries TWO deleted versions, a 175.02s cut and the 159.52s trim that replaced
# it, and both were destroyed. A check that refused only one of them would pass the other
# -- which is the same artifact and the same disqualifier. Both directions, so a narrowing
# back to a single digest cannot pass silently.
_BOTH = ["first-version", "second-version"]
check(
    "4 the OLDER of two deleted versions FAILS",
    verdict(g.check_not_void_cut("first-version", _BOTH, "git history")) == FAIL,
)
check(
    "4 the NEWER of two deleted versions FAILS",
    verdict(g.check_not_void_cut("second-version", _BOTH, "git history")) == FAIL,
)
check(
    "4 a cut matching neither still passes",
    verdict(g.check_not_void_cut("something-else", _BOTH, "git history")) == PASS,
)
# WHICH MODE ANSWERED must be legible on every branch. A PASS sourced from git history and
# a PASS from a clone that had nothing to compare are different claims, and the second one
# is not a comparison at all -- so the label is asserted, not assumed.
check(
    "4 a PASS says where the reference came from",
    "git history" in g.check_not_void_cut("something-else", _BOTH, "git history")[1],
)
check(
    "4 a NOT CHECKED says why it could not look",
    "shallow clone" in g.check_not_void_cut("aaa", [], "shallow clone")[1],
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
# The same two-platform pair the check itself reads, and it has to stay the same pair: with
# only the Windows names, every case below skipped on Linux while the check there had no
# needle either, so the suite reported a clean skip over a detector searching for nothing.
USER = os.environ.get("USERNAME") or os.environ.get("USER") or ""
HOME = os.environ.get("USERPROFILE") or os.environ.get("HOME") or ""
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

# ffmpeg and ffprobe BUILD and READ every fixture here. Absent, build() used to raise
# FileNotFoundError out of subprocess.run and take the whole suite down with a traceback --
# including layers 1 and 3, which need no tools at all and are the controls that have
# actually caught regressions here (M2 and M3 both went stale under one refactor and both
# fired). A missing tool is an environment fact, not a finding, so it skips and says so.
FFMPEG_OK = bool(shutil.which("ffmpeg") and shutil.which("ffprobe"))


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
    F = build(Path(_td)) if FFMPEG_OK else {}
    missing = [k for k, v in F.items() if not v.is_file() or v.stat().st_size == 0]
    if not FFMPEG_OK:
        NOT_RUN.append("layer 2 (ffmpeg/ffprobe not on PATH)")
        print("  SKIP layer 2: ffmpeg/ffprobe not on PATH, so no fixture can be built")
    elif missing:
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

        # ROW 4 compares the target against every superseded version of the deleted cut.
        # Those resolve from git history now, so in an ordinary clone the row genuinely
        # runs -- but a SHALLOW clone reaches no history at all, and there the row reads
        # NOT CHECKED, rc 0 becomes unreachable and the E2b cases below cannot be satisfied.
        # Point VOID_CUT at a real file whose bytes differ from the fixture, so this block
        # is hermetic and does not depend on how the checkout was fetched. That supplies an
        # input, it does not switch the row off -- the check's own logic (a matching digest
        # FAILS, an empty set is NOT CHECKED, and BOTH deleted versions are refused) is
        # pinned by the "4 ..." cases in layer 1, and the gate only ever reads these bytes
        # in order to hash them.
        #
        # EVERY RESTORE IS REGISTERED AT ITS MUTATION, never in a try/finally further down.
        # The previous shape assigned g.VOID_CUT here and restored it in a `finally` roughly
        # fifty lines below that guarded only the last few statements, so anything raising
        # in between leaked the stand-in for the whole rest of the run -- and layer 4 reads
        # g.VOID_CUT, so a failure here would have silently pointed the incident case at 43
        # bytes of fixture text instead of a video. ExitStack rather than a hand-widened
        # try, because a hand-widened try is the thing that drifted in the first place: it
        # has to be remembered and re-widened on every edit, and a callback does not.
        with ExitStack() as _restore:
            _void_fixture = Path(_td) / "superseded-cut.mp4"
            _void_fixture.write_bytes(b"stand-in for the superseded cut; digest only")
            _restore.callback(setattr, g, "VOID_CUT", g.VOID_CUT)
            g.VOID_CUT = _void_fixture

            # THE OTHER DIRECTION, in two parts, because the first draft of this case
            # asserted rc==0 while passing --no-network --no-gates and the suite went red.
            # The gate was right and the case was wrong: two checks genuinely could not
            # run, so 3 is the correct answer and 0 would have been the gate lying. Kept
            # split, because the two halves prove different things.
            #
            # E2a: a clean file with two checks switched OFF must reach 3, never 0.
            _o2 = io.StringIO()
            with redirect_stdout(_o2), redirect_stderr(io.StringIO()):
                _rc2 = g.main(
                    [str(F["good"]), "--no-network", "--no-gates", "--fps", "1"]
                )
            _body2 = _o2.getvalue()
            _expect_off = 2 if g.TESSERACT.exists() else 4  # OCR off adds two more
            check(
                "F e2e: a good fixture never FAILS", _rc2 != 1, f"rc={_rc2}\n{_body2}"
            )
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

            # E2b: and rc 0 MUST be reachable, or the gate can never say "safe to export"
            # and every green above would describe a verdict nothing can obtain.
            #
            # THE EXTRACTION IS STUBBED, NOT ONLY THE CHECK. This used to stub
            # check_repo_gates while gate() still shelled out to scripts/check-all.py, so a
            # 155.5s subprocess ran and its result was thrown away -- 69% of a 226s suite,
            # spent on a value nothing reads. Stubbing repo_gate_result instead lets the
            # REAL check_repo_gates run on supplied facts, which is strictly more coverage
            # for strictly less time. Their own logic is covered by cases 9 and 10 above.
            #
            # Rows 7 and 8 need tesseract, so without it two rows are NOT CHECKED, rc is 3
            # rather than 0, and these three cases are unprovable. That is a missing tool,
            # not a finding: skip, and let the skip count say so.
            if not g.TESSERACT.exists():
                SKIPPED += 3
                print("  SKIP E2b: no tesseract, so rows 7 and 8 cannot reach PASS")
            else:
                _restore.callback(setattr, g, "fetch_status", g.fetch_status)
                _restore.callback(setattr, g, "repo_gate_result", g.repo_gate_result)
                g.fetch_status = lambda url: ("ok", "HTTP 200 (stubbed)")
                g.repo_gate_result = lambda: (
                    0,
                    "stubbed: check-all.py not re-run here",
                )

                _o4 = io.StringIO()
                with redirect_stdout(_o4), redirect_stderr(io.StringIO()):
                    _rc4 = g.main([str(F["good"]), "--fps", "1"])
                _body4 = _o4.getvalue()
                check(
                    "F e2e: rc 0 is reachable on a clean cut",
                    _rc4 == 0,
                    f"rc={_rc4}\n{_body4}",
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


# ======================================= 2b. THE RESTORE IS SCOPED TO THE MUTATION

print("\nlayer 2b: module state layer 2 moved is back where it started")

# R0 is the claim that matters: layer 2 pointed g.VOID_CUT at a 43-byte stand-in, and by
# the time layer 4 reads it, it is the real path again. Asserting it is the difference
# between the restore having FIRED and the restore having been WRITTEN.
check(
    "R0 layer 2 left g.VOID_CUT back at its import-time value",
    g.VOID_CUT == VOID_AT_IMPORT,
    f"{g.VOID_CUT} != {VOID_AT_IMPORT}",
)

# R1/R2 are the over-correction control for that change, and they are the reason it is not
# merely a tidier spelling of the same thing. R1 drives the OLD shape -- mutate, then a
# try/finally that begins BELOW the mutation -- and requires it to LEAK, because a control
# that cannot show the previous shape failing proves nothing about the new one. Both run
# against the real module object rather than a stand-in namespace, since the bug was about
# this module's attribute and a toy would not have caught it.
_before = g.VOID_CUT
try:
    g.VOID_CUT = Path("stand-in-that-must-not-survive.mp4")
    raise RuntimeError("anything at all raising in the window between the two")
    # The old code's try/finally started HERE, below the assignment, and so never covered
    # the statement that did the mutating.
except RuntimeError:
    pass
check(
    "R1 the old narrow-try shape LEAKS the stand-in through a raise",
    g.VOID_CUT != _before,
    "if this stopped leaking, the old shape was safe and R2 proves nothing",
)
g.VOID_CUT = (
    _before  # by hand, which is exactly what the old shape required of a reader
)
check("R1b and only a hand repair puts it back", g.VOID_CUT == _before)

try:
    with ExitStack() as _probe:
        _probe.callback(setattr, g, "VOID_CUT", g.VOID_CUT)
        g.VOID_CUT = Path("stand-in-that-must-not-survive.mp4")
        raise RuntimeError("the same failure, in the same window")
except RuntimeError:
    pass
check(
    "R2 the ExitStack shape restores g.VOID_CUT through that same raise",
    g.VOID_CUT == _before,
    f"{g.VOID_CUT} != {_before}",
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
# RE-KEYED AGAIN 2026-08-20, and the previous key passed BY COINCIDENCE. It blanked only
# the 'os account name' needle, but `identity` carries the SAME VALUE twice: the account
# name AND the home-directory basename. Wherever those match, which is nearly every
# machine and every CI runner (both 'runner'), blanking one leaves the other catching the
# planted leak, so the mutant was never disabled. It passed HERE only because this
# machine's account name and home directory happen to DIFFER. It failed on the first
# Linux runner it ever saw. Disabling the whole identity list is environment-independent
# and tests exactly the claim the control is named for.
_m2 = mutate(
    '    needles = identity + [(f"timezone marker {m.strip()!r}", m) for m in TZ_MARKERS]',
    '    needles = [] + [(f"timezone marker {m.strip()!r}", m) for m in TZ_MARKERS]',
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

# THE FIXTURE IS RECOVERED FROM GIT when the working tree no longer has it, which is every
# clone, because the artifact was deleted on purpose. Before this, E1 could only ever run on
# the one machine that still had the file -- so the case pinned as "the incident shape" was
# skipped everywhere it would have been useful, and the four assertions below had never been
# exercised by anybody else.
#
# ids[0] is the NEWEST surviving version, which matters: the path has two, a 175.02s cut and
# the 159.52s trim that replaced it. The measurements pinned below were taken on 2026-08-06,
# after the trim landed, so they describe the 159.52s one -- 159 frames at fps=1 is that
# duration and not the other. Reading the older blob would quietly re-point this case at a
# different video than the numbers in it describe.
_e1: Path | None = None
_e1_mode = ""
_e1_tmp = None
if not FFMPEG_OK:
    _e1_mode = "ffmpeg/ffprobe not on PATH, so the gate could not read a video anyway"
    NOT_RUN.append("layer 4 / E1 (ffmpeg/ffprobe not on PATH)")
elif g.VOID_CUT.is_file():
    _e1, _e1_mode = g.VOID_CUT, "the working tree"
else:
    _ids, _mode = g.superseded_blob_ids()
    _raw = g.git_blob_bytes(_ids[0]) if _ids else b""
    if _raw:
        _e1_tmp = tempfile.TemporaryDirectory(prefix="zcx-gate-e1-")
        _e1 = Path(_e1_tmp.name) / g.VOID_CUT.name
        _e1.write_bytes(_raw)
        _e1_mode = f"{_mode}, blob {_ids[0][:12]}, {len(_raw)} bytes"
    else:
        _e1_mode = _mode

if _e1 is not None:
    print(f"  E1 fixture recovered from {_e1_mode}")
    _o3 = io.StringIO()
    with redirect_stdout(_o3), redirect_stderr(io.StringIO()):
        # 0.05 fps keeps this to ~8 frames. The claim here is that the extraction path runs
        # on a real 159s file, NOT that 8 frames are leak coverage.
        _rc3 = g.main([str(_e1), "--no-network", "--no-gates", "--fps", "0.05"])
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
    # The blind-spot claim is about what OCR DID read, so it needs OCR to have run at all.
    # Without tesseract row 8 is NOT CHECKED, and asserting PASS there would turn a missing
    # tool into a red -- the exact "could not look" / "looked and it was fine" collapse the
    # gate's own exit codes exist to keep apart.
    if g.TESSERACT.exists():
        check(
            "E1 check 8 does NOT catch those explorer pages (the measured blind spot)",
            f"{PASS}  8 " in _b3,
            "if this flipped to FAIL the ceiling documented in check_explorer has changed",
        )
    else:
        SKIPPED += 1
        print("  SKIP E1 check-8 blind spot: no tesseract, so row 8 could not run")
    check("E1 refused on resolution", f"{FAIL}  2  resolution" in _b3, _b3)
    check(
        "E1 refused as the superseded cut", f"{FAIL}  4  not the superseded" in _b3, _b3
    )
    check(
        "E1 its duration is inside the limit, so that row passes",
        f"{PASS}  1  duration" in _b3,
        _b3,
    )
    if _e1_tmp is not None:
        _e1_tmp.cleanup()
else:
    SKIPPED += 4
    print(f"  SKIP E1: no fixture to run against ({_e1_mode or 'no reason recorded'}).")
    print("       A shallow clone reaches no history; fetch with --depth=0 to run it.")

print(f"\n{CHECKS - FAILS}/{CHECKS} checks passed, {SKIPPED} skipped")
if NOT_RUN:
    # A layer that never ran is not a layer that passed. Said out loud, because the count
    # above cannot distinguish them and a reader will take it for coverage.
    print("NOT RUN: " + "; ".join(NOT_RUN))
sys.exit(1 if FAILS else 0)
