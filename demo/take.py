#!/usr/bin/env python3
"""Shoot one verified demo beat, and refuse to call it a take unless the frame proves it.

WHY A RUNNER AND NOT A CHECKLIST. Every failure this thing guards against exits 0 while producing
nothing usable, so a human following a checklist cannot tell a good take from a dead one:

  - The default Windows console is GPU-composited and captures pure BLACK through gdigrab. The MP4
    is valid, ffmpeg exits 0, and every frame is empty. Measured: frame mean 0, 8,892 bytes for 4s.
  - `title X && ...` in cmd puts a TRAILING SPACE in the window title, and gdigrab matches exactly,
    so it reports "Can't find window" while PowerShell finds it fine. Writing the title on its own
    line in a .cmd file removes the failure mode rather than working around it.
  - Console windows have ODD pixel dimensions and yuv420p rejects them with a bare -22.

So the take is verified on the FRAME, never on an exit code: luminance proves light, and OCR of the
expected on-screen strings proves legibility and proves the right thing ran. A beat whose markers do
not appear is a failed take even if every command succeeded.

  python demo/take.py --list
  python demo/take.py --beat feed-heartbeat
  python demo/take.py --beat feed-heartbeat --dry-run    # run the command, skip the capture

Durations below were measured by agents that ran each command, not estimated.
"""

from __future__ import annotations

import argparse
import atexit
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / ".submission-research" / "takes"
TESSERACT = Path(
    "C:/Program Files/Tesseract-OCR/tesseract.exe"
)  # installed, not on PATH
TITLE = "ZCXTAKE"

# >=130 columns: the replay probe's output wraps below that and wrapped terminal text reads as
# noise on video. 34 rows keeps the tallest beat (the offline verifier, 20 lines) off the scroll.
#
# 134, not 130, and the distinction it encodes cost a shipped take: `mode con: cols=` sets the
# BUFFER, and conhost clamps the WINDOW to the panel. At Consolas height 30 the 1900px window
# rendered only ~106 of the 130 buffered columns, so characters past the window edge were CLIPPED
# OFF-FRAME while the gate passed on markers that sat left of the cut — the mainnet take shipped
# with `Custom": 300`, the entire point of its beat, outside the frame. Probed empirically
# (probe_geometry.py: launch, print a ruler ending in a marker, capture, OCR the marker):
#   height 30 / cols 130  ->  ~106 columns visible, CLIPPED
#   height 26 / cols 134  ->  1900x1024 window, ALL columns render
# 134 fits every beat's longest line: mainnet-refusal 120, replay-probe 130, reproducibility's
# PASS lines 133. Only reproducibility's 148-char footnote wraps, and a wrapped footnote is
# acceptable where a clipped payload is not.
COLS, ROWS = 134, 34


class Beat:
    def __init__(self, name, command, expect, seconds, note=""):
        self.name = name
        self.command = command
        self.expect = expect  # every one of these must survive OCR, or the take fails
        self.seconds = seconds  # measured, not guessed
        self.note = note


BEATS = [
    Beat(
        "feed-heartbeat",
        'set "FEED_PDA=JEtuZkcRzePbbLo8oiM26aqpbt1zJyLP4snvQCjVveg" && python scripts/feed_heartbeat.py',
        ["FRESH", "seq="],
        1.64,
        "Cleanest beat in the set. One 80-char line. The sequence advances between takes, which is "
        "the point: it is a live feed, not a screenshot. NOTE the cmd-native `set X=Y &&` form: the "
        "POSIX `FEED_PDA=... python ...` prefix this was recorded as does NOT run in a Windows "
        "console, and would have failed on camera.",
    ),
    Beat(
        "x402-challenge",
        "curl -si --ssl-revoke-best-effort https://x402.perfpilot.dev/price",
        ["402", "x402Version"],
        3.56,
        "curl works here with this flag, 0.4s. The earlier claim that curl fails TLS on this machine "
        "was refuted by measurement and is why this is curl rather than a wrapped Python one-liner.",
    ),
    Beat(
        "mainnet-refusal",
        "python3 scripts/verify_proof_offline.py --bundle docs/proof-bundle/mainnet-transactions.json",
        # The literal is {"Custom": 300} with a colon. Matching on the JSON punctuation would be
        # brittle under OCR, so the first two carry the meaning in characters that survive the
        # pixel round-trip. The third exists because of a measured failure, not symmetry: a take
        # shipped with `Custom": 300` clipped off the RIGHT EDGE of the frame while this gate
        # passed, because both original markers sit to the LEFT of the cut. `Custom` is the last
        # word on the beat's 120-char critical line, so if the frame loses the payload again the
        # gate fails instead of certifying a frame missing the entire point of the beat. Bare word,
        # no punctuation, and it appears only on that line.
        # `createFixedDelegation` rather than `cap=500000`, and the distinction is which FAILURE
        # each marker is for. The digit string is the semantic payload, and OCR misreads its final
        # zero as `@` (`cap=50000@`, both psm modes, measured on a frame where every character
        # renders crisply), so gating on it fails good frames — the FRESH/psm-11 lesson again: fix
        # the instrument's marker, never loosen the gate to protect a frame. The method name is on
        # the SAME line, is unambiguous English OCR reads reliably, and proves the same thing: the
        # cap line rendered. A human judge reads cap=500000 off the frame effortlessly.
        ["FAILED ON CHAIN", "createFixedDelegation", "Custom"],
        0.65,
        "Offline and byte-identical across runs, so it cannot fail mid-take. Film THIS rather than "
        "MAINNET-PROOF.md, whose own reproduce recipe moves real money. Best-composed beat in the "
        "set: five self-test lines (one positive control, four negative) render above three "
        "transactions, of which 1000000 is refused and 400000 settles against a 500000 cap. The "
        "control suite and the refusal it validates are on one screen.",
    ),
    Beat(
        "replay-probe",
        "python3 scripts/replay_allowance_probe.py",
        ["ACCEPT"],
        4.1,
        "Live against mainnet, no key and no funds. Warm it up before rolling: its only real risk is "
        "an RPC error printing a ~20-line raw traceback.",
    ),
    Beat(
        "chain-history",
        "python demo/chain_history.py",
        # From the real run this beat was built from: "774 tx | 0 failed | median gap 20.5 min |
        # largest gap 61.5 min | since 2026-07-25". The count moves every ~20 minutes, so no digit
        # string is a marker; the three word-shaped phrases are unique to the line and OCR-stable.
        ["failed", "median gap", "largest gap"],
        2.12,
        "The durability spine as ONE line, derived live by pagination rather than quoted, for "
        "beats 11 and 13. The ring close re-runs it and the count must be HIGHER than the beat-3 "
        "plant. The largest gap prints unconditionally: a judge running this finds it anyway, and "
        "a disclosed outlier is evidence the number was measured. Network beat: warm it before "
        "rolling, same as the others.",
    ),
    Beat(
        "reproducibility",
        "python3 scripts/verify-proof.py",
        # Taken from a real run, not from the summary anyone remembers. The counts themselves
        # ("10/10", "4/4") are deliberately NOT markers: a slash between digits is exactly what OCR
        # turns into a 1 or a letter, so gating on them would fail good frames. These two phrases
        # carry the same proof — both summary lines rendered — in characters that survive.
        ["static claims verified", "live claims verified"],
        9.67,
        "The reproducibility axis made visible, and the fourth of the four uncontested beats. One "
        "command, no install, no key, and fourteen checks go green: 10/10 static and 4/4 live on "
        "the measured run. TWO SHOOT CONSTRAINTS. It is 31 lines, which is near the console's row "
        "budget at the 30px font, so verify the summary has not scrolled off before keeping a take. "
        "And at 9.67s it is by far the longest beat here, roughly 6% of a three-minute cut, so it "
        "wants narration over it rather than silence, or a speed ramp in the edit. It also hits the "
        "network, so it carries the same warm-up requirement as the other live beats.",
    ),
]


def find(name):
    for b in BEATS:
        if b.name == name:
            return b
    return None


def launch(beat, hold):
    """Write the beat to a .cmd and run it under the LEGACY console host.

    The title goes on its own line, so it cannot pick up the trailing space that `title X && ...`
    produces and that gdigrab then cannot match.
    """
    script = OUT / f"_{beat.name}.cmd"
    script.write_text(
        "@echo off\r\n"
        f"title {TITLE}\r\n"
        f"mode con: cols={COLS} lines={ROWS}\r\n"
        # The default prompt renders the full cwd, which on this machine puts the operator's
        # Windows username on screen in a video bound for a public Discord post. Measured: a first
        # take carried "C:\\Users\\<name>\\DEV\\..." in the frame and nothing but OCR would have
        # caught it. A short project prompt is also simply better on camera.
        "prompt zeroclaw$G \r\n"
        "cls\r\n"
        f"{beat.command}\r\n",
        # No `timeout` here. MSYS ships its own `timeout` that takes -t rather than /t and wins on
        # PATH, so `timeout /t N` printed "invalid time interval" INTO THE CAPTURED FRAME. `cmd /k`
        # already holds the window open, so the hold was never needed; the tidy-looking line was
        # pure risk.
        encoding="utf-8",
    )
    subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f'Start-Process -FilePath "$env:SystemRoot\\System32\\conhost.exe" '
            f"-ArgumentList 'cmd.exe /k \"{script}\"' -WindowStyle Normal",
        ],
        cwd=str(REPO),
    )
    return script


# The console font is a per-user GLOBAL, and it is read when conhost CREATES the window. A
# per-title key (HKCU\Console\<title>) is never consulted here, because the .cmd sets the title
# AFTER launch, which is why an earlier attempt silently did nothing. So set the default, shoot,
# and put it back.
#
# Measured: default (__DefaultTTFont__, height 16) gives a 1260x680 window with 20px glyphs.
# Consolas at height 30 gave a 1900-wide window — and only ~106 VISIBLE columns of the 130-column
# buffer, which is the clipping defect documented at COLS above. The claim this comment used to
# make ("1900x1026 ... at 130 columns") conflated the buffer with the window: the window was 1900px,
# the columns were not all in it. Height 26 is the probed value at which every one of the 134
# buffered columns renders inside the panel (1900x1024 window, ~14px advance). Glyphs are still
# 1.6x the default's area.
FONT_KEY = r"HKCU:\Console"
SHOOT_FONT = {
    "FaceName": "Consolas",
    "FontFamily": 54,
    "FontWeight": 400,
    "FontSize": 0x001A0000,
}


def _ps(cmd):
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", cmd],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def font_snapshot():
    r = _ps(
        f'$p = Get-ItemProperty "{FONT_KEY}"; '
        '"{0}|{1}|{2}|{3}" -f $p.FaceName, [int]$p.FontSize, [int]$p.FontFamily, [int]$p.FontWeight'
    )
    parts = (r.stdout or "").strip().split("|")
    return parts if len(parts) == 4 else None


def font_apply(face, size, family, weight):
    _ps(
        f'Set-ItemProperty "{FONT_KEY}" -Name FaceName -Value "{face}"; '
        f'Set-ItemProperty "{FONT_KEY}" -Name FontSize -Value {int(size)} -Type DWord; '
        f'Set-ItemProperty "{FONT_KEY}" -Name FontFamily -Value {int(family)} -Type DWord; '
        f'Set-ItemProperty "{FONT_KEY}" -Name FontWeight -Value {int(weight)} -Type DWord'
    )


def window_title():
    r = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f'(Get-Process | Where-Object {{ $_.MainWindowTitle -like "{TITLE}*" }} '
            f"| Select-Object -First 1).MainWindowTitle",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return (r.stdout or "").strip()


def kill():
    subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            f'Get-Process | Where-Object {{ $_.MainWindowTitle -like "{TITLE}*" }} '
            f"| Stop-Process -Force -ErrorAction SilentlyContinue",
        ],
        capture_output=True,
    )


def frame_stats(png):
    r = subprocess.run(
        [
            "magick",
            str(png),
            "-colorspace",
            "Gray",
            "-format",
            "%[fx:int(mean*255)] %[fx:int(standard_deviation*255)]",
            "info:",
        ],
        capture_output=True,
        text=True,
    )
    try:
        m, s = r.stdout.split()
        return int(m), int(s)
    except Exception:
        return -1, -1


def frame_size(png):
    r = subprocess.run(
        ["magick", str(png), "-format", "%w %h", "info:"],
        capture_output=True,
        text=True,
    )
    try:
        w, h = r.stdout.split()
        return int(w), int(h)
    except Exception:
        return -1, -1


def ocr(png):
    if not TESSERACT.exists():
        return None
    # BOTH page-segmentation modes, unioned. A full terminal frame is a uniform text block, which is
    # psm 6; psm 11 is for sparse graphical layouts. Measured: on a real take, psm 11 alone read
    # "RESH:" and dropped the leading glyph, while psm 6 and a 4x upscaled crop of the same pixels
    # both read "FRESH:" correctly. The capture was fine and the reader was wrong, so the fix
    # belongs here rather than in a loosened marker.
    out = []
    for psm in ("6", "11"):
        r = subprocess.run(
            [str(TESSERACT), str(png), "stdout", "--psm", psm],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        out.append(r.stdout or "")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--beat")
    ap.add_argument("--list", action="store_true")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="run the command in this shell and check its markers, no window, no capture",
    )
    args = ap.parse_args()

    if args.list or not args.beat:
        print(f"{'beat':<18} {'measured':>9}  expects")
        for b in BEATS:
            print(f"{b.name:<18} {b.seconds:>8.2f}s  {', '.join(b.expect)}")
            print(f"{'':<18} {'':>9}  {b.note}")
        return 0

    beat = find(args.beat)
    if not beat:
        print(f"FAIL  no beat named {args.beat!r}; --list to see them", file=sys.stderr)
        return 2

    if args.dry_run:
        r = subprocess.run(
            beat.command,
            shell=True,
            cwd=str(REPO),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        body = (r.stdout or "") + (r.stderr or "")
        print(body[:1500])
        missing = [e for e in beat.expect if e not in body]
        print(
            f"\nexit={r.returncode}  markers missing from OUTPUT: {missing or 'none'}"
        )
        return 1 if missing else 0

    for tool in ("ffmpeg", "magick"):
        if not shutil.which(tool):
            print(f"FAIL  {tool} not on PATH", file=sys.stderr)
            return 2

    OUT.mkdir(parents=True, exist_ok=True)
    mp4 = OUT / f"{beat.name}.mp4"
    png = OUT / f"{beat.name}.png"

    # Hold the window open well past the command so the finished output is what gets captured.
    hold = int(beat.seconds) + 30
    kill()
    saved = font_snapshot()
    font_apply(
        SHOOT_FONT["FaceName"],
        SHOOT_FONT["FontSize"],
        SHOOT_FONT["FontFamily"],
        SHOOT_FONT["FontWeight"],
    )
    # Restore on ANY exit path, including an early return or an exception. A try/finally wrapping
    # the whole capture would also work and is easy to get subtly wrong; atexit cannot be. The font
    # is a per-user global, so leaving it changed would silently alter every console the operator
    # opens afterwards.
    if saved:
        atexit.register(font_apply, saved[0], saved[1], saved[2], saved[3])
    launch(beat, hold)

    # Let the command actually finish before rolling, or the capture films a half-drawn screen.
    time.sleep(3.0 + beat.seconds + 1.5)

    title = window_title()
    if not title:
        kill()
        print("FAIL  no console window appeared", file=sys.stderr)
        return 1
    if title != TITLE:
        kill()
        print(
            f"FAIL  window title is {title!r}, expected {TITLE!r}. A trailing space here is the "
            f"classic cause and gdigrab cannot match it.",
            file=sys.stderr,
        )
        return 1

    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "gdigrab",
            "-framerate",
            "30",
            "-i",
            f"title={TITLE}",
            "-t",
            "4",
            # pad rather than scale: console windows are odd-sized and resampling softens the type
            "-vf",
            "pad=ceil(iw/2)*2:ceil(ih/2)*2",
            "-c:v",
            "libx264",
            "-crf",
            "18",
            "-pix_fmt",
            "yuv420p",
            str(mp4),
        ],
        capture_output=True,
    )
    subprocess.run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(mp4),
            "-vf",
            "select=eq(n\\,40)",
            "-fps_mode",
            "passthrough",
            "-frames:v",
            "1",
            str(png),
        ],
        capture_output=True,
    )
    kill()

    if not mp4.exists() or mp4.stat().st_size == 0:
        print("FAIL  nothing was captured", file=sys.stderr)
        return 1
    if not png.exists():
        print("FAIL  could not extract a frame from the capture", file=sys.stderr)
        return 1

    mean, sd = frame_stats(png)
    text = ocr(png)
    missing = [e for e in beat.expect if e.lower() not in (text or "").lower()]

    w, h = frame_size(png)
    print(f"beat    : {beat.name}")
    print(f"capture : {mp4.name}  {mp4.stat().st_size:,} bytes")
    print(f"frame   : {w}x{h}  mean={mean} sd={sd}")
    upscale = max(1920 / w, 1080 / h) if w > 0 and h > 0 else 99.0
    if upscale > 1.15:
        # Not fatal, but say it every time. The cut this rebuild replaces shipped at 1280x720 and
        # its terminal text was soft for exactly this reason. A console window's pixel size is
        # font size x columns, so the fix is a LARGER CONSOLE FONT rather than more columns:
        # more columns at the same font makes the window wider and the glyphs no bigger.
        print(
            f"          NOTE below 1920x1080. Upscaling this into the timeline reproduces the "
            f"softness of the old cut. Raise the console font size before the real take."
        )

    if mean <= 1:
        print(
            "\nFAIL  the frame is BLACK. The window rendered through a GPU-composited host rather "
            "than conhost. Nothing about the exit code would have told you.",
            file=sys.stderr,
        )
        return 1
    if text is None:
        print(
            "\nFAIL  tesseract missing, so legibility is unproven. Luminance alone is not a take.",
            file=sys.stderr,
        )
        return 1
    # IDENTIFIER GATE. The video is a public deliverable, so an operator identifier in a single
    # frame is a leak that no later edit reliably removes. Two independent findings tonight hit
    # this: a default cmd prompt rendered the full home path into a take, and the posture guard
    # prints the home path when run bare. Derived from the environment and never written down,
    # because hardcoding the name here would publish it in the very file that screens for it.
    # Timezone strings are the third identifier class, found by the postmortem and missed by the
    # first version of this gate: explorer pages render timestamps in the OPERATOR'S timezone, so
    # every settlement frame quietly discloses where he lives ("West Africa Time" on the shipped
    # cut). These are literals rather than env-derived because the leak is what a THIRD PARTY'S
    # page prints about this machine, not what this machine knows about itself. Word-shaped
    # patterns only; a bare "WAT" would fire on WATCH.
    tz_markers = (
        "west africa",
        "africa/lagos",
        "utc+1",
        "utc+01",
        "gmt+1",
        "gmt+01",
        " wat ",
    )
    body = (text or "").lower()
    leaked = [
        label
        for label, value in (
            ("windows username", os.environ.get("USERNAME", "")),
            ("home directory", os.environ.get("USERPROFILE", "")),
        )
        if value and value.lower() in body
    ] + [f"timezone marker {m.strip()!r}" for m in tz_markers if m in body]
    if leaked:
        print(
            f"\nFAIL  the frame carries {leaked}. This take cannot ship. Set a bare prompt, cd to "
            f"a neutral path, or crop before it reaches an export.",
            file=sys.stderr,
        )
        return 1

    if missing:
        print(
            f"\nFAIL  the frame does not show {missing}. Light is not legibility: this frame has "
            f"content and it is not the content the beat is for.",
            file=sys.stderr,
        )
        print(f"OCR read: {' '.join((text or '').split())[:300]}", file=sys.stderr)
        return 1

    print(f"OCR     : {' '.join(text.split())[:220]}")
    print(
        f"\nPASS  every expected marker {beat.expect} is legible in the captured frame."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
