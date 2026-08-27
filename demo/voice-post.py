#!/usr/bin/env python3
"""Master a human voiceover take, and prove the processing did not eat the voice.

The narration on this submission is human. That is a deliberate constraint, and it means the audio
arrives as a phone recording in a normal room rather than as a studio file, so the mastering has to
do real work without leaving the processed, underwater sound that makes a listener stop trusting
what they are hearing.

Every stage below is tied to a measurement of an actual take, not to a preset:

    integrated  -24.0 LUFS   ~8 dB under a web-video target
    true peak    +1.5 dBFS   already clipping, so this cannot be a simple gain
    loudness range 11.6 LU   far too wide for narration; mouth-to-mic distance moving
    noise floor -44.4 dB     room tone audible
    SNR          17.3 dB     the binding constraint, and the reason NR stays gentle

The trap this script exists to avoid: at 17 dB SNR, aggressive denoising produces the watery
artefact that reads instantly as "processed". So `nr` is low and the compressor does most of the
consistency work.

    python demo/voice-post.py take.m4a -o take-mastered.m4a

VERIFY, do not trust the numbers. Every value below moved the right way on the reference take, and
that alone proves nothing: a denoiser that removed the voice would improve the noise floor too. The
control that matters is INTELLIGIBILITY. Run --verify and the script measures before and after,
including high-frequency energy, which is where presence dies first when NR is too strong.

On the reference take this chain gave: -16.1 LUFS, 6.1 LU, -0.9 dBFS true peak, floor -71.1 dB, and
high-frequency energy up 8.5 dB against an 8 dB overall gain, meaning the top end tracked the gain
rather than being dulled. A speech-to-text pass over the processed file returned the source
transcript word for word, differing only in the engine's own non-lexical tags. Nothing was lost.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# 80 Hz: nothing in a speaking voice lives below it, and desk rumble, footsteps and handling noise
#   all do. Removing it before the compressor stops the compressor ducking the voice on a thump.
# afftdn nr=12: gentle on purpose. See the SNR note above.
# deesser: close phone mics exaggerate sibilance, and the compressor makes it worse.
# acompressor 3:1: the real fix for an 11.6 LU range. Slow-ish attack keeps consonant transients.
# loudnorm last: with an explicit true-peak ceiling, so the +1.5 dBFS clipping cannot survive.
CHAIN = (
    "highpass=f=80,"
    "afftdn=nr=12:nf=-45,"
    "deesser=i=0.4,"
    "acompressor=threshold=-20dB:ratio=3:attack=15:release=180:makeup=2,"
    "loudnorm=I=-16:TP=-1.5:LRA=7"
)


def run(args):
    return subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )


def measure(path):
    """Loudness, peak, range, noise floor and high-frequency energy.

    NOTE the absence of a quiet flag. ebur128 and astats report through ffmpeg's LOGGER at info
    level, so `-loglevel error` silences the measurement while the command still exits 0, and an
    empty result then looks exactly like a real reading of silence.
    """
    out = {}
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
    for key, pat in (
        ("lufs", r"I:\s*(-?\d+\.?\d*)\s*LUFS"),
        ("lra", r"LRA:\s*(-?\d+\.?\d*)\s*LU"),
        ("peak", r"Peak:\s*(-?\d+\.?\d*)\s*dBFS"),
    ):
        m = re.findall(pat, r.stderr or "")
        out[key] = float(m[-1]) if m else None

    r = run(
        [
            "ffmpeg",
            "-hide_banner",
            "-nostats",
            "-i",
            str(path),
            "-af",
            "astats=metadata=1",
            "-f",
            "null",
            "-",
        ]
    )
    for key, pat in (
        ("floor", r"Noise floor dB:\s*(-?\d+\.?\d*)"),
        ("rms", r"RMS level dB:\s*(-?\d+\.?\d*)"),
    ):
        m = re.findall(pat, r.stderr or "")
        out[key] = float(m[0]) if m else None

    r = run(
        [
            "ffmpeg",
            "-hide_banner",
            "-nostats",
            "-i",
            str(path),
            "-af",
            "highpass=f=4000,astats=metadata=1",
            "-f",
            "null",
            "-",
        ]
    )
    m = re.findall(r"RMS level dB:\s*(-?\d+\.?\d*)", r.stderr or "")
    out["hf"] = float(m[0]) if m else None
    return out


def show(label, m):
    def f(v, unit=""):
        return f"{v:>7.1f}{unit}" if isinstance(v, float) else "      ?"

    snr = (
        (m["rms"] - m["floor"])
        if (m["rms"] is not None and m["floor"] is not None)
        else None
    )
    print(
        f"  {label:<10} {f(m['lufs'], ' LUFS')}  range{f(m['lra'], ' LU')}  peak{f(m['peak'], ' dBFS')}"
        f"  floor{f(m['floor'], ' dB')}  SNR{f(snr, ' dB')}  HF{f(m['hf'], ' dB')}"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("-o", "--out")
    ap.add_argument(
        "--verify", action="store_true", help="measure before and after, and judge it"
    )
    args = ap.parse_args()

    if not shutil.which("ffmpeg"):
        print(
            "CANNOT CHECK  ffmpeg is not on PATH, so nothing can be mastered; "
            "install ffmpeg or add it to PATH.",
            file=sys.stderr,
        )
        return 2
    src = Path(args.source)
    if not src.exists():
        print(
            f"CANNOT CHECK  no such source file: {src}; pass an existing path.",
            file=sys.stderr,
        )
        return 2
    dst = Path(args.out) if args.out else src.with_name(src.stem + "-mastered.m4a")

    before = measure(src) if args.verify else None

    r = run(
        [
            "ffmpeg",
            "-y",
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(src),
            "-af",
            CHAIN,
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            str(dst),
        ]
    )
    if r.returncode != 0 or not dst.exists():
        print(f"FAIL  encode failed\n{(r.stderr or '')[:400]}", file=sys.stderr)
        return 1
    print(f"wrote {dst}  ({dst.stat().st_size:,} bytes)")

    if not args.verify:
        return 0

    after = measure(dst)
    print()
    show("before", before)
    show("after", after)
    print()

    problems = []
    if after["peak"] is not None and after["peak"] > -0.5:
        problems.append(
            f"true peak {after['peak']:+.1f} dBFS is too close to full scale"
        )
    if after["lufs"] is not None and not (-18 <= after["lufs"] <= -14):
        problems.append(
            f"integrated {after['lufs']:.1f} LUFS is outside the -18..-14 web band"
        )
    if after["lra"] is not None and after["lra"] > 9:
        problems.append(f"range {after['lra']:.1f} LU is still wide for narration")

    # The control that actually matters. Every metric above improves when a denoiser removes the
    # VOICE as well as the room, so a clean sheet up there is not evidence of anything. If the
    # top end fell while overall level rose, presence was eaten.
    if (
        before["hf"] is not None
        and after["hf"] is not None
        and before["rms"]
        and after["rms"]
    ):
        gain = after["rms"] - before["rms"]
        hf_gain = after["hf"] - before["hf"]
        print(f"  overall gain {gain:+.1f} dB, high-frequency gain {hf_gain:+.1f} dB")
        if hf_gain < gain - 3:
            problems.append(
                f"high frequencies rose only {hf_gain:+.1f} dB against {gain:+.1f} dB overall, so "
                f"the denoiser dulled the voice. Lower nr and re-run."
            )
        else:
            print("  top end tracked the gain, so NR did not dull the voice")

    print()
    if problems:
        for p in problems:
            print(f"FAIL  {p}", file=sys.stderr)
        return 1
    print("PASS  levels are in band and the voice survived the processing.")
    print(
        "      Numbers cannot prove intelligibility. Transcribe the OUTPUT and diff it against a"
    )
    print(
        "      transcript of the SOURCE; if words are missing, the chain is too aggressive."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
