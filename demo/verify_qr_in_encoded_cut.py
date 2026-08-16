#!/usr/bin/env python3
"""CHECK 3: does the pay QR survive the lossy encode into the shipped cut?

`demo/verify_qr_scannable.py` already proves the QR decodes off the PAGE, from a browser render,
with two independent decoders. That is a different surface from this one. Between that render and
what a judge actually watches sits an h264 encode, and a QR is exactly the kind of high-frequency
square-edged content a lossy codec degrades: chroma subsampling, deblocking and motion estimation
all work against sharp module boundaries. A code that decodes off the page can fail off the tape,
and only the tape is shipped.

So this reads the ENCODED FILE, frame by frame, and asks whether a decoder still accepts it.

TWO DECODERS THAT DO NOT SHARE AN IMPLEMENTATION: pyzbar (zbar, C) and OpenCV's QRCodeDetector.
Agreement is the pass. Either alone can be fooled by a marginal render, which is the same argument
the page-side verifier makes and the reason it is repeated here rather than trusted from there.

THE NEGATIVE CONTROL IS THE POINT. A decoder that has never been shown to return nothing has not
been shown to be reading anything: if it reported a payload on every frame it would look identical
to a healthy run. So this also decodes frames that contain no QR at all and requires silence from
both. A run where every frame yields a payload is reporting on a broken instrument, not a good QR.

Stdlib plus opencv, pyzbar and ffmpeg. No network.

    python demo/verify_qr_in_encoded_cut.py
    python demo/verify_qr_in_encoded_cut.py --video path/to/other.mp4

DELIBERATELY NOT WIRED INTO ci.yml, and this note exists so that is not read as the orphan-gate
oversight it resembles. A CI gate earns its place by catching a REGRESSION, and the subject here
cannot regress: the cut is a shipped, frozen artifact. Wiring it would also put a 22 MB decode and
an ffmpeg dependency on every push to re-answer a settled question. It becomes a gate the moment
the video is replaced, which is the only event that can change its answer.

MEASURED on the shipped cut, 2026-08-16: 135 frames at a 1 s stride, 14 carrying a payload, 121
returning nothing, 4 decoding on BOTH, one distinct payload. Note the decoders disagree about WHICH
frames they can read -- zbar reads some, OpenCV others -- which is the two-decoder argument holding
up empirically rather than in principle.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_VIDEO = REPO / "docs" / "assets" / "zeroclaw-demo-1080p.mp4"

# Sample every N seconds. The QR is on screen for several seconds in the shipped cut, so a
# 1 s stride cannot miss it while keeping the run under a minute.
STRIDE_S = 1.0

# A run that finds no QR anywhere is far more likely to be a broken extraction than a cut with no
# QR in it, given the QR beat is the centre of the demo. Refuse to report a verdict in that case
# rather than printing a clean-looking zero.
MIN_FRAMES = 30


def ffmpeg_frames(video: Path, out: Path, stride: float) -> list[Path]:
    """Decode to PNGs at a fixed stride. Sequential decode, not -ss seeking.

    `-ss` and `select=eq(n,N)` both extract the WRONG frame on this source, which produced a bogus
    caption-mismatch verdict once already. Sequential decode with an fps filter is the form that
    has been shown to land on the frame it claims.
    """
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        "ffmpeg",
        "-v",
        "error",
        "-i",
        str(video),
        "-vf",
        f"fps=1/{stride}",
        "-fps_mode",
        "passthrough",
        str(out / "f_%05d.png"),
    ]
    subprocess.run(cmd, check=True, timeout=900)
    return sorted(out.glob("f_*.png"))


def decode_both(png: Path) -> tuple[str | None, str | None]:
    """(pyzbar_payload, cv2_payload). None where that decoder found nothing."""
    import cv2
    import numpy as np
    from PIL import Image
    from pyzbar.pyzbar import decode as zbar_decode

    img = Image.open(png).convert("RGB")
    z = zbar_decode(img)
    z_payload = z[0].data.decode("utf-8", "replace") if z else None

    arr = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
    ok, pts = cv2.QRCodeDetector().detect(arr)
    c_payload = None
    if ok:
        try:
            c_payload = cv2.QRCodeDetector().decode(arr, pts)[0] or None
        except cv2.error:
            c_payload = None
    return z_payload, c_payload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--video", default=str(DEFAULT_VIDEO))
    ap.add_argument("--stride", type=float, default=STRIDE_S)
    args = ap.parse_args()

    video = Path(args.video)
    if not video.is_file():
        print(f"NOT CHECKED: {video} does not exist.", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as td:
        frames = ffmpeg_frames(video, Path(td), args.stride)
        if len(frames) < MIN_FRAMES:
            print(
                f"NOT CHECKED: extraction produced only {len(frames)} frame(s), expected at least "
                f"{MIN_FRAMES}. A short walk reports a clean zero for the wrong reason.",
                file=sys.stderr,
            )
            return 2

        hits, silent = [], []
        for i, f in enumerate(frames):
            z, c = decode_both(f)
            if z or c:
                hits.append((i * args.stride, z, c))
            else:
                silent.append(i * args.stride)

        print(f"{video.name}: {len(frames)} frames at {args.stride}s stride")
        print(f"  frames yielding a QR payload : {len(hits)}")
        print(f"  frames yielding nothing      : {len(silent)}")

        # NEGATIVE CONTROL: silence must exist. If every frame decoded, the decoders are not
        # discriminating and a payload proves nothing.
        if not silent:
            print(
                "\nFAIL  every frame returned a payload. Both decoders are reporting on something "
                "other than a QR, so no pass here can be trusted.",
                file=sys.stderr,
            )
            return 1
        print(f"  negative control: {len(silent)} frame(s) correctly returned nothing")

        if not hits:
            print(
                "\nFAIL  the encoded cut contains no decodable QR at this stride. The QR beat is "
                "the centre of the demo, so this is a real regression or a wrong file.",
                file=sys.stderr,
            )
            return 1

        both = [h for h in hits if h[1] and h[2]]
        print(f"\n  frames where BOTH decoders agree: {len(both)}")
        for t, z, c in hits[:6]:
            agree = "both" if (z and c) else ("zbar only" if z else "cv2 only")
            payload = (z or c) or ""
            print(f"    t={t:6.1f}s  {agree:9}  {payload[:88]}")

        if not both:
            print(
                "\nFAIL  no frame decoded on BOTH. One decoder alone can be fooled by a marginal "
                "render, which is the whole reason two are run.",
                file=sys.stderr,
            )
            return 1

        payloads = {h[1] for h in both} | {h[2] for h in both}
        payloads.discard(None)
        print(f"  distinct payloads across agreeing frames: {len(payloads)}")
        for p in sorted(payloads):
            print(f"    {p[:110]}")

        print(
            f"\nOK  the QR survives the encode: {len(both)} frame(s) decoded by two independent "
            f"decoders, against {len(silent)} frame(s) where both correctly stayed silent."
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
