#!/usr/bin/env python3
"""Two live x402 challenges, memos aligned, the rotating tail pointed at.

    $ python demo/nonce_diff.py
    challenge 1  memo: x402-18c8d158473c5d29-88
    challenge 2  memo: x402-18c8f10a22e41b77-13
                       ^^^^^ common prefix ^^^^^  ROTATED

The point is a single-use nonce visibly changing between requests, and without help it
is two near-identical strings: 21 of 23 characters are a common prefix, so the rotation is
invisible at a glance. This prints both memos aligned and marks where they diverge.

Alignment and a caret line rather than ANSI colour, deliberately: the take films a legacy conhost,
where VT escape rendering is a per-machine gamble, and the frame is OCR-gated, which colour does
not survive. Layout survives both.

A prior sed attempt at this silently emitted empty strings; this script REFUSES to print a
comparison unless both memos are non-empty and well-formed, because a highlighter that renders
nothing reads on camera as the feature not existing.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

URL = "https://x402.perfpilot.dev/price"


def challenge_memo():
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code != 402:
            raise
        body = json.loads(e.read())  # 402 IS the product; urlopen raises on it
    for item in body.get("accepts", []):
        memo = (item.get("extra") or {}).get("memo")
        if memo:
            return memo
    raise SystemExit("FAIL  no memo in the challenge body; the endpoint shape changed")


def main():
    a = challenge_memo()
    b = challenge_memo()
    if not a or not b:
        print(
            "FAIL  empty memo; refusing to render a comparison of nothing",
            file=sys.stderr,
        )
        return 1

    prefix = 0
    for x, y in zip(a, b):
        if x != y:
            break
        prefix += 1

    pad = " " * len("challenge 1  memo: ")
    print(f"challenge 1  memo: {a}")
    print(f"challenge 2  memo: {b}")
    if a == b:
        print(pad + "!" * len(a))
        print(
            "FAIL  the nonce DID NOT rotate between requests; that is the story, film nothing"
        )
        return 1
    print(pad + " " * prefix + "^" * (max(len(a), len(b)) - prefix))
    print(
        f"same prefix: {prefix} chars | tail ROTATED: single-use nonce, new on every request"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
