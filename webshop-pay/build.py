"""Assemble the Solana Pay checkout page from its vendored sources.

    python build.py            # write index.html
    python build.py --check    # verify index.html matches, write nothing (exit 1 on drift)

Self-contained and username-free: every path is relative to this file, so a fresh clone
can rebuild the deployed page with no machine-specific input and nothing machine-specific
ever ships to the deployed site.

WHY THE PAGE IS ASSEMBLED RATHER THAN EDITED DIRECTLY, since the obvious question is why
not just keep index.html by hand. It used to be exactly that, and the generator carried
its own stale copy of the markup inline. The two drifted: index.html accumulated the
pinned merchant address, the mint-keyed asset names, the wrong-recipient refusal and the
Portuguese translation, while build.py still held the version from before any of them.
Running it would have silently reverted four fixes at once, one of them the control that
stops a customer paying a wallet this shop does not own. There is now exactly one copy of
each part, and `--check` is what keeps the artifact and its sources from separating again.

NEWLINES: the vendored sources are LF. `write_text` applies the platform ending on write,
which is how the deployed file came to be CRLF, so `--check` compares text rather than
bytes and is therefore correct on either platform.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / "src"
OUT = HERE / "index.html"


def read(name: str) -> str:
    """Read a vendored part. Missing parts fail loudly: a silently-empty section would
    produce a page that still loads and quietly does less than it claims to."""
    p = SRC / name if name != "qrcode.js" else HERE / name
    if not p.is_file():
        raise SystemExit(f"missing source part: {p}")
    return p.read_text(encoding="utf-8")


html = (
    read("head.html")
    + "<style>"
    + read("style.css")
    + "</style></head><body>"
    + read("body.html")
    + "<script>"
    + read("qrcode.js")
    + "</script>"
    + "<script>"
    + read("app.js")
    + "</script>"
    + read("tail.html")
)

if "--check" in sys.argv:
    if not OUT.is_file():
        raise SystemExit(f"FAIL {OUT.name} does not exist; run: python build.py")
    current = OUT.read_text(encoding="utf-8")
    if current != html:
        raise SystemExit(
            f"FAIL {OUT.name} does not match its sources "
            f"(on disk {len(current)} chars, from sources {len(html)}).\n"
            "The page was edited directly, or a source part changed without a rebuild.\n"
            "Reconcile before deploying: whichever side is correct, make the other match."
        )
    print(f"OK {OUT.name} matches its sources ({len(html)} chars)")
else:
    OUT.write_text(html, encoding="utf-8")
    print(f"pay-page rebuilt: {len(html)} chars from {SRC.name}/ + qrcode.js")
