#!/usr/bin/env python3
"""Serve the CURRENT WhatsApp pairing QR as a live, self-refreshing page.

Why this exists: the daemon prints a fresh QR roughly every 20 seconds and stops
after about two minutes. Any delivery path that copies an image to a human takes
longer than the rotation, so the QR is always dead on arrival. The fix is to stop
delivering photographs of the QR and let the browser watch the source instead.

The raw `2@...` payload is never logged, only half-block art, so the modules are
reconstructed from the art. That is lossless: each text line carries two module
rows, `█` both dark, `▀` top dark, `▄` bottom dark, space neither.

Output is SVG rather than PNG so this needs no imaging library at all -- one rect
per dark module, which a browser renders crisply at any size.
"""

import html
import http.server
import re
import socketserver
import sys

LOG = "/home/ubuntu/.zeroclaw/daemon.log"
PORT = 8899
MARKER = "WhatsApp Web QR code"
FULL, UPPER, LOWER = "█", "▀", "▄"
ART = re.compile(f"[{FULL}{UPPER}{LOWER}]")


def latest_qr_grid():
    """Return (bitmap, age_lines) for the newest QR block, or (None, reason)."""
    try:
        with open(LOG, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().split("\n")
    except OSError as exc:
        return None, f"cannot read log: {exc}"

    # Walk backwards to the newest marker so a rotation is picked up immediately.
    start = None
    for i in range(len(lines) - 1, -1, -1):
        if MARKER in lines[i]:
            start = i
            break
    if start is None:
        return None, "no QR block in the log yet"

    art = []
    for ln in lines[start + 1 :]:
        if ART.search(ln):
            art.append(ln.rstrip("\r"))
        elif art:
            break
    if not art:
        return None, "marker found but no art followed it"

    width = max(len(ln) for ln in art)
    rows = []
    for ln in art:
        ln = ln.ljust(width)
        top, bot = [], []
        for ch in ln:
            top.append(1 if ch in (FULL, UPPER) else 0)
            bot.append(1 if ch in (FULL, LOWER) else 0)
        rows.append(top)
        rows.append(bot)

    # Trim the light border, then re-add a proper 4-module quiet zone. Scanners
    # need the quiet zone; the terminal art does not reliably carry one.
    dark_rows = [i for i, r in enumerate(rows) if any(r)]
    if not dark_rows:
        return None, "art parsed to an all-light grid"
    cols = range(len(rows[0]))
    dark_cols = [c for c in cols if any(r[c] for r in rows)]
    r0, r1 = dark_rows[0], dark_rows[-1]
    c0, c1 = dark_cols[0], dark_cols[-1]
    grid = [r[c0 : c1 + 1] for r in rows[r0 : r1 + 1]]

    q = 4
    w = len(grid[0]) + 2 * q
    padded = [[0] * w for _ in range(q)]
    for r in grid:
        padded.append([0] * q + list(r) + [0] * q)
    padded.extend([[0] * w for _ in range(q)])
    return padded, len(lines) - start


def svg(grid, scale=10):
    n_rows, n_cols = len(grid), len(grid[0])
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{n_cols * scale}" '
        f'height="{n_rows * scale}" shape-rendering="crispEdges">',
        '<rect width="100%" height="100%" fill="#fff"/>',
    ]
    for y, row in enumerate(grid):
        x = 0
        while x < n_cols:
            if row[x]:
                run = x
                while run < n_cols and row[run]:
                    run += 1
                parts.append(
                    f'<rect x="{x * scale}" y="{y * scale}" '
                    f'width="{(run - x) * scale}" height="{scale}" fill="#000"/>'
                )
                x = run
            else:
                x += 1
    parts.append("</svg>")
    return "".join(parts)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep the node's journal clean

    def do_GET(self):
        grid, info = latest_qr_grid()
        if grid is None:
            body = (
                "<h2>Waiting for a QR</h2><p>" + html.escape(str(info)) + "</p>"
                "<p>The daemon emits one about every 20 seconds while pairing is open.</p>"
            )
            square = ""
        else:
            body = (
                f"<p>Live from the node. {len(grid)}x{len(grid[0])} modules, "
                f"{info} log lines old. This page re-reads on every refresh, so what "
                "you see is the current QR, not a copy of an old one.</p>"
            )
            square = svg(grid)
        page = (
            "<!doctype html><meta charset=utf-8>"
            "<meta http-equiv=refresh content=3>"
            "<title>ZeroClaw - live WhatsApp QR</title>"
            "<style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;"
            "text-align:center;padding:18px}svg{background:#fff;padding:10px;border-radius:8px}"
            "p{max-width:44ch;margin:10px auto;line-height:1.45;font-size:14px;color:#bbb}</style>"
            "<h1>Scan in WhatsApp &gt; Linked Devices</h1>"
            f"{square}{body}"
        )
        raw = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)


if __name__ == "__main__":
    # Self-test before serving: a page that renders nothing is worse than a
    # missing page, because it looks like the pairing window closed.
    grid, info = latest_qr_grid()
    print(
        f"selftest: grid={'None' if grid is None else f'{len(grid)}x{len(grid[0])}'} info={info}"
    )
    if grid is not None and len(grid) != len(grid[0]):
        print("WARNING: grid is not square; art may be clipped", file=sys.stderr)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as srv:
        print(f"serving on 127.0.0.1:{PORT}")
        srv.serve_forever()
