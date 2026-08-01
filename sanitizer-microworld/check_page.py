"""Syntax-check the microworld page's script block.

A JS error here yields a page that renders its prose fine and does nothing when you type,
which is the worst failure shape for a demo artifact: it looks finished.
"""

import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(REPO, "sanitizer-microworld", "index.html")

html = io.open(PAGE, encoding="utf-8").read()
m = re.search(r"<script>(.*?)</script>", html, re.S)
if not m:
    print("no script block")
    sys.exit(2)
js = m.group(1)

node = shutil.which("node")
if not node:
    print("node not on PATH")
    sys.exit(2)

# Strip the base64 blob so the check is fast and the error line numbers stay readable.
js_small = re.sub(r'const WASM_B64 = "[^"]*";', 'const WASM_B64 = "";', js)

with tempfile.NamedTemporaryFile(
    "w", suffix=".js", delete=False, encoding="utf-8", newline="\n"
) as f:
    f.write(js_small)
    path = f.name

try:
    r = subprocess.run(
        [node, "--check", path], capture_output=True, text=True, timeout=30
    )
finally:
    os.unlink(path)

if r.returncode != 0:
    print("SCRIPT DOES NOT PARSE. The page would render and do nothing.")
    print(r.stderr.strip()[:800])
    sys.exit(1)

print(f"script parses ({len(js):,} chars, {len(js_small):,} without the wasm blob)")

# Cheap structural assertions on things that silently break the artifact.
checks = [
    ("wasm blob present", 'WASM_B64 = "' in js and len(js) - len(js_small) > 50_000),
    # Match actual HTML-injection SINKS, not the substring. The first version of this
    # flagged the comment explaining that we avoid innerHTML, which is the cry-wolf
    # failure: a checker that fires on prose gets muted exactly as fast as one that lies.
    (
        "no HTML-injection sink",
        not re.search(
            r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write\s*\(", js
        ),
    ),
    ("presets defined", js.count('"name":') >= 6 or js.count("name:") >= 6),
    ("alloc/sanitize called", "wasm.alloc(" in js and "wasm.sanitize(" in js),
    ("reads length prefix", "getUint32" in js),
]
bad = [n for n, ok in checks if not ok]
for n, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}  {n}")
print()
print("page structurally sound" if not bad else f"{len(bad)} structural problem(s)")
sys.exit(1 if bad else 0)
