#!/usr/bin/env python3
"""One command that answers two questions before a live demo: is every element green,
and where is today's dated capture of the x402 challenge. (stdlib only)

    python3 scripts/demo-preflight.py

Exit 0 = go. 1 = something SUBSTANTIVE is red. 2 = every failure was the network
refusing, so nothing was actually measured and a retry is allowed.

WHY THREE EXIT CODES AND NOT TWO. A probe that fails for a reason about ITSELF has not
told you anything about the thing it was pointed at, and folding that into "red" is the
defect this repo keeps finding in its own instruments. The contract here is deliberately
the same one `scripts/verify-proof.py` already uses, so a caller branches on one number
across both.

WHY THIS IS NOT A check-*.py GATE, and please do not rename it into one. Both discovery
walks that decide what runs in CI key on `git ls-files scripts/check-*.py`:
scripts/check-all.py and the scope floor in .github/workflows/regression-gate.yml. This
needs the public internet and a live host, so it belongs in neither. It is an operator
tool that a stranger can also run, which is a different thing from a publish gate.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
It sends NOTHING to the shop. No message, no order, no write of any kind. The shop is a
live agent that moves real money, so every probe here is GET or HEAD against an HTTP
endpoint, asserted below rather than left to good intentions.

It does not run scripts/verify_proof_ledger_control.py. That control is worth having and
takes 174.7 seconds measured, with no progress output, which is most of a five-minute
slot spent on dead air. It is declared here rather than silently omitted, because an
undocumented omission is indistinguishable from an oversight.

THE MEASURED BEHAVIOURS THIS ENCODES, each of which cost a rehearsal to learn
-----------------------------------------------------------------------------
A single failed request is not a verdict. The demo mp4's HEAD fails roughly 1 in 8, and
it is always the FIRST request; a retry returns 200 in 0.2s. So every probe retries
before it is allowed to report red.

verify-proof.py's STATIC half can go red from transport. Measured twice independently at
`9/10 static`, exit 2, on an RPC timeout. Static claims are about immutable history and
are still FETCHED, so a red there is not proof of a substantive problem. Its own exit
code says which kind it was, and that is what is read here rather than its prose.

Wall time is printed per element because it varies by more than it means. verify-proof.py
measured median 11.9s over 12 runs, worst 66.6s, with 3 of 12 over 30s.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Every URL is overridable, which is what makes this instrument testable: point one at a
# host that does not resolve and the run must go red for that element and stay green for
# the rest. A checker nobody has watched fail is a hypothesis.
PRICE_URL = os.environ.get("X402_PRICE_URL", "https://x402.perfpilot.dev/price")
SELFCHECK_URL = os.environ.get(
    "SHOP_SELFCHECK_URL", "https://x402.perfpilot.dev/selfcheck"
)
HEALTH_URL = os.environ.get("SHOP_HEALTH_URL", "https://x402.perfpilot.dev/health")
PAY_URL = os.environ.get("SHOP_PAY_URL", "https://zeroclaw-shop-pay.pages.dev/")
PAGES_URL = os.environ.get(
    "PAGES_ROOT_URL", "https://belumume.github.io/zeroclaw-solana/"
)
VIDEO_URL = os.environ.get(
    "DEMO_VIDEO_URL",
    "https://belumume.github.io/zeroclaw-solana/docs/assets/zeroclaw-demo-1080p.mp4",
)

ATTEMPTS = 3
BACKOFF = (0.5, 1.5)  # seconds before attempt 2 and attempt 3
TIMEOUT = 25
UA = "Mozilla/5.0 (compatible; zeroclaw-demo-preflight)"
SLOT_SECONDS = 300

# Declared, with the reason. The check-all.py pattern: what cannot run says so out loud.
NOT_RUN = {
    "scripts/verify_proof_ledger_control.py": (
        "174.7s measured with no progress output. Offline and worth running, but it is "
        "most of a demo slot. Run it separately, never on the call."
    ),
}

GREEN, RED = "GREEN", "RED"
TRANSPORT, SUBSTANCE = "TRANSPORT", "SUBSTANCE"


class Result:
    def __init__(self, name, verdict, seconds, note, kind=None, attempts=1):
        self.name = name
        self.verdict = verdict
        self.seconds = seconds
        self.note = note
        self.kind = kind  # TRANSPORT or SUBSTANCE, only when verdict is RED
        self.attempts = attempts


def is_transport(exc):
    """Same classification scripts/verify-proof.py uses, and for the same reason.

    A claim that stopped holding arrives as a SUCCESSFUL response carrying a different
    value, so it never reaches this function and can never be retried into looking
    healthy. Only the shapes below are safe to retry.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code >= 500 or exc.code in (408, 429)
    if isinstance(exc, urllib.error.URLError):
        return True
    return isinstance(exc, (TimeoutError, ConnectionError, OSError))


def fetch_once(url, method, want_body):
    """One request. Returns (status, headers, body_bytes). Raises on anything else.

    Read-only by construction rather than by convention: an unexpected method is a
    programming error here, and this script must never write to a live system.
    """
    if method not in ("GET", "HEAD"):
        raise ValueError(f"demo-preflight is read-only; refusing method {method}")
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read() if want_body else b""
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        # A 402 is the whole point of the x402 endpoint, and urllib raises it. Whether
        # that is a pass is the caller's call, not the transport layer's.
        body = e.read() if want_body else b""
        return e.code, dict(e.headers), body


def probe(name, url, expect, method="GET", want_body=False, want_ctype=None):
    """Retry transport before declaring anything down. See the module docstring."""
    t0 = time.time()
    last = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            status, headers, body = fetch_once(url, method, want_body)
        # HTTPError, URLError, TimeoutError and ConnectionError are all OSError
        # subclasses. A ValueError out of fetch_once is a programming error rather than
        # a finding, so it is deliberately left to crash instead of reported as red.
        except OSError as e:
            last = e
            if not is_transport(e) or attempt == ATTEMPTS:
                break
            time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
            continue

        dt = time.time() - t0
        if status != expect:
            # A wrong status that arrived is an answer, not a transport failure, unless
            # the status itself is one of the retryable shapes.
            retryable = status >= 500 or status in (408, 429)
            if retryable and attempt < ATTEMPTS:
                # Deliberately does not set `last`. The only route to the post-loop
                # fallback is the OSError branch's break, which sets it there; on the
                # final attempt this branch returns using `status` directly. Assigning
                # here would be dead code that reads as if it fed the fallback.
                time.sleep(BACKOFF[min(attempt - 1, len(BACKOFF) - 1)])
                continue
            return Result(
                name,
                RED,
                dt,
                f"HTTP {status}, expected {expect}",
                TRANSPORT if retryable else SUBSTANCE,
                attempt,
            )

        ctype = headers.get("Content-Type", "")
        if want_ctype and want_ctype not in ctype:
            return Result(
                name,
                RED,
                dt,
                f"HTTP {status} but Content-Type {ctype!r}",
                SUBSTANCE,
                attempt,
            )

        # Prefer the bytes actually received over the header, because a chunked
        # response carries no Content-Length and "? B" reads as a measurement that
        # was not taken. HEAD has no body, so there the header is all there is.
        size = str(len(body)) if want_body else (headers.get("Content-Length") or "?")
        note = f"HTTP {status}, {size} B"
        if want_ctype:
            note += f", {ctype.split(';')[0]}"
        if attempt > 1:
            note += f"  (attempt {attempt}/{ATTEMPTS})"
        r = Result(name, GREEN, dt, note, None, attempt)
        r.body = body
        r.headers = headers
        r.status = status
        return r

    dt = time.time() - t0
    kind = TRANSPORT if (last is None or is_transport(last)) else SUBSTANCE
    reason = f"{type(last).__name__}: {last}" if last else "no response"
    return Result(name, RED, dt, f"{reason} after {ATTEMPTS} attempts", kind, ATTEMPTS)


def run_script(name, argv, signal=None, transport_rc=None):
    """Run a repo script and report it. rc 0 is green.

    `transport_rc` names a return code the script itself defines as "the network
    refused", which is how verify-proof.py already reports a retryable failure. Reading
    its number rather than grepping its prose is deliberate: an earlier caller grepped
    for words like 'unreachable' and misclassified a genuine broken claim as transport.
    """
    t0 = time.time()
    r = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    dt = time.time() - t0
    out = (r.stdout or "") + (r.stderr or "")
    lines = [ln.strip() for ln in out.split("\n") if ln.strip()]

    note = ""
    if signal:
        hits = [ln for ln in lines if signal in ln]
        note = "; ".join(hits[:2]) if hits else ""
    if not note:
        note = lines[-1] if lines else "(no output)"
    # Mark a truncation rather than cutting mid-word, so a clipped line cannot be
    # misread under time pressure as a corrupt one.
    if len(note) > 78:
        note = note[:75] + "..."

    if r.returncode == 0:
        return Result(name, GREEN, dt, note)
    kind = (
        TRANSPORT
        if (transport_rc is not None and r.returncode == transport_rc)
        else SUBSTANCE
    )
    res = Result(name, RED, dt, f"rc={r.returncode}  {note}", kind)
    res.output = out
    return res


def verify_proof_note(out):
    """Pull the static and live split out, because the two halves fail for different
    reasons and a single number hides which one moved."""
    static = live = "?"
    for ln in out.split("\n"):
        s = ln.strip()
        if "static claims verified" in s:
            static = s.split()[0]
        elif "live claims verified" in s:
            live = s.split()[0]
    return static, live


def capture_label(path):
    """Render a capture path for the report. Never raises.

    A separate function because the crash it prevents was IN THE FORMATTING, not in the
    write. `--capture-dir` is a documented override that can point anywhere, and
    `Path.relative_to` raises for anything outside ROOT, so this line used to kill the
    run after every probe had finished and after the capture had already landed on disk.
    The traceback exited 1, which is the NO-GO code, so a crash was indistinguishable
    from a real substantive finding at the moment a caller was deciding whether to go.

    Relativising is a nicety. It must never cost the report, and it must be reachable by
    a test without a network round trip, which it was not while it lived inline.
    """
    try:
        return str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def capture_price(result, outdir):
    """Write the challenge body plus the instant it was taken, so it can be shown as an
    honestly labelled capture rather than passed off as a live fetch.

    The timestamp is the reason this runs shortly before the slot instead of days early.
    """
    outdir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    path = outdir / f"x402-price-{stamp}.json"

    body_text = result.body.decode("utf-8", "replace")
    try:
        parsed = json.loads(body_text)
    except json.JSONDecodeError:
        parsed = None

    record = {
        "captured_at_utc": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "label": f"CAPTURE, not a live fetch. Taken {now.strftime('%Y-%m-%d %H:%M UTC')}.",
        "url": PRICE_URL,
        "method": "GET",
        "http_status": result.status,
        "content_type": result.headers.get("Content-Type", ""),
        "body_bytes": len(result.body),
        "body": parsed if parsed is not None else body_text,
    }
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def main():
    ap = argparse.ArgumentParser(description="Pre-flight for the live demo.")
    ap.add_argument(
        "--capture-dir",
        default=str(ROOT / "preflight-captures"),
        help="where the dated /price capture is written (gitignored by default)",
    )
    ap.add_argument(
        "--no-capture", action="store_true", help="probe /price but write no artifact"
    )
    args = ap.parse_args()

    started = datetime.now(timezone.utc)
    print(f"demo preflight  {started.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"retry policy: {ATTEMPTS} attempts per probe, {TIMEOUT}s timeout\n")

    results = []
    py = sys.executable

    # 1. The offline spine. No network is involved, so a red here is substantive by
    #    construction and there is nothing to retry.
    results.append(
        run_script(
            "verify_proof_offline.py",
            [py, str(ROOT / "scripts" / "verify_proof_offline.py")],
            signal="verified offline",
        )
    )
    results.append(
        run_script(
            "certify_publish_tx.py",
            [py, str(ROOT / "scripts" / "certify_publish_tx.py")],
            signal="cases correct",
        )
    )
    results.append(
        run_script(
            "check_page.py",
            [py, str(ROOT / "sanitizer-microworld" / "check_page.py")],
            signal="structurally sound",
        )
    )

    # 2. verify-proof.py, reported with its two halves separated.
    t0 = time.time()
    vp = subprocess.run(
        [py, str(ROOT / "scripts" / "verify-proof.py")],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(ROOT),
    )
    vp_dt = time.time() - t0
    static, live = verify_proof_note((vp.stdout or "") + (vp.stderr or ""))
    if vp.returncode == 0:
        results.append(
            Result("verify-proof.py", GREEN, vp_dt, f"{static} static, {live} live")
        )
    else:
        kind = TRANSPORT if vp.returncode == 2 else SUBSTANCE
        res = Result(
            "verify-proof.py",
            RED,
            vp_dt,
            f"rc={vp.returncode}  {static} static, {live} live",
            kind,
        )
        res.output = (vp.stdout or "") + (vp.stderr or "")
        results.append(res)

    # 3. Every live element the demo leans on. GET or HEAD only.
    price = probe("x402 /price", PRICE_URL, expect=402, want_body=True)
    results.append(price)
    # want_body on every GET so the reported size is bytes received rather than a
    # header that some of these responses do not send.
    results.append(probe("x402 /selfcheck", SELFCHECK_URL, expect=200, want_body=True))
    results.append(probe("x402 /health", HEALTH_URL, expect=200, want_body=True))
    results.append(probe("pay page", PAY_URL, expect=200, want_body=True))
    results.append(probe("Pages root", PAGES_URL, expect=200, want_body=True))
    results.append(
        probe("demo mp4", VIDEO_URL, expect=200, method="HEAD", want_ctype="video/mp4")
    )

    # 4. The dated capture. Only possible if the probe actually got the challenge.
    capture_path = None
    capture_note = ""
    if args.no_capture:
        capture_note = "skipped (--no-capture)"
    elif price.verdict == GREEN:
        capture_path = capture_price(price, pathlib.Path(args.capture_dir))
        capture_note = capture_label(capture_path)
    else:
        capture_note = (
            "NOT WRITTEN: /price did not answer, so there is nothing honest to show"
        )

    # 5. The table.
    width = max(len(r.name) for r in results)
    print(f"{'element':<{width}}  {'verdict':<14} {'time':>7}  note")
    print("-" * (width + 60))
    for r in results:
        verdict = r.verdict if r.verdict == GREEN else f"{RED} {r.kind}"
        print(f"{r.name:<{width}}  {verdict:<14} {r.seconds:6.1f}s  {r.note}")

    total = sum(r.seconds for r in results)
    print("-" * (width + 60))
    print(f"{'total':<{width}}  {'':<14} {total:6.1f}s")

    print(f"\ncapture: {capture_note}")
    for name, why in sorted(NOT_RUN.items()):
        print(f"not run: {name}\n         {why}")

    if total > SLOT_SECONDS:
        print(
            f"\nBUDGET: {total:.0f}s of checks against a {SLOT_SECONDS}s slot. "
            "Start the slow ones and narrate over them."
        )

    reds = [r for r in results if r.verdict == RED]
    substance = [r for r in reds if r.kind == SUBSTANCE]

    if not reds:
        print(f"\nGO. {len(results)} element(s) green.")
        return 0

    for r in reds:
        print(f"\n--- {r.name} ({r.kind}) ---")
        out = getattr(r, "output", None)
        if out:
            for ln in out.split("\n")[-12:]:
                if ln.strip():
                    print(f"    {ln}")
        else:
            print(f"    {r.note}")

    if not substance:
        print(
            f"\nCOULD NOT CHECK. All {len(reds)} failure(s) were transport, so nothing "
            "was measured. Retry before treating any of this as a finding."
        )
        return 2

    print(
        f"\nNO-GO. {len(substance)} of {len(reds)} failure(s) are substantive. "
        "Name the claim on the call and fall back to the offline spine."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
