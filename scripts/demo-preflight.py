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
takes 46.1 seconds measured (2026-08-19, rc 0, six branches reached), with no progress
output at all. That is roughly three times this entire pre-flight, spent showing nothing,
which is why it stays out of a go/no-go check that has to answer fast. Re-time it with
  python -c "import subprocess,sys,time; t=time.time(); r=subprocess.run([sys.executable,'scripts/verify_proof_ledger_control.py']); print(time.time()-t, r.returncode)"
rather than trusting this number. It drives a decision rather than decorating one: whether
the control can fit in a slot at all depends on it, so a stale figure silently changes the
answer without looking wrong.
It is declared here rather than silently omitted, because an undocumented omission is
indistinguishable from an oversight.

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
import hashlib
import json
import os
import pathlib
import re
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
PROXY_URL = os.environ.get(
    "SETTLEMENT_PROXY_URL", "https://zeroclaw-rpc-proxy.cf-eeyw6.workers.dev"
)
PAGES_URL = os.environ.get(
    "PAGES_ROOT_URL", "https://belumume.github.io/zeroclaw-solana/"
)
VIDEO_URL = os.environ.get(
    "DEMO_VIDEO_URL",
    "https://belumume.github.io/zeroclaw-solana/docs/assets/zeroclaw-demo-1080p.mp4",
)

ATTEMPTS = 3
BACKOFF = (0.5, 1.5)  # seconds before attempt 2 and attempt 3
# The read-only allowlist, named so `fetch_once` states its rule instead of spelling it. Every
# member must be SAFE in the RFC 9110 sense; adding a method that can alter state defeats the
# module docstring's guarantee wherever a caller routes through here.
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
TIMEOUT = 25
UA = "Mozilla/5.0 (compatible; zeroclaw-demo-preflight)"
SLOT_SECONDS = 300

# Declared, with the reason. The check-all.py pattern: what cannot run says so out loud.
NOT_RUN = {
    "scripts/verify_proof_ledger_control.py": (
        "46.1s measured 2026-08-19 (rc 0), with no progress output. Offline and worth "
        "running, and short enough to run before the call rather than never. Kept out of "
        "this pre-flight because it is ~3x the whole check and prints nothing while it "
        "works. Run it separately, not on the call."
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

    OPTIONS joins GET and HEAD because it is a SAFE method in the RFC 9110 sense: it asks a
    server to describe itself and is defined never to alter state. It is here for a concrete
    reason rather than for completeness. The settlement Worker answers a CORS preflight from
    its own `cors()` and returns 204 before it parses a body, reaches an upstream, or touches
    KV, so OPTIONS reads the header that dates the deploy while POSTing a JSON-RPC probe
    would bill a metered upstream and write a permanent settlement key on every pre-flight.
    """
    if method not in SAFE_METHODS:
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


def _git_show(rel):
    """(bytes, None) for a blob at origin/main, or (None, reason). Never raises.

    The RETURNCODE is read rather than inferred from empty stdout. A renamed path, an unfetched
    ref and a genuinely empty file all produce zero bytes, and only git's own stderr separates
    them; the previous form printed "git fetch" for all three, which is advice that is wrong for
    two of them. `git` missing from PATH is an OSError and is a fact about the workstation rather
    than about the deploy, so it is reported as unreadable instead of killing the caller.
    """
    try:
        r = subprocess.run(
            ["git", "show", f"origin/main:{rel}"], capture_output=True, cwd=str(ROOT)
        )
    except OSError as e:
        return None, f"git unavailable ({type(e).__name__})"
    if r.returncode != 0:
        why = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        return None, (why[-1][:70] if why else f"git show rc={r.returncode}")
    return r.stdout, None


def _eol_digest(b):
    """sha256 over line-ending-normalised bytes.

    Normalising first means a deploy pipeline that re-encodes line endings does not read as drift
    while the content is identical. This repo pins `* text=auto eol=lf` in .gitattributes, so the
    blob and a Pages deploy agree today; a deploy taken straight from a Windows working copy under
    core.autocrlf=true would not, and it would differ by exactly one byte per line while saying
    the same thing.
    """
    return hashlib.sha256(b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")).hexdigest()


def _hdr(headers, name):
    """A case-insensitive header lookup over the plain dict `fetch_once` returns.

    `fetch_once` hands back `dict(r.headers)`, and that conversion DROPS the case-insensitivity
    `http.client.HTTPMessage` provides: the keys become whatever casing the wire used, so a
    lookup for a lowercase name misses a title-cased header entirely. Header names are
    case-insensitive per RFC 9110, so any proxy is free to re-case them, and the result here
    would be a confident DIFFERS about a surface that is current.
    """
    target = name.lower()
    return next((v for k, v in headers.items() if k.lower() == target), None)


def _expose_at_main(src):
    """The access-control-expose-headers value cors() ships at origin/main, or None.

    Parsed from source rather than pinned as a constant here, so the baseline moves when cors()
    moves. A constant would have to be edited in lockstep with the Worker, and the failure of
    that lockstep is the drift this whole function exists to detect.

    SCOPED TO cors() rather than searched over the whole file, because the first match anywhere
    wins and the real literal already has a four-line comment sitting directly above it. A
    header name quoted in a comment, a test fixture or a second block would silently become the
    baseline, and a wrong baseline reports drift with the same confidence as a right one.
    """
    text = src.decode("utf-8", "replace")
    start = text.find("function cors(")
    if start == -1:
        return None
    end = text.find("\n}", start)
    body = text[start : end if end != -1 else len(text)]
    m = re.search(
        r'["\']access-control-expose-headers["\']\s*:\s*["\']([^"\']*)["\']',
        body,
        re.IGNORECASE,
    )
    return m.group(1) if m else None


def _hdr_tokens(value):
    """A comma-separated header value as a comparable set.

    Order and whitespace carry no meaning in this header, so comparing raw strings would report
    drift for a reformat. Comparing sets reports it only for a real change in what is exposed.
    """
    return frozenset(t.strip().lower() for t in value.split(",") if t.strip())


def currency_report():
    """Is each deployed surface CURRENT? A different question from whether it is UP.

    Every other check here is liveness: a status code, a content type, a body that exists. None can
    tell a fresh deploy from one months behind, because a stale artifact answers 200 exactly like a
    current one. Measured 2026-08-19: this pre-flight returned GO with 10 green while the pay page
    was missing the entire double-payment fix and the settlement Worker was a commit behind, and
    neither appeared anywhere in the table.

    STRICTLY ADVISORY. It never touches the exit code, and its caller wraps it, because a deploy one
    commit behind is worth knowing on the morning of a demo and is not a reason to refuse to run
    one. Drift is a decision, not a failure.

    Compared against origin/main rather than the working tree ON PURPOSE: a branch checkout is ahead
    of every deploy by construction, so comparing against HEAD would report drift on every ordinary
    working day, and a check that is always red gets ignored.

    THE VERDICT IS DIFFERS RATHER THAN BEHIND, because a digest mismatch does not carry a
    direction. A deploy made from a branch is ahead, not stale, and calling that BEHIND sends the
    reader looking for a redeploy that would move the surface backwards.

    BOTH HALVES COMPARE A VALUE, never a proxy for one. The pay page is compared by sha256 over
    line-ending-normalised bytes: a byte LENGTH is not a content comparison, and this page carries
    same-length constants (`commitment:'confirmed'` against `'processed'`) whose meaning changes
    without changing size, so a length check reports CURRENT over exactly the edit that matters.
    The Worker is compared on the VALUE of its `access-control-expose-headers`, parsed out of
    `cors()` at origin/main. Presence alone is a one-shot ratchet: it can only ever prove the
    deploy is at-or-after the commit that introduced the header, so once that ships it reads
    CURRENT forever no matter how far the Worker drifts afterwards.

    EVERY REQUEST GOES THROUGH `probe`, which is what buys the retry the module docstring promises
    and what keeps the read-only guard load-bearing. The Worker is asked with OPTIONS, a CORS
    preflight it answers from `cors()` at 204 without parsing a body, reaching an upstream, or
    writing KV.

    CONTROLS, because a checker that can only report one verdict is decorative. `selftest_currency`
    below drives every branch against a localhost server: CURRENT on exact bytes, CURRENT on the
    same content re-encoded CRLF, DIFFERS on a same-length edit that a byte count calls identical,
    DIFFERS on a stale header value, and COULD NOT CHECK on a 404 and on an unresolvable host.
    Run it with `--selftest`; it opens no socket to the outside world.
    """
    rows = []

    blob, why = _git_show("webshop-pay/index.html")
    r = probe("pay page", PAY_URL, 200, want_body=True)
    if r.verdict == RED:
        rows.append(("pay page", "COULD NOT CHECK", r.note))
    elif blob is None:
        rows.append(("pay page", "COULD NOT CHECK", why))
    else:
        want, got = _eol_digest(blob), _eol_digest(r.body)
        rows.append(
            (
                "pay page",
                "CURRENT" if want == got else "DIFFERS from main",
                f"served {len(r.body):,} B sha256 {got[:12]} vs "
                f"main {len(blob):,} B sha256 {want[:12]}",
            )
        )

    src, why = _git_show("rpc-proxy/src/index.js")
    w = probe("settlement worker", PROXY_URL, 204, method="OPTIONS")
    want_hdr = _expose_at_main(src) if src is not None else None
    if w.verdict == RED:
        rows.append(("settlement worker", "COULD NOT CHECK", w.note))
    elif src is None:
        rows.append(("settlement worker", "COULD NOT CHECK", why))
    elif want_hdr is None:
        # The comparison has no baseline, which is a different state from a stale deploy and must
        # not borrow its verdict. It fires if cors() is refactored to build the header some other
        # way, and saying so is what stops a silent fall back to presence-only.
        rows.append(
            (
                "settlement worker",
                "COULD NOT CHECK",
                "no access-control-expose-headers literal in cors() at origin/main",
            )
        )
    else:
        got_hdr = _hdr(w.headers, "access-control-expose-headers")
        if got_hdr is None:
            rows.append(
                (
                    "settlement worker",
                    "DIFFERS from main",
                    "access-control-expose-headers ABSENT; the deploy predates it",
                )
            )
        else:
            mine, theirs = _hdr_tokens(got_hdr), _hdr_tokens(want_hdr)
            missing = sorted(theirs - mine)
            rows.append(
                (
                    "settlement worker",
                    "CURRENT" if mine == theirs else "DIFFERS from main",
                    f"expose-headers {len(mine)} token(s) vs main {len(theirs)}"
                    + (f"; missing {', '.join(missing)}" if missing else ""),
                )
            )

    width = max(len(n) for n, _, _ in rows)
    print("\ncurrency (advisory, never gates):")
    for name, state, note in rows:
        print(f"  {name:<{width}}  {state:<16} {note}")
    # The denominator is the CHECKED count, not the row count. "0 of 2 behind" printed when both
    # rows are COULD NOT CHECK is a reassuring zero from a check that never ran, which is precisely
    # the failure this block exists to catch, so it must not be reproduced by the block itself.
    behind = [n for n, st, _ in rows if st.startswith("DIFFERS")]
    unknown = [n for n, st, _ in rows if st.startswith("COULD NOT")]
    checked = len(rows) - len(unknown)
    summary = f"  {len(behind)} of {checked} CHECKED surface(s) differ from main"
    if behind:
        summary += ": " + ", ".join(behind)
    if unknown:
        summary += f"; {len(unknown)} NOT MEASURED ({', '.join(unknown)}) -- not the same as current"
    print(summary)


def runbook_pins_report(price_result):
    """Compare the runbook's PINNED /price values against the body just fetched.

    WHY THIS EXISTS, and why it lives here rather than in a repo gate. `notes/` is gitignored, so
    every tracked-path checker in this repo is structurally blind to it. That blind spot has now
    produced the same class of defect THREE times, and the third was the expensive one: after the
    gate binary was deployed and the day-pass tier left the live menu, the runbook still told the
    operator that saying "one payment, one read" would be CONTRADICTED BY THE SCREEN. It no longer
    was. That instruction would have suppressed the truest sentence in the beat, on camera, to
    avoid a contradiction which had been fixed hours earlier.

    The check keys on the INVARIANT -- the runbook must not describe a live menu that differs from
    the live menu -- rather than on any wording, because wording is what changes when someone
    improves the prose, and a check keyed to one phrasing punishes the correct edit.

    IT IS ENFORCED IN BOTH DIRECTIONS, which the first version was not. It fired when the runbook
    said the day-pass tier was STILL on the menu and was silent when the runbook said the tier was
    GONE and the tier came back -- so the reversal of the exact defect it was built for would have
    passed. Both directions now compare against the live tier COUNT.

    HONEST CEILING, three of them, so this is never read as covering the file. It reads only lines
    naming `/price` or the day pass, so a stale figure elsewhere in the runbook is invisible to it
    (the enumeration of what else the runbook claims, and what is deliberately left ungated, is the
    survey this grew out of). A historical marker still silences everything after it on its line,
    so a line that puts its retired value FIRST is skipped. And it can only run where a live body
    is in hand, which is demo morning, not CI.

    It runs HERE because this script already fetches /price on demo morning, which is both the
    moment a stale pin costs the most and the only moment the live value is in hand.

    SKIPS cleanly when the runbook is absent (a fresh clone has no `notes/`) and SAYS so, because a
    silent pass and a real pass must never look alike.
    """
    t0 = time.time()
    rb = pathlib.Path(__file__).resolve().parent.parent / "notes" / "DEMO-RUNBOOK.md"
    if not rb.exists():
        return Result(
            "runbook pins",
            GREEN,
            time.time() - t0,
            "SKIPPED: no notes/DEMO-RUNBOOK.md here (expected in a fresh clone)",
        )
    if not getattr(price_result, "body", None):
        return Result(
            "runbook pins",
            GREEN,
            time.time() - t0,
            "SKIPPED: /price returned no body, so there is nothing to compare against",
        )
    try:
        live = json.loads(price_result.body.decode("utf-8", "replace"))
        tiers = live.get("accepts") or []
    except json.JSONDecodeError:
        return Result(
            "runbook pins",
            GREEN,
            time.time() - t0,
            "SKIPPED: /price body did not parse as JSON",
        )

    live_bytes = len(price_result.body)
    lines = rb.read_text(encoding="utf-8", errors="replace").splitlines()
    problems = []
    scanned = 0

    # A figure is HISTORICAL when its own line marks it so. That exemption is what lets a line cite
    # a past value as context without this reading it as a live claim -- the same distinction a
    # correction sweep draws between a value still being asserted and one quoted to retire it.
    historical = ("was ", "before", "previously", "used to", "prior to", "superseded")

    for i, line in enumerate(lines, 1):
        if "/price" not in line:
            continue
        scanned += 1
        # SPAN-SCOPED, NOT LINE-SCOPED. A marker retires the figures that FOLLOW it, never the
        # whole line. `**666 B** (was 988 before the deploy)` states one current value and one
        # retired one, and dropping the line to spare the 988 spares the 666 with it. Measured:
        # the runbook pinned /price at 664 B against a live 666 B and this reported "all agree",
        # because the same line carried a historical parenthetical. Everything from the first
        # marker onward is dropped and the prefix is still read.
        low = line.lower()
        cut = min((low.find(h) for h in historical if h in low), default=len(line))
        head = line[:cut]
        toks = head.replace("**", " ").replace("|", " ").replace(",", "").split()
        for j, tok in enumerate(toks[:-1]):
            if tok.isdigit() and toks[j + 1].rstrip(".,;)").upper() == "B":
                n = int(tok)
                if n != live_bytes and n > 99:
                    problems.append(
                        f"line {i} pins /price at {n} B; live is {live_bytes} B"
                    )

    # The tier claim. Only a CURRENT-tense assertion counts: a line retiring the day pass has to
    # NAME it in order to retire it, which is the prohibition-must-name-what-it-forbids trap.
    n_live = len(tiers)
    current = ("still serves", "still advertis", "both menu tiers", "both tiers")
    for i, line in enumerate(lines, 1):
        low = line.lower()
        if "day pass" not in low and "day-pass" not in low:
            continue
        if any(h in low for h in historical) or "gone from the live menu" in low:
            continue
        if any(w in low for w in current):
            descs = [t.get("description") for t in tiers]
            problems.append(
                f"line {i} says the live menu still carries a day pass; live /price has "
                f"{n_live} tier(s): {descs}"
            )

    # THE MIRROR, and it is the direction that cost the most. The loop above only fires when the
    # runbook says the menu STILL carries a day pass. Nothing fires when the runbook asserts the
    # tier is GONE and a tier comes BACK -- and a retirement sentence has to NAME what it retires,
    # so `gone from the live menu` is both the honest wording and the exemption that would keep the
    # reversal silent. That asymmetry is the whole defect class here: the expensive one was a
    # SPOKEN instruction derived from live state, still true when written and false by the morning.
    # Keyed to the tier COUNT, which is the invariant, rather than to either phrasing.
    retired = (
        "gone from the live menu",
        "one `accepts` entry",
        "one accepts entry",
        "the screen now agrees",
    )
    if n_live > 1:
        descs = [t.get("description") for t in tiers]
        for i, line in enumerate(lines, 1):
            low = line.lower()
            if any(w in low for w in retired):
                problems.append(
                    f"line {i} says the live menu no longer carries the withdrawn tier, or that "
                    f"the screen agrees with a one-tier line; live /price has {n_live} tier(s): "
                    f"{descs}"
                )

    dt = time.time() - t0
    if problems:
        return Result(
            "runbook pins",
            RED,
            dt,
            f"{len(problems)} stale live-value claim(s): " + "; ".join(problems[:3]),
            SUBSTANCE,
        )
    return Result(
        "runbook pins",
        GREEN,
        dt,
        f"{scanned} /price line(s) scanned, all agree with live ({live_bytes} B, {n_live} tier)",
    )


def selftest_runbook_pins():
    """Drive both verdicts against a temp runbook. Opens no socket.

    The control is the whole point: a checker that has only ever printed GREEN cannot be told apart
    from one that cannot print anything else. The cases are PAIRED -- a stale claim that must fire
    beside its corrected form that must not -- so a later narrowing which silences the detector goes
    red here rather than in front of the operator.
    """

    class FakeResult:
        pass

    # PADDED PAST THE n > 99 FLOOR ON PURPOSE, and this is a fixture correction rather than a
    # decoration. The unpadded body was 82 B, which the byte-pin floor discards before comparing,
    # so EVERY must-not-fire byte case here passed without the equality branch ever running and
    # the one must-fire case passed only because 988 happens to clear the floor. A fixture that
    # cannot reach the code it is asserting on is the same false-green this file exists to catch.
    # The real endpoint answers in the high hundreds, so this also matches production shape.
    body = json.dumps(
        {
            "accepts": [
                {"description": "one feed reading", "maxAmountRequired": "1000000"}
            ],
            "resource": "https://example.invalid/feed/latest" + "x" * 480,
        }
    ).encode()
    fake = FakeResult()
    fake.body = body
    live_n = len(body)
    assert live_n > 99, (
        "fixture must clear the byte-pin floor or every byte case is vacuous"
    )

    # A SECOND live shape, so the mirror cases have a two-tier menu to disagree with. Without it
    # the reversal cases could only be asserted against a one-tier body, which is the state in
    # which they must stay SILENT -- and a case that can only pass is not a control.
    two_tier = FakeResult()
    two_tier.body = json.dumps(
        {
            "accepts": [
                {"description": "one feed reading", "maxAmountRequired": "1000000"},
                {"description": "day pass: unlimited", "maxAmountRequired": "9000000"},
            ]
        }
    ).encode()

    cases = [
        (
            f"| x402 `/price` | HTTP 402, {live_n} B | ok |",
            False,
            "matching byte pin",
            fake,
        ),
        ("| x402 `/price` | HTTP 402, 988 B | ok |", True, "stale byte pin", fake),
        (
            "The deployed gate still serves BOTH menu tiers, including a day pass.",
            True,
            "current-tense day-pass claim",
            fake,
        ),
        (
            "The withdrawn day-pass tier is gone from the live menu.",
            False,
            "retirement sentence naming what it retires",
            fake,
        ),
        (
            "The day pass was removed on 2026-08-20.",
            False,
            "historical day-pass mention",
            fake,
        ),
        (
            f"| x402 `/price` | **{live_n} B** (was 988 before the deploy) | ok |",
            False,
            "a line citing a past value behind a historical marker",
            fake,
        ),
        # THE PAIR THAT FAILED BEFORE THIS CHANGE, and the reason it was found. Identical prose to
        # the case above except the CURRENT figure is stale; the line-scoped exemption cleared both
        # and reported "all agree" over a real 2-byte drift in the live runbook.
        (
            f"| x402 `/price` | **988 B** (was {live_n} before the deploy) | ok |",
            True,
            "a STALE current pin sharing its line with a historical aside",
            fake,
        ),
        (
            "| x402 `/price` | **previously 988 B**, now smaller | ok |",
            False,
            "over-correction control: a marker FIRST still silences the rest of the line",
            fake,
        ),
        # THE MIRROR. Each of these is the sentence a correct runbook carries TODAY, so the
        # one-tier column proves the gate is not simply loud, and the two-tier column proves it
        # can see the reversal at all.
        (
            "The withdrawn day-pass tier is gone from the live menu.",
            True,
            "mirror: a retirement sentence while the tier is BACK",
            two_tier,
        ),
        (
            "`/price` returns ONE `accepts` entry, and nothing else.",
            True,
            "mirror: a one-tier assertion while the tier is BACK",
            two_tier,
        ),
        (
            'SAY "ONE PAYMENT, ONE READ". The screen now agrees with you.',
            True,
            "mirror: the SPOKEN instruction while the tier is BACK",
            two_tier,
        ),
        (
            'SAY "ONE PAYMENT, ONE READ". The screen now agrees with you.',
            False,
            "the same spoken instruction while the menu really is one tier",
            fake,
        ),
        ("nothing relevant here at all", False, "unrelated text", fake),
        (
            "nothing relevant here at all",
            False,
            "unrelated text, two-tier menu",
            two_tier,
        ),
    ]

    failures = []
    rb = pathlib.Path(__file__).resolve().parent.parent / "notes" / "DEMO-RUNBOOK.md"
    rb.parent.mkdir(exist_ok=True)
    backup = rb.read_text(encoding="utf-8") if rb.exists() else None
    try:
        for text, must_fire, label, price in cases:
            rb.write_text(text, encoding="utf-8", newline="")
            r = runbook_pins_report(price)
            fired = r.verdict == RED
            if fired != must_fire:
                want = "FIRE" if must_fire else "silent"
                failures.append(f"  {label}: expected {want}, got: {r.note}")
        # The skip path must be reachable AND must announce itself.
        rb.unlink()
        r = runbook_pins_report(fake)
        if "SKIPPED" not in r.note:
            failures.append("  absent runbook: expected an explicit SKIPPED note")
    finally:
        if backup is not None:
            rb.write_text(backup, encoding="utf-8", newline="")
        elif rb.exists():
            rb.unlink()

    for f in failures:
        print(f)
    total = len(cases) + 1
    print(f"runbook-pin selftest: {total - len(failures)}/{total}")
    return 1 if failures else 0


def selftest_currency():
    """Drive every currency verdict against a localhost server. Opens no outside socket.

    The load-bearing case is `same length, different meaning`: it is the one a byte-count check
    calls CURRENT, so it is what proves the digest comparison is doing work rather than decorating
    it. The CRLF case is its mirror -- different bytes, same meaning -- and proves the fix did not
    over-correct into reporting drift for a re-encode.
    """
    import contextlib
    import io
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    global PAY_URL, PROXY_URL, _git_show

    page = b"<html>\n<body>commitment:'confirmed'</body>\n</html>\n"
    full = "x-zc-fast, x-zc-deep, x-zc-allowed-0"
    # Shaped like the real cors(), because the baseline parser is scoped to that function and a
    # fixture that omits it would exercise a code path the Worker never takes.
    src = f'function cors(origin, allowed) {{\n  "access-control-expose-headers":\n    "{full}",\n}}\n'.encode()
    bodies = {
        "exact": page,
        "crlf": page.replace(b"\n", b"\r\n"),
        # Byte-identical in LENGTH to `page` ('confirmed' and 'processed' are both 9 chars) and
        # opposite in meaning. This is the edit the old delta==0 check reported as CURRENT.
        "samelen": page.replace(b"confirmed", b"processed"),
    }
    hdrs = {
        "full": full,
        "stale": "x-zc-fast, x-zc-deep",
        "none": None,
        "titlecase": full,
    }

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            key = self.path.rsplit("/", 1)[-1]
            if key not in bodies:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(bodies[key])))
            self.end_headers()
            self.wfile.write(bodies[key])

        def do_OPTIONS(self):
            self.send_response(204)
            key = self.path.rsplit("/", 1)[-1]
            v = hdrs.get(key)
            if v is not None:
                # TITLE-CASED on purpose for one route. Header names are case-insensitive per
                # RFC 9110 and any proxy may re-case them, and a stub that only ever emits
                # lowercase cannot see a lookup that depends on the casing.
                name = (
                    "Access-Control-Expose-Headers"
                    if key == "titlecase"
                    else "access-control-expose-headers"
                )
                self.send_header(name, v)
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    cases, failures = 0, []

    def report(name, ok):
        nonlocal cases
        cases += 1
        if not ok:
            failures.append(name)

    def row(pay, proxy, blob=page, worker=src):
        global PAY_URL, PROXY_URL, _git_show
        PAY_URL = pay
        PROXY_URL = proxy

        def stub(rel):
            return (blob, None) if rel.endswith("index.html") else (worker, None)

        _git_show = stub
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            currency_report()
        out = buf.getvalue()
        return (
            next(ln for ln in out.splitlines() if "pay page" in ln),
            next(ln for ln in out.splitlines() if "settlement worker" in ln),
        )

    base = f"http://127.0.0.1:{port}"
    real_git_show, real_pay, real_proxy = _git_show, PAY_URL, PROXY_URL
    try:
        pay, wk = row(f"{base}/pay/exact", f"{base}/proxy/full")
        report("exact bytes read CURRENT", "CURRENT" in pay)
        report("an exact expose-header read CURRENT", "CURRENT" in wk)

        pay, _ = row(f"{base}/pay/crlf", f"{base}/proxy/full")
        report("the same content re-encoded CRLF still reads CURRENT", "CURRENT" in pay)

        pay, _ = row(f"{base}/pay/samelen", f"{base}/proxy/full")
        report("a SAME-LENGTH edit reads DIFFERS", "DIFFERS" in pay)

        pay, _ = row(f"{base}/pay/missing", f"{base}/proxy/full")
        report("a 404 reads COULD NOT CHECK, never DIFFERS", "COULD NOT CHECK" in pay)
        report("and the 404 is not counted as drift", "DIFFERS" not in pay)

        _, wk = row(f"{base}/pay/exact", f"{base}/proxy/stale")
        report("a stale expose-header value reads DIFFERS", "DIFFERS" in wk)
        report("and it names the token that is missing", "x-zc-allowed-0" in wk)

        _, wk = row(f"{base}/pay/exact", f"{base}/proxy/none")
        report("an absent expose-header reads DIFFERS", "DIFFERS" in wk)

        pay, wk = row(
            "http://zc-no-such-host.invalid/p", "http://zc-no-such-host.invalid/x"
        )
        report(
            "an unresolvable pay host reads COULD NOT CHECK", "COULD NOT CHECK" in pay
        )
        report(
            "an unresolvable worker host reads COULD NOT CHECK", "COULD NOT CHECK" in wk
        )

        # No baseline is its OWN verdict, never a borrowed DIFFERS.
        _, wk = row(
            f"{base}/pay/exact", f"{base}/proxy/full", worker=b"function cors(){}"
        )
        report("an unparseable cors() reads COULD NOT CHECK", "COULD NOT CHECK" in wk)

        # HEADER NAMES ARE CASE-INSENSITIVE and the dict `fetch_once` returns is not. Without
        # this case a title-casing proxy makes a CURRENT Worker read DIFFERS, and nothing here
        # would notice, because every other route in this stub emits lowercase.
        _, wk = row(f"{base}/pay/exact", f"{base}/proxy/titlecase")
        report("a title-cased expose-header still reads CURRENT", "CURRENT" in wk)

        # THE BASELINE MUST COME FROM cors(), not from the first quoted literal in the file. A
        # decoy above the function is the shape that actually occurs: the real literal already
        # has a comment block sitting directly above it.
        decoy = (
            b'// "access-control-expose-headers": "x-decoy"\n'
            b"function cors(){\n"
            b'  "access-control-expose-headers": "' + full.encode() + b'",\n}\n'
        )
        _, wk = row(f"{base}/pay/exact", f"{base}/proxy/full", worker=decoy)
        report(
            "a decoy literal above cors() is not used as the baseline", "CURRENT" in wk
        )
    finally:
        _git_show = real_git_show
        # RESTORE THE URLS TOO. Leaving them pointed at a dead ephemeral port makes any real
        # probe in the same process silently read COULD NOT CHECK against localhost.
        PAY_URL, PROXY_URL = real_pay, real_proxy
        srv.shutdown()

    # The read-only guard, asserted rather than trusted: OPTIONS is the method the worker half
    # now uses, and a state-changing method must still be refused.
    try:
        fetch_once("http://127.0.0.1:1/x", "POST", False)
        report("fetch_once refuses POST", False)
    except ValueError:
        report("fetch_once refuses POST", True)
    except OSError:
        report("fetch_once refuses POST", False)
    report("OPTIONS is on the safe list", "OPTIONS" in SAFE_METHODS)
    report("POST is not on the safe list", "POST" not in SAFE_METHODS)

    # _git_show reads the RETURNCODE: a path that does not exist is unreadable-with-a-reason,
    # not empty-and-silent.
    blob, why = real_git_show("no/such/path/zz.txt")
    report("_git_show reports a missing path as unreadable", blob is None and bool(why))

    for f in failures:
        print(f"  FAIL  {f}")
    print(f"selftest: {cases - len(failures)}/{cases}")
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description="Pre-flight for the live demo.")
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="drive currency_report's branches against localhost and exit",
    )
    ap.add_argument(
        "--capture-dir",
        default=str(ROOT / "preflight-captures"),
        help="where the dated /price capture is written (gitignored by default)",
    )
    ap.add_argument(
        "--no-capture", action="store_true", help="probe /price but write no artifact"
    )
    args = ap.parse_args()

    if args.selftest:
        rc = selftest_currency()
        return rc | selftest_runbook_pins()

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
    # The runbook is gitignored, so no repo gate can see it. This is the only place that
    # both holds a live /price body and can read the operator's own pins, so it is where
    # they meet.
    results.append(runbook_pins_report(price))
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
    # Labelled "probes" because the currency block below is not in this sum. Calling it `total`
    # while more network work follows makes a partial measurement read as the whole run.
    print(f"{'total (probes)':<{width}}  {'':<14} {total:6.1f}s")

    # Advisory only, and defended so a bug in it can never change a go/no-go answer.
    try:
        currency_report()
    except Exception as exc:  # noqa: BLE001 - advisory must never gate the verdict
        print(f"\ncurrency: COULD NOT CHECK ({type(exc).__name__}: {exc})")

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
