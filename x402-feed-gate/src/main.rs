//! x402 feed gate — the earning-node server.
//!
//! Turns a ZeroClaw DePIN node into a machine that SELLS its own device-signed
//! on-chain feed. A client (agent or human) GETs `/reading`; if it presents no
//! valid payment it gets HTTP 402 with a price menu and a per-request nonce; it
//! pays us a stablecoin transfer on Solana, retries with a `PAYMENT-SIGNATURE`
//! header (v1's `X-PAYMENT` is still accepted)
//! carrying the signed transaction; we verify the bytes, simulate, broadcast,
//! confirm, and only then serve the latest feed reading plus a settlement
//! receipt. We hold no keys but our public receiving address — this process
//! cannot move funds, only recognise a payment made to us.
//!
//! Config via env:
//!   X402_SELLER_WALLET   base58 wallet that receives payment (required)
//!   X402_MINT            base58 stablecoin mint (required)
//!   X402_FEED_PDA        base58 feed account to read + serve (required)
//!   X402_RPC_URL         Solana RPC (default https://api.devnet.solana.com)
//!   X402_READ_RPC_URL    RPC used ONLY to read the feed account being sold
//!                        (default: X402_RPC_URL)
//!   X402_SETTLE_RPC_URL  RPC used ONLY to simulate/broadcast/confirm the buyer's
//!                        payment (default: X402_RPC_URL)
//!   X402_NETWORK         CAIP-2 network id (x402 v2 requires this form;
//!                        default solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1)
//!   X402_RESOURCE_URL    absolute URL of the resource sold, for v2's required
//!                        `resource` object (default http://localhost:$PORT/reading)
//!   X402_PORT            listen port (default 4577)
//!   X402_PRICE_SINGLE    atomic units for one reading (default 1000000 = 1 USDC)
//!   X402_PRICE_DAYPASS   atomic units for a day pass (default 5000000)
//!   X402_DAILY_CAP       per-payer atomic-unit daily cap (default 20000000)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use solana_core::rpc::RpcTransport;
use solana_core::{Commitment, Pubkey, RpcError, SolanaRpc};
use tiny_http::{Header, Response, Server};

use x402_feed_gate::{
    settlement_header, verify_x_payment, DailyLedger, EarningRecord, GateConfig, Reject,
    VerifiedPayment,
};

/// Native RPC transport: POST the JSON-RPC body to the configured endpoint over
/// HTTPS. The wasm plugins use `WakiTransport`; this host-side bin uses `ureq`.
struct UreqTransport {
    url: String,
}

impl RpcTransport for UreqTransport {
    fn post_json(&self, body: &str) -> Result<String, RpcError> {
        ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| RpcError::Transport(format!("ureq: {e}")))?
            .into_string()
            .map_err(|e| RpcError::Transport(format!("read body: {e}")))
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_pubkey(key: &str) -> Pubkey {
    let v = std::env::var(key).unwrap_or_else(|_| {
        eprintln!("missing required env {key} (base58 pubkey)");
        std::process::exit(2);
    });
    Pubkey::from_base58(&v).unwrap_or_else(|_| {
        eprintln!("{key} is not valid base58: {v}");
        std::process::exit(2);
    })
}

/// UTC day number (days since epoch) for the daily-cap boundary. Uses the
/// system clock; the accounting logic itself is tested with an injected day.
fn utc_day_now() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86_400) as i64
}

/// A monotonic, unguessable-enough nonce for a 402 challenge. Combines a
/// process-lifetime counter with the current nanosecond clock; single-use is
/// enforced by the ledger, so uniqueness (not cryptographic randomness) is what
/// matters here.
fn issue_nonce(counter: &AtomicU64) -> String {
    let n = counter.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("x402-{nanos:x}-{n:x}")
}

/// Read the latest reading from the feed account and render a small JSON body.
/// The feed layout matches the oracle program: sequence at offset 94 (u64 LE),
/// value at offset 73 (i64 LE). A read failure yields a soft error body rather
/// than withholding a paid response entirely.
fn feed_reading_json<T: RpcTransport>(rpc: &SolanaRpc<T>, feed: &Pubkey) -> String {
    match rpc.get_account_info(feed) {
        Ok(Some(acct)) if acct.data.len() >= 102 => {
            let seq = u64::from_le_bytes(acct.data[94..102].try_into().unwrap());
            let val = i64::from_le_bytes(acct.data[73..81].try_into().unwrap());
            serde_json::json!({
                "feed": feed.to_base58(),
                "sequence": seq,
                "value_scaled": val,
                "note": "device-signed on-chain reading; value is fixed-point per the feed's scale",
            })
            .to_string()
        }
        Ok(_) => serde_json::json!({
            "feed": feed.to_base58(),
            "error": "feed account not found or too small",
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "feed": feed.to_base58(),
            "error": format!("rpc read failed: {e:?}"),
        })
        .to_string(),
    }
}

/// One place that decides where the earnings ledger lives, so the writer and the
/// startup reader can never disagree about it. They did not disagree before; there
/// was simply no reader, and a second literal is how that starts.
fn earnings_log_path() -> String {
    std::env::var("X402_EARNINGS_LOG").unwrap_or_else(|_| "x402-earnings.jsonl".to_string())
}

/// Read settled sales back out of the earnings ledger for the daily-cap rebuild.
///
/// Tolerant by design: a missing file is a first run, and a malformed line is
/// skipped rather than fatal, because refusing to start over one bad line would
/// take the node offline to protect an accounting number. Skips are counted and
/// reported so a corrupt ledger is visible instead of silently shrinking the
/// restored spend.
fn load_earnings(path: &str) -> (Vec<EarningRecord>, usize) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return (Vec::new(), 0),
    };
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let parsed: Option<EarningRecord> = serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| {
                Some(EarningRecord {
                    day: v.get("day")?.as_i64()?,
                    payer: v.get("payer")?.as_str()?.to_string(),
                    amount: v.get("amount")?.as_u64()?,
                    nonce: v.get("nonce").and_then(|n| n.as_str()).map(str::to_string),
                })
            });
        match parsed {
            Some(r) => out.push(r),
            None => skipped += 1,
        }
    }
    (out, skipped)
}

/// Append a settled sale to the earnings ledger (JSON-lines). The ZeroClaw agent
/// reads this file in an SOP and reports the node's daily x402 revenue to the
/// owner's channel ("the node announces what it sold"), and since this change it is
/// also what the daily cap is rebuilt from at startup. Best-effort: any IO failure
/// is swallowed so it can never withhold a paid response.
///
/// That trade is worth naming now that the file has a second reader. A dropped write
/// loses one sale from both the revenue report and the restored cap, which is the
/// direction that favours the paying customer over our accounting. Withholding a
/// response the customer already paid for would be the worse failure.
fn record_earning(v: &VerifiedPayment, signature: &str, day: i64, nonce: &str) {
    use std::io::Write;
    let path = earnings_log_path();
    // `nonce` is the payment's memo, not a secret: it is already on chain in the
    // transaction this line settles. It is recorded so the daily ledger can restore
    // redeemed nonces across a restart, which it previously could not.
    let line = serde_json::json!({
        "day": day,
        "payer": v.payer.to_base58(),
        "amount": v.amount,
        "is_day_pass": v.is_day_pass,
        "settlement": signature,
        "nonce": nonce,
    })
    .to_string();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
}

fn json_response(status: u16, body: String) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(body).with_status_code(status);
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        resp.add_header(h);
    }
    resp
}

fn main() {
    let port = env_or("X402_PORT", "4577");
    let cfg = GateConfig {
        seller_wallet: env_pubkey("X402_SELLER_WALLET"),
        mint: env_pubkey("X402_MINT"),
        // CAIP-2, which x402 v2 requires. The v1 friendly form ("solana-devnet")
        // fails the reference validator's NetworkSchemaV2 while we declare v2.
        // Mainnet is solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp.
        network: env_or("X402_NETWORK", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
        // v2 requires a non-empty `resource.url`. Defaulted to the local bind so
        // a fresh clone serves a valid challenge with no configuration; a
        // deployment behind a proxy sets its public URL, which the gate cannot
        // discover for itself.
        resource_url: env_or(
            "X402_RESOURCE_URL",
            &format!("http://localhost:{port}/reading"),
        ),
        price_single: env_or("X402_PRICE_SINGLE", "1000000")
            .parse()
            .unwrap_or(1_000_000),
        price_day_pass: env_or("X402_PRICE_DAYPASS", "5000000")
            .parse()
            .unwrap_or(5_000_000),
        daily_cap: env_or("X402_DAILY_CAP", "20000000")
            .parse()
            .unwrap_or(20_000_000),
    };
    let feed = env_pubkey("X402_FEED_PDA");
    let rpc_url = env_or("X402_RPC_URL", "https://api.devnet.solana.com");
    // READING the feed and SETTLING the payment are separate concerns that were
    // forced through one client. They can legitimately live on different clusters:
    // the goods may be a devnet feed account while the money is real. Both default
    // to X402_RPC_URL, so an existing deployment that sets only that is unchanged.
    let read_rpc_url = env_or("X402_READ_RPC_URL", &rpc_url);
    let settle_rpc_url = env_or("X402_SETTLE_RPC_URL", &rpc_url);

    let read_rpc = SolanaRpc::new(UreqTransport {
        url: read_rpc_url.clone(),
    })
    .with_commitment(Commitment::Confirmed);
    let settle_rpc = SolanaRpc::new(UreqTransport {
        url: settle_rpc_url.clone(),
    })
    .with_commitment(Commitment::Confirmed);
    // Restore the daily ledger before serving anything. The unit is Restart=always,
    // so until this existed every restart handed each payer a fresh full allowance and
    // forgot every redeemed nonce. Nothing in the output would have shown that.
    let mut restored = DailyLedger::new();
    let (records, skipped) = load_earnings(&earnings_log_path());
    let applied = restored.rehydrate(records);
    eprintln!("  ledger: restored {applied} settled sale(s) from the earnings log");
    if skipped > 0 {
        eprintln!("  ledger: WARNING {skipped} unparseable line(s) skipped; restored spend is a lower bound");
    }
    let restore_stats = RestoreStats { applied, skipped };
    let ledger = Mutex::new(restored);
    let nonce_counter = AtomicU64::new(0);

    let addr = format!("127.0.0.1:{port}");
    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("failed to bind {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!("x402-feed-gate listening on http://{addr}");
    eprintln!("  selling feed {}", feed.to_base58());
    // Printed separately even when identical: an operator who has split them needs to
    // see WHICH cluster settles money, and an operator who has not needs to see that
    // nothing changed. A silent default is the shape that hides a misconfiguration.
    eprintln!("  read  RPC {read_rpc_url}");
    eprintln!("  settle RPC {settle_rpc_url}  <- real money moves here");
    eprintln!(
        "  receiving to ATA {} for mint {}",
        cfg.receiving_ata().to_base58(),
        cfg.mint.to_base58()
    );
    eprintln!("  GET /reading  |  GET /price  |  GET /health  |  GET /selfcheck");

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        // v2 renamed the client's payment header to PAYMENT-SIGNATURE; v1 called
        // it X-PAYMENT and the reference v2 server reads only the former. Both
        // are accepted so a spec-current client and every existing payer of this
        // gate work, with the v2 name preferred when a client sends both.
        let x_payment = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("PAYMENT-SIGNATURE"))
            .or_else(|| {
                request
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("X-Payment"))
            })
            .map(|h| h.value.as_str().to_string());

        let path = url.split('?').next().unwrap_or("/");
        let response_body: (u16, String, Option<String>) = match path {
            "/health" => handle_health(&ledger, &restore_stats, cfg.daily_cap),
            "/selfcheck" => handle_selfcheck(),
            "/price" => {
                let nonce = issue_nonce(&nonce_counter);
                (402, cfg.challenge(&nonce).to_json(), None)
            }
            "/reading" => handle_reading(
                &cfg,
                &read_rpc,
                &settle_rpc,
                &feed,
                &ledger,
                &nonce_counter,
                x_payment.as_deref(),
            ),
            _ => (404, r#"{"error":"not found"}"#.to_string(), None),
        };

        let (status, body, settle_hdr) = response_body;
        // v2's HTTP transport carries PaymentRequired in a base64 PAYMENT-REQUIRED
        // header and treats the body as an implementation concern; the reference
        // client reads only the header. Derived from the body that actually ships
        // rather than rebuilt, so the two cannot diverge (the reject path splices
        // a `rejected` key in, and the header must reflect that too).
        let payment_required_hdr = if status == 402 {
            Some(base64::engine::general_purpose::STANDARD.encode(&body))
        } else {
            None
        };
        let mut resp = json_response(status, body);
        if let Some(h) = payment_required_hdr {
            if let Ok(header) = Header::from_bytes(&b"PAYMENT-REQUIRED"[..], h.as_bytes()) {
                resp.add_header(header);
            }
        }
        if let Some(h) = settle_hdr {
            // PAYMENT-RESPONSE is the v2 name for the settlement receipt;
            // X-Payment-Response is v1's. Both are sent for the same reason the
            // request side accepts both names.
            if let Ok(header) = Header::from_bytes(&b"PAYMENT-RESPONSE"[..], h.as_bytes()) {
                resp.add_header(header);
            }
            if let Ok(header) = Header::from_bytes(&b"X-Payment-Response"[..], h.as_bytes()) {
                resp.add_header(header);
            }
        }
        let _ = request.respond(resp);
    }
}

/// Liveness for the node, not just for this process.
///
/// This used to return a hardcoded `{"ok":true}`, which could not fail and so
/// asserted nothing the TCP connection had not already proven.
///
/// The gap it now closes: the shop agent is a Telegram and WhatsApp CLIENT with
/// no inbound port, so nothing about it was observable from outside. Its trace
/// is entirely traffic-driven, with no heartbeat or periodic poll anywhere in
/// 200 sampled records, which means a QUIET shop and a DEAD shop produced an
/// identical signal. That ambiguity is what hid the 2026-07-26 outage. This gate
/// runs on the same box under the same `systemd --user` session, so it can
/// answer the question from the inside and make it one unauthenticated request.
///
/// NECESSARY, NOT SUFFICIENT, and the response says so itself rather than
/// leaving a reader to assume: it proves the unit is running and when the shop
/// last handled traffic. It does NOT prove the channel binding still works or
/// that the model provider is reachable. Only a synthetic round-trip proves
/// those, and that costs a model call and pollutes the agent's memory, which is
/// the measured cause of reply-extraction degrading.
///
/// It also separates two failures that were previously indistinguishable: no
/// answer at all means the box is down, while an answer reporting the shop
/// inactive means that process died specifically.
fn handle_health(
    ledger: &Mutex<DailyLedger>,
    restore: &RestoreStats,
    daily_cap: u64,
) -> (u16, String, Option<String>) {
    let unit = "zc-shop.service";

    // `is-active` exits non-zero for anything but active, so the status code is
    // the signal and stdout is only for the reason.
    let (active, state) = match std::process::Command::new("systemctl")
        .args(["--user", "is-active", unit])
        .output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            (
                o.status.success(),
                if s.is_empty() { "unknown".into() } else { s },
            )
        }
        // systemctl absent (a non-systemd host, or a dev box) is reported as
        // unknown rather than as a dead shop. Claiming an outage because the
        // instrument is missing is worse than reporting that it is missing.
        Err(_) => (false, "unavailable".to_string()),
    };

    // HOME rather than a literal path: the deployed copy must not carry an
    // operator username, and this response is public.
    let trace_age = std::env::var("HOME").ok().and_then(|h| {
        std::fs::metadata(format!("{h}/.zeroclaw/data/state/runtime-trace.jsonl"))
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
    });

    // Built with serde_json rather than format!, matching every other response
    // in this file. A hand-built body compiles fine while emitting broken JSON,
    // and the checker reading this endpoint would see a 200 either way.
    // A poisoned lock means some earlier request panicked while holding the
    // ledger. Reporting that is strictly better than the two alternatives:
    // panicking here would take the health endpoint down for a fault that does
    // not affect it, and silently recovering would hide a real incident behind
    // numbers that look normal. The data itself is still readable either way.
    let (lock_ok, guard) = match ledger.lock() {
        Ok(g) => (true, g),
        Err(poisoned) => (false, poisoned.into_inner()),
    };
    let ledger_json = serde_json::json!({
        "daily_cap_atomic_units": daily_cap,
        "restored_sales_at_startup": restore.applied,
        "unparseable_lines_skipped": restore.skipped,
        "redeemed_nonces": guard.redeemed_nonce_count(),
        "tracked_payer_days": guard.tracked_payer_days(),
        "settled_atomic_units": guard.total_settled(),
        "lock_healthy": lock_ok,
    });
    drop(guard);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let receipts = receipts_json(read_announce_log(), now, RECEIPT_FRESH_SECS);

    let body = serde_json::json!({
        "gate": "ok",
        "shop": {
            "unit": unit,
            "active": active,
            "state": state,
            "trace_age_seconds": trace_age,
        },
        "receipts": receipts,
        "ledger": ledger_json,
        "proves": "this gate answered, plus the shop unit's state and when it last \
                   handled traffic. The ledger block is the per-payer daily cap made \
                   externally checkable: a non-zero restored_sales_at_startup is this \
                   process having rebuilt spend and redeemed nonces from the earnings \
                   log rather than handing every payer a fresh allowance, which is what \
                   a Restart=always unit would otherwise do on every restart. Counts and \
                   sums only, never payers or nonces, because this endpoint is public. \
                   The receipts block reports the newest outcome the settlement \
                   announcer recorded: a `connected` delivery is positive evidence that \
                   the channel binding carried a real receipt to a real customer that \
                   recently, and it is the ONLY value here that is evidence of anything \
                   working. `failing` is the opposite evidence. `stale` and `unknown` \
                   are the absence of evidence and must never be read as health, but \
                   neither do they prove the channel binding is broken, because the \
                   announcer sends only when a payment settles and silence is what a \
                   shop that sold nothing looks like. Read records_found against \
                   lines_scanned before believing a zero: zero of zero means nothing \
                   was read, and zero of many means the window holds no delivery. It \
                   does not prove the model provider is reachable, and only a synthetic \
                   round-trip proves that. \
                   A restored count of zero is \
                   also the honest answer on a node that has genuinely sold nothing yet, \
                   so it is evidence of survival only once sales exist.",
    })
    .to_string();
    (200, body, None)
}

/// How old the newest delivered receipt may be and still be reported as `connected`.
///
/// TWENTY-FOUR HOURS, and what matters is the direction it errs in rather than the
/// number. The announcer sends only when a payment actually settles, so there is no
/// delivery to expect on a schedule and a tight window would paint a shop that sold
/// nothing overnight as broken. That is the same conflation of QUIET with DEAD that
/// hid the 2026-07-26 outage, pointed the other way, and a liveness line that cries
/// wolf stops being read at all.
///
/// A day is long enough that a quiet night cannot trip it, and short enough that a
/// send path broken days ago stops being quoted as evidence. Past it the verdict is
/// `stale`, never `disconnected`: an absence of receipts is not proof of a broken
/// channel, and claiming otherwise would be the same overreach in reverse.
const RECEIPT_FRESH_SECS: u64 = 86_400;

/// How far back to ask the journal for. Bounds both the read and the denominator,
/// and comfortably spans the freshness window above so a `stale` verdict is a real
/// observation rather than an artefact of how little was read.
const RECEIPT_WINDOW: &str = "-48h";

/// Cap on a file-sourced log, when `ZC_ANNOUNCE_LOG` points at one. This endpoint is
/// public and unauthenticated, so an unbounded read of a file that grows forever is a
/// denial-of-service lever pointed at ourselves.
const RECEIPT_LOG_TAIL_BYTES: u64 = 1_048_576;

/// The newest receipt-delivery outcome the announcer recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceiptOutcome {
    ok: bool,
    /// Epoch seconds, and only when the record carried an instant this parser could
    /// read. `None` means the delivery happened at a time we cannot establish, which
    /// is deliberately NOT the same as recently.
    at: Option<u64>,
    /// The channel the announcer named. Present on a failure, which says which
    /// channel refused; absent on a success, which does not name one.
    channel: Option<String>,
}

/// What the newest completed announcer run did.
#[derive(Clone, Debug, PartialEq, Eq)]
struct AnnounceRun {
    announced: u64,
    committed: bool,
}

/// The result of reading the announcer's own record of itself.
struct ReceiptScan {
    lines_scanned: usize,
    records_found: usize,
    newest: Option<ReceiptOutcome>,
    last_run: Option<AnnounceRun>,
}

/// Days since the epoch for a civil date. The inverse of `civil_from_days` above,
/// and the round trip between the two is asserted in the tests, because a calendar
/// routine that is wrong by a day is wrong quietly.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` to epoch seconds.
///
/// STRICT ON PURPOSE. Every separator is checked and the trailing `Z` is required,
/// so this accepts a UTC instant and nothing else. A lenient parser here would be
/// the one way a wrong number reaches `connected`, and a refusal costs only an
/// honest `unknown`.
fn parse_rfc3339_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last()? != b'Z'
    {
        return None;
    }
    // Anything between the seconds and the `Z` may only be a fractional part.
    if b.len() > 20 && b[19] != b'.' {
        return None;
    }
    let f = |r: std::ops::Range<usize>| s.get(r).and_then(|t| t.parse::<i64>().ok());
    let (y, mo, d) = (f(0..4)?, f(5..7)?, f(8..10)?);
    let (h, mi, se) = (f(11..13)?, f(14..16)?, f(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let secs = days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3_600 + mi * 60 + se;
    u64::try_from(secs).ok()
}

/// Is this the shape of a channel ref (`<type>` or `<type>.<alias>`)?
///
/// Prose does not match, so a channel name lifted out of an error line has to look
/// like a channel before it is reported as one.
fn is_channel_ref(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    let mut dots = 0;
    for c in s.chars() {
        match c {
            'a'..='z' | '0'..='9' | '_' | '-' => {}
            '.' => {
                dots += 1;
                if dots > 1 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

/// The first token on the line that is a UTC instant.
///
/// Positional parsing would break the first time the announcer reworded a sentence,
/// and the message text is not an interface. Scanning for the token is stable across
/// any rewording that keeps the instant.
fn instant_in(line: &str) -> Option<u64> {
    line.split_whitespace()
        .map(|t| t.trim_matches(|c| matches!(c, '(' | ')' | ',' | ';' | '.')))
        .find_map(parse_rfc3339_utc)
}

/// Read the announcer's own record of what it delivered.
///
/// THE JOURNAL IS THE HONEST SOURCE and this reads it directly. `zc-announce.service`
/// sets `StandardOutput=journal`, so its lines exist nowhere else: a file-based reader
/// pointed at the shop daemon's log would scan forever and never see a receipt,
/// because the announcer is a separate process whose stdout never lands there.
///
/// `--user` because the gate runs under the same `systemd --user` session as the unit
/// it is asking about. `-o cat` because the message text is what carries the outcome
/// and a syslog prefix is noise. `--since` bounds the read.
///
/// `ZC_ANNOUNCE_LOG` overrides the whole thing with a file, which is what makes this
/// testable and what leaves a route open if the unit is ever changed to log to one.
fn read_announce_log() -> Result<(String, &'static str), String> {
    use std::io::{Read, Seek, SeekFrom};

    if let Ok(p) = std::env::var("ZC_ANNOUNCE_LOG") {
        if !p.trim().is_empty() {
            // The error strings carry no path: std's fs errors do not append one, and
            // the path may hold $HOME, which would put a username in a public body.
            let meta =
                std::fs::metadata(&p).map_err(|e| format!("announce log unreadable: {e}"))?;
            let start = meta.len().saturating_sub(RECEIPT_LOG_TAIL_BYTES);
            let mut f =
                std::fs::File::open(&p).map_err(|e| format!("announce log unreadable: {e}"))?;
            if start > 0 {
                f.seek(SeekFrom::Start(start))
                    .map_err(|e| format!("announce log unreadable: {e}"))?;
            }
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)
                .map_err(|e| format!("announce log unreadable: {e}"))?;
            let text = String::from_utf8_lossy(&buf).into_owned();
            // A seek lands mid-line, and half a line is not a record.
            let text = if start > 0 {
                text.split_once('\n')
                    .map(|(_, rest)| rest.to_string())
                    .unwrap_or_default()
            } else {
                text
            };
            return Ok((text, "zc-announce log file"));
        }
    }

    let out = std::process::Command::new("journalctl")
        .args([
            "--user",
            "-u",
            "zc-announce.service",
            "--since",
            RECEIPT_WINDOW,
            "--no-pager",
            "-o",
            "cat",
        ])
        .output()
        // journalctl absent, or no user journal, is reported as unknown rather than
        // as a broken channel, on the same reasoning a missing `systemctl` is.
        .map_err(|e| format!("journalctl unavailable: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "journalctl exited {}",
            out.status.code().unwrap_or(-1)
        ));
    }
    Ok((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        "zc-announce journal",
    ))
}

/// Recover the newest receipt-delivery outcome from the announcer's output.
///
/// WHAT THESE LINES ARE. The announcer prints one outcome per receipt and one
/// summary per run:
///
///   sent: payment received: 0.39 USDC from <payer> at <instant> (signature <sig>)
///   SEND FAILED, will retry next run: payment received: ... (signature ...)
///   Error: Failed to send message via <channel>
///   announced 5, ledger committed
///   announced 0 of 5; ledger NOT committed so the rest re-announce
///
/// This is a stronger signal than the channel-liveness proxy it replaces, because it
/// is the thing anyone actually cares about: a receipt reaching a customer. It is
/// also produced by a shell script that never consults a model.
///
/// MATCHED BY DISTINCTIVE SUBSTRING rather than by position, so a reworded sentence
/// or a log format that adds a prefix does not silently stop matching.
///
/// THE INSTANT IS THE PAYMENT'S, NOT THE SEND'S, and that is sound in the direction
/// that matters. A payment is received before its receipt goes out, so an age derived
/// from it is an OVER-estimate of how long ago the send happened. Over-estimating age
/// can only move a verdict toward `stale`, never toward a false `connected`.
///
/// LAST OCCURRENCE WINS, because the journal is append-only, so file order is time
/// order and the last outcome is the newest.
fn scan_receipt_records(log: &str) -> ReceiptScan {
    let mut scan = ReceiptScan {
        lines_scanned: 0,
        records_found: 0,
        newest: None,
        last_run: None,
    };
    for raw in log.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        scan.lines_scanned += 1;

        if line.contains("sent: payment received:") {
            scan.records_found += 1;
            scan.newest = Some(ReceiptOutcome {
                ok: true,
                at: instant_in(line),
                channel: None,
            });
            continue;
        }
        if line.contains("SEND FAILED") {
            scan.records_found += 1;
            scan.newest = Some(ReceiptOutcome {
                ok: false,
                at: instant_in(line),
                channel: None,
            });
            continue;
        }
        // The channel is named only by the error that follows a failure, so it is
        // attached to the outcome already in hand rather than treated as its own
        // record. A success does not name a channel and none is invented for it.
        if let Some(rest) = line.split_once("Failed to send message via ") {
            let named = rest.1.trim().trim_end_matches('.');
            if is_channel_ref(named) {
                if let Some(o) = scan.newest.as_mut() {
                    if !o.ok && o.channel.is_none() {
                        o.channel = Some(named.to_string());
                    }
                }
            }
            continue;
        }
        if let Some(rest) = line.split_once("announced ") {
            let n = rest
                .1
                .split(|c: char| !c.is_ascii_digit())
                .find(|t| !t.is_empty())
                .and_then(|t| t.parse::<u64>().ok());
            if let Some(announced) = n {
                if line.contains("ledger NOT committed") {
                    scan.last_run = Some(AnnounceRun {
                        announced,
                        committed: false,
                    });
                } else if line.contains("ledger committed") {
                    scan.last_run = Some(AnnounceRun {
                        announced,
                        committed: true,
                    });
                }
            }
        }
    }
    scan
}

/// Turn the newest outcome into the reported verdict.
///
/// FOUR STATES, and only one of them is good news.
///   `connected` a dated delivery inside the freshness window. Positive evidence.
///   `failing`   the newest attempt failed. Positive evidence, the bad kind.
///   `stale`     a delivery we can show is older than the window.
///   `unknown`   no record, or a delivery we cannot date, so we decline to call it
///               recent.
fn receipt_verdict(o: Option<&ReceiptOutcome>, now: u64, stale_after: u64) -> serde_json::Value {
    let Some(o) = o else {
        return serde_json::json!({
            "status": "unknown",
            "last_success_age_seconds": null,
            "last_attempt_age_seconds": null,
            "age_basis": "none",
            "channel": null,
            "detail": "no delivery outcome was found in the window read. A shop that \
                       sold nothing looks exactly like this, so it is not evidence of \
                       a fault",
        });
    };

    // TWO AGES, AND THE NAMES ARE LOAD-BEARING. `last_attempt_age_seconds` is how long
    // ago the newest attempt happened whatever came of it; `last_success_age_seconds` is
    // populated ONLY when that attempt delivered. Reporting a failure's age under the
    // success name would tell a consumer a receipt got through when none ever did, which
    // is the exact class of lie this endpoint exists to avoid, so a failure keeps a null
    // success age and carries its age in its own field.
    //
    // BOTH ARE DERIVED FROM THE PAYMENT'S SETTLEMENT INSTANT, which precedes the attempt,
    // so both OVER-estimate. On the success path that can only move a verdict toward
    // `stale`; on the failure path it can only make an outage look older than it is,
    // never fresher, so neither direction manufactures reassurance.
    let attempt_age = o.at.map(|at| now.saturating_sub(at));
    let basis = if attempt_age.is_some() {
        "settlement_instant"
    } else {
        "none"
    };

    if !o.ok {
        return serde_json::json!({
            "status": "failing",
            "last_success_age_seconds": null,
            "last_attempt_age_seconds": attempt_age,
            "age_basis": basis,
            "channel": o.channel,
            "detail": "the newest delivery attempt failed and the receipt has not \
                       reached the customer. Read last_attempt_age_seconds: a refusal \
                       minutes old is a transient the next tick may clear, and one \
                       weeks old is an outage nobody noticed",
        });
    }
    match attempt_age {
        Some(age) => {
            let fresh = age <= stale_after;
            serde_json::json!({
                "status": if fresh { "connected" } else { "stale" },
                "last_success_age_seconds": age,
                "last_attempt_age_seconds": age,
                "age_basis": basis,
                "channel": o.channel,
                "detail": if fresh {
                    "a receipt was delivered for a payment that settled within the \
                     freshness window"
                } else {
                    "the newest delivered receipt is older than the freshness window, \
                     which is what a quiet shop and a broken send path look like alike"
                },
            })
        }
        None => serde_json::json!({
            "status": "unknown",
            "last_success_age_seconds": null,
            "last_attempt_age_seconds": null,
            "age_basis": basis,
            "channel": o.channel,
            "detail": "a delivery is recorded but carries no readable instant, so it \
                       cannot be shown to be recent and is not counted as evidence",
        }),
    }
}

/// The `receipts` block.
///
/// Takes its input rather than reading the world, so both directions are drivable
/// from a test: a fresh delivery must report `connected`, and everything else must
/// not.
fn receipts_json(
    loaded: Result<(String, &'static str), String>,
    now: u64,
    stale_after: u64,
) -> serde_json::Value {
    let (text, source) = match loaded {
        Ok(v) => v,
        // An unreadable source is reported as unknown rather than as a broken send
        // path, for the same reason a missing `systemctl` is: claiming an outage
        // because the instrument is missing is worse than reporting it is missing.
        Err(reason) => {
            return serde_json::json!({
                "source": "unavailable",
                "log_readable": false,
                "lines_scanned": 0,
                "records_found": 0,
                "stale_after_seconds": stale_after,
                "delivery": receipt_verdict(None, now, stale_after),
                "last_run": null,
                "detail": reason,
            });
        }
    };

    let scan = scan_receipt_records(&text);
    let last_run = scan
        .last_run
        .as_ref()
        .map(|r| serde_json::json!({ "announced": r.announced, "ledger_committed": r.committed }));

    serde_json::json!({
        "source": source,
        "log_readable": true,
        "lines_scanned": scan.lines_scanned,
        "records_found": scan.records_found,
        "stale_after_seconds": stale_after,
        "delivery": receipt_verdict(scan.newest.as_ref(), now, stale_after),
        "last_run": last_run,
        "detail": "the newest receipt-delivery outcome the announcer recorded. Only \
                   `connected` is evidence the send path works; read records_found \
                   against lines_scanned before believing an empty result.",
    })
}

/// What the startup rebuild found, kept so `/health` can report it.
///
/// These are startup facts rather than live ones, so they are captured once and
/// never recomputed. `skipped` travels with `applied` deliberately: a restored
/// total built from a log with unreadable lines is a LOWER BOUND on real spend,
/// and a reader who sees only the applied count would take it as exact.
struct RestoreStats {
    applied: usize,
    skipped: usize,
}

/// Publishes the box self-check verdict so a checker anywhere can read it.
///
/// `deploy/box_selfcheck.py` runs ON the box and writes a verdict JSON, because
/// the box cannot be reached inbound cheaply: port 22 is blocked network-wide
/// from the operator's location, and Run Command is absent from the node's live
/// plugin list. The verdict therefore has to travel outward, and this gate
/// already runs a Cloudflare tunnel, so it is the door. Until this route existed
/// the verdict was computed and then stayed on the disk that produced it.
///
/// This handler only publishes. It does not run the check, judge it, or
/// summarise it: the verdict object is served as written, with two server-added
/// fields, so a change to what the checker asserts needs no change here.
fn handle_selfcheck() -> (u16, String, Option<String>) {
    let zeroclaw_home = std::env::var("ZEROCLAW_HOME").ok();
    let home = std::env::var("HOME").ok();
    let path = match resolve_verdict_path(zeroclaw_home.as_deref(), home.as_deref()) {
        Ok(p) => p,
        Err(reason) => return selfcheck_unavailable(&reason),
    };

    // mtime first, then the bytes. Reading the file and then failing to stat it
    // would leave the age unknown on a verdict that is present, and an age that
    // silently defaulted would be indistinguishable from a fresh one.
    let loaded = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .and_then(|mtime| std::fs::read(&path).map(|bytes| (bytes, mtime)))
        // The io error's own text is short and carries no path (std's fs errors
        // do not append one), which matters because this detail ships in a
        // public body and the path holds $HOME.
        .map_err(|e| format!("verdict unreadable: {e}"));

    render_selfcheck(loaded, SystemTime::now())
}

/// Where the verdict lives, resolved the way `deploy/box_selfcheck.py` resolves
/// it: `ZEROCLAW_HOME` if set, else `$HOME/.zeroclaw`, then
/// `state/box-selfcheck.json` under that.
///
/// THE TWO MUST BE CHANGED TOGETHER. `box_selfcheck.py` takes its root from
/// `os.environ.get("ZEROCLAW_HOME", Path.home() / ".zeroclaw")`; if this
/// disagrees, a box running with the override writes a verdict where this route
/// does not look, and a present verdict is then served as 503. That is worse
/// than a plain miss, because 503 here means "no verdict was produced", so a
/// reader applies the remedy for a checker that is not running while the
/// checker is running fine.
///
/// Env is read by the caller and passed in, so both branches are testable
/// without mutating process-global state from a threaded test harness.
///
/// HOME rather than a literal path, for the same reason `/health` reads it that
/// way: the deployed copy must not carry an operator username, and this
/// response is public.
fn resolve_verdict_path(zeroclaw_home: Option<&str>, home: Option<&str>) -> Result<String, String> {
    // Set-but-EMPTY is the case that `.ok()` alone does not cover: `std::env::var`
    // returns `Ok("")` for `ZEROCLAW_HOME=` in a unit file, which is a shape a
    // shell produces by accident rather than on purpose.
    //
    // This is the ONE point where mirroring Python exactly would be wrong, so it
    // is deliberate rather than an oversight: `os.environ.get` also returns `""`
    // there, and `Path("") / "state"` is the RELATIVE path `state/...`, while the
    // naive Rust equivalent is `/state/...` at the filesystem root. Both are
    // useless, neither is what an operator meant, and only one of them can be
    // reached by a reader who then wonders why the root of the disk is being
    // stat'd. Falling back to `$HOME/.zeroclaw` is the reading that can be right.
    let root = match zeroclaw_home.filter(|v| !v.is_empty()) {
        Some(explicit) => explicit.to_string(),
        None => match home.filter(|v| !v.is_empty()) {
            Some(h) => format!("{h}/.zeroclaw"),
            None => {
                return Err(
                    "neither ZEROCLAW_HOME nor HOME is set, so the verdict path is unknown"
                        .to_string(),
                )
            }
        },
    };
    Ok(format!("{root}/state/box-selfcheck.json"))
}

/// The pure half of `/selfcheck`: verdict bytes and their mtime in, status and
/// body out. Split out so all three branches are drivable without a filesystem,
/// and so the age arithmetic can be tested against a clock the test controls.
fn render_selfcheck(
    verdict: Result<(Vec<u8>, SystemTime), String>,
    now: SystemTime,
) -> (u16, String, Option<String>) {
    let (bytes, mtime) = match verdict {
        Ok(v) => v,
        Err(reason) => return selfcheck_unavailable(&reason),
    };

    let mut parsed: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => return selfcheck_unavailable(&format!("verdict is not valid JSON: {e}")),
    };

    // Built with serde_json rather than format!, matching every other response
    // in this file: a hand-built body compiles fine while emitting broken JSON,
    // and the checker reading this endpoint would see a 200 either way. Here it
    // also does the merge, which string concatenation cannot do safely at all.
    match parsed.as_object_mut() {
        Some(obj) => {
            // The age comes from the FILE'S MTIME, never from the verdict's own
            // `generated_at`. That field is written by the same process that
            // writes the file, so it cannot see a run that died before writing,
            // and it travels with the bytes if the file is copied from
            // somewhere else. The mtime is the independent signal.
            //
            // A future mtime (a clock step, a copy that preserved a newer
            // stamp) saturates at zero rather than failing the request: the
            // verdict is present, and reporting it as missing would be a
            // sharper error than reporting it as very fresh.
            let age = now
                .duration_since(mtime)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            obj.insert("age_seconds".to_string(), serde_json::json!(age));
            obj.insert("served_at".to_string(), serde_json::json!(rfc3339_utc(now)));
        }
        // A bare scalar or an array parses as JSON and still cannot receive the
        // two fields. Serving it unmerged would hand the fetcher a 200 with no
        // age, which is the one thing a staleness check needs.
        None => return selfcheck_unavailable("verdict is not a JSON object"),
    }

    (200, parsed.to_string(), None)
}

/// No verdict is a 503 with a reason, never a 200 with a partial body.
///
/// This endpoint exists so a fetcher can tell "the box asserted its invariants"
/// from "the box said nothing", and those two must not share a status code. A
/// missing verdict readable as a pass is worse than no endpoint, because the
/// green then gets quoted as evidence — which is the same reasoning that makes
/// the checker itself fail closed.
fn selfcheck_unavailable(detail: &str) -> (u16, String, Option<String>) {
    let body = serde_json::json!({
        "error": "no verdict",
        "detail": detail,
    })
    .to_string();
    (503, body, None)
}

/// Epoch time to `YYYY-MM-DDTHH:MM:SSZ`.
///
/// The same shape the verdict writer emits for its own `generated_at`
/// (`time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())`), so the two timestamps
/// in one response can be compared without either side parsing two formats.
///
/// Hand-rolled because this crate carries no date dependency and one timestamp
/// does not justify the supply-chain surface of adding one. The days-to-civil
/// step is Hinnant's algorithm, which is exact across leap years and century
/// rules rather than an approximation that drifts near either.
fn rfc3339_utc(t: SystemTime) -> String {
    // Before the epoch is not a real case for a file this process just stat'd,
    // and clamping keeps the signature infallible rather than pushing an error
    // no caller could act on into the response.
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since 1970-01-01 to a proleptic Gregorian (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap day lands at the end of the cycle
    // and no month arithmetic has to special-case February.
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The core request handler: no payment -> 402 challenge; a payment -> verify,
/// enforce the cap, simulate, broadcast, confirm, serve the reading.
fn handle_reading<T: RpcTransport, S: RpcTransport>(
    cfg: &GateConfig,
    read_rpc: &SolanaRpc<T>,
    settle_rpc: &SolanaRpc<S>,
    feed: &Pubkey,
    ledger: &Mutex<DailyLedger>,
    nonce_counter: &AtomicU64,
    x_payment: Option<&str>,
) -> (u16, String, Option<String>) {
    let Some(header) = x_payment else {
        // No payment presented: issue a fresh challenge.
        let nonce = issue_nonce(nonce_counter);
        return (402, cfg.challenge(&nonce).to_json(), None);
    };

    // The client echoes the nonce it was challenged with inside the memo; we
    // recover it from the payment itself by trying the memo against our issued
    // set. To keep the gate stateless-per-request while still binding the
    // payment, we accept ANY memo the payment carries as the nonce and enforce
    // single-use in the ledger — so a replay of the same signed tx is refused,
    // and a tx with no memo is refused by verify's MissingMemo path.
    let nonce = match extract_memo_nonce(header) {
        Some(n) => n,
        None => {
            let fresh = issue_nonce(nonce_counter);
            return (402, cfg.challenge(&fresh).to_json(), None);
        }
    };

    let verified = match verify_x_payment(cfg, header, &nonce) {
        Ok(v) => v,
        Err(reject) => return reject_to_response(cfg, nonce_counter, reject),
    };

    // Enforce single-use nonce + daily cap BEFORE broadcasting.
    let day = utc_day_now();
    {
        let mut l = ledger.lock().unwrap();
        if let Err(reject) = l.commit(&verified.payer, &nonce, day, verified.amount, cfg.daily_cap)
        {
            return reject_to_response(cfg, nonce_counter, reject);
        }
    }

    // Simulate, then broadcast, then confirm.
    match settle(settle_rpc, &verified) {
        Ok(signature) => {
            // Append to the earnings ledger (JSON-lines) so the ZeroClaw agent can
            // report "sold N readings, earned X" to the owner's channel. Best-effort:
            // a log-write failure never withholds a paid response.
            record_earning(&verified, &signature, day, &nonce);
            let body = serde_json::json!({
                "paid": true,
                "amount": verified.amount,
                "settlement": signature,
                "reading": serde_json::from_str::<serde_json::Value>(&feed_reading_json(read_rpc, feed))
                    .unwrap_or(serde_json::Value::Null),
            })
            .to_string();
            let hdr = settlement_header(&signature, &cfg.network, &verified.payer);
            (200, body, Some(hdr))
        }
        Err(e) => {
            // Settlement failed after the cap was recorded; the nonce is spent
            // (correct — the same signed tx must not be retried). Report 502.
            (
                502,
                serde_json::json!({ "paid": false, "error": e }).to_string(),
                None,
            )
        }
    }
}

/// Simulate then broadcast then confirm the client's payment transaction.
fn settle<T: RpcTransport>(rpc: &SolanaRpc<T>, v: &VerifiedPayment) -> Result<String, String> {
    if let Ok(Some(sim_err)) = rpc.simulate_transaction(&v.raw_tx) {
        return Err(format!("simulation failed: {sim_err}"));
    }
    let sig = rpc
        .send_transaction(&v.raw_tx)
        .map_err(|e| format!("send failed: {e:?}"))?;
    // Poll to at least `confirmed`.
    for _ in 0..30 {
        if let Ok(Some(status)) = rpc.get_signature_status(&sig) {
            if let Some(err) = &status.err {
                return Err(format!("transaction failed on-chain: {err}"));
            }
            if status.is_settled() {
                return Ok(sig);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    Err("payment did not confirm within timeout".into())
}

/// Recover the memo string from an X-PAYMENT header by decoding the transaction
/// and reading the first Memo-program instruction's data. Used to bind the
/// payment to its own nonce for single-use enforcement.
fn extract_memo_nonce(header: &str) -> Option<String> {
    let json_bytes = base64::engine::general_purpose::STANDARD
        .decode(header.trim())
        .ok()?;
    let env: serde_json::Value = serde_json::from_slice(&json_bytes).ok()?;
    let tx_b64 = env.get("payload")?.get("transaction")?.as_str()?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(tx_b64.trim())
        .ok()?;
    let decoded = solana_core::decode_transaction(&raw).ok()?;
    let memo_prog = solana_core::pubkey::memo_program();
    for ix in &decoded.message.instructions {
        if decoded.program_id_of(ix) == Some(&memo_prog) {
            return std::str::from_utf8(&ix.data).ok().map(str::to_string);
        }
    }
    None
}

fn reject_to_response(
    cfg: &GateConfig,
    nonce_counter: &AtomicU64,
    reject: Reject,
) -> (u16, String, Option<String>) {
    // A cap/nonce/payment rejection returns 402 with a fresh challenge and the
    // specific reason, so an honest client can adjust and retry.
    let nonce = issue_nonce(nonce_counter);
    let mut body = cfg.challenge(&nonce).to_json();
    // Splice the reason in for observability.
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&body) {
        v["rejected"] = serde_json::json!(format!("{reject:?}"));
        body = v.to_string();
    }
    (402, body, None)
}

#[cfg(test)]
mod health_tests {
    use super::*;

    const TEST_CAP: u64 = 20_000_000;

    /// A payer address and a nonce that are distinctive enough that finding
    /// either one in the response body is unambiguous. Real base58 payers and
    /// real nonces both appear in the ledger's keys, so the leak test needs a
    /// value that cannot occur by chance in surrounding prose.
    const FIXTURE_PAYER: &str = "PayerLeakCanary11111111111111111111111111111";
    const FIXTURE_NONCE: &str = "nonce-leak-canary-8f3a";

    /// Drive `/health` against a ledger built from `records`, as the running
    /// gate does after a restart.
    fn health_with(records: Vec<EarningRecord>, skipped: usize) -> (u16, String, Option<String>) {
        let mut l = DailyLedger::new();
        let applied = l.rehydrate(records);
        handle_health(&Mutex::new(l), &RestoreStats { applied, skipped }, TEST_CAP)
    }

    /// The state a node in is before it has ever sold anything.
    fn health_empty() -> (u16, String, Option<String>) {
        health_with(vec![], 0)
    }

    /// Two settled sales from one payer on one day, plus one from another day.
    fn restored_records() -> Vec<EarningRecord> {
        vec![
            EarningRecord {
                day: 20_300,
                payer: FIXTURE_PAYER.to_string(),
                amount: 1_500_000,
                nonce: Some(FIXTURE_NONCE.to_string()),
            },
            EarningRecord {
                day: 20_300,
                payer: FIXTURE_PAYER.to_string(),
                amount: 500_000,
                nonce: Some(format!("{FIXTURE_NONCE}-b")),
            },
            EarningRecord {
                day: 20_301,
                payer: FIXTURE_PAYER.to_string(),
                amount: 250_000,
                nonce: None,
            },
        ]
    }

    /// The route this replaced returned a hardcoded `{"ok":true}` that could not
    /// fail, so it asserted nothing. These assert the replacement actually says
    /// something, and that it stays parseable: the body is built by `format!`
    /// over a `concat!`, which compiles happily while emitting broken JSON.
    #[test]
    fn health_body_is_valid_json_with_the_fields_a_checker_reads() {
        let (status, body, hdr) = health_empty();
        assert_eq!(status, 200);
        assert!(hdr.is_none());

        // Balanced braces and quotes: the cheapest structural check that does
        // not pull a JSON dependency into a crate that has none.
        // A real parse, not a brace count. The body is machine-read by the
        // scheduled checker, so "looks structurally plausible" is not the bar.
        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("invalid JSON ({e}): {body}"));
        assert_eq!(v["gate"], "ok");
        assert!(v["shop"]["unit"].is_string());
        assert!(v["shop"]["active"].is_boolean());
        assert!(v["shop"]["state"].is_string());
        // null when the trace is unreadable, a number when it is not. Never a
        // string, because a checker comparing it against a threshold would then
        // silently compare against text.
        let age = &v["shop"]["trace_age_seconds"];
        assert!(
            age.is_u64() || age.is_null(),
            "trace age must be numeric or null: {age}"
        );

        assert!(v["proves"].is_string(), "the limit clause must be present");
    }

    /// The honesty clause is load-bearing rather than decorative. Without it a
    /// reader takes a 200 as proof the shop can serve an order, which this
    /// endpoint cannot know: it sees the unit and the trace, not the channel
    /// binding or the model provider.
    #[test]
    fn health_states_its_own_limit() {
        let (_, body, _) = health_empty();
        // Case-insensitive on purpose: the clause is prose and its first word
        // capitalises or not depending on where a sentence break lands. Pinning
        // the case makes the test fail on a rewording that changed nothing.
        let lower = body.to_lowercase();
        assert!(
            lower.contains("does not prove"),
            "limit clause missing: {body}"
        );
        assert!(
            lower.contains("channel binding"),
            "limit is not specific: {body}"
        );
        assert!(
            lower.contains("model provider"),
            "limit is not specific: {body}"
        );
        // Added with the channels block. The block makes a partial claim about the
        // channel binding, so the honesty clause has to say which value is
        // evidence and which are merely the absence of it. Without this a reader
        // takes any channels block at all as a green light.
        assert!(
            lower.contains("absence of evidence"),
            "the channels clause must say what a non-connected value is NOT: {body}"
        );
        assert!(
            lower.contains("connected"),
            "the channels clause must name the only value that is evidence: {body}"
        );
    }

    /// A missing `systemctl` must read as unknown, never as a dead shop. On a
    /// dev box or a non-systemd host this path is the normal one, and reporting
    /// an outage because the instrument is absent is worse than reporting the
    /// instrument is absent.
    #[test]
    fn absent_instrument_is_not_reported_as_an_outage() {
        let (_, body, _) = health_empty();
        if body.contains("\"state\":\"unavailable\"") {
            assert!(body.contains("\"active\":false"));
            assert!(
                !body.contains("\"gate\":\"down\""),
                "a missing instrument must not be reported as the gate failing"
            );
        }
    }

    /// The reason this endpoint grew a ledger block. The restart-survival
    /// property was asserted in the write-up and observable only by the operator
    /// reading a startup line, so a reader had to take it on trust.
    ///
    /// Both directions, because one alone proves nothing. A ledger rebuilt from
    /// three settled sales must SAY three and must report the spend those sales
    /// imply, and a genuinely empty node must say zero rather than inheriting a
    /// number from anywhere. Without the empty case a hardcoded three would pass.
    #[test]
    fn the_ledger_block_reports_what_a_restart_actually_restored() {
        let (_, restored, _) = health_with(restored_records(), 2);
        let v: serde_json::Value = serde_json::from_str(&restored).unwrap();
        let l = &v["ledger"];
        assert_eq!(l["restored_sales_at_startup"], 3);
        assert_eq!(l["unparseable_lines_skipped"], 2);
        // Two nonces, because the third record carries none: a line written
        // before the gate recorded nonces restores its spend but cannot restore
        // its single-use marker, and the count must show that rather than round up.
        assert_eq!(l["redeemed_nonces"], 2);
        // Two payer-days: the same payer on two different UTC days.
        assert_eq!(l["tracked_payer_days"], 2);
        assert_eq!(l["settled_atomic_units"], 2_250_000);
        assert_eq!(l["daily_cap_atomic_units"], TEST_CAP);
        assert_eq!(l["lock_healthy"], true);

        let (_, empty, _) = health_empty();
        let e: serde_json::Value = serde_json::from_str(&empty).unwrap();
        assert_eq!(e["ledger"]["restored_sales_at_startup"], 0);
        assert_eq!(e["ledger"]["redeemed_nonces"], 0);
        assert_eq!(e["ledger"]["settled_atomic_units"], 0);
    }

    /// This endpoint is public and unauthenticated, and the ledger it now reads
    /// from is keyed by payer address and by nonce. Publishing either would let
    /// anyone enumerate who buys from this node, and publishing the nonces would
    /// hand an attacker the exact strings the single-use guard is keyed on.
    ///
    /// The fixture values are canaries chosen so a hit cannot be coincidence.
    /// The accessors are written so that the leak is not merely absent but
    /// unavailable, and this test is what stops a future field from reaching
    /// past them.
    #[test]
    fn no_payer_address_or_nonce_reaches_the_public_body() {
        let (_, body, _) = health_with(restored_records(), 0);
        assert!(
            !body.contains(FIXTURE_PAYER),
            "a payer address reached the public health body: {body}"
        );
        assert!(
            !body.contains(FIXTURE_NONCE),
            "a nonce reached the public health body: {body}"
        );
        // The control: the body really was built from that ledger, so the two
        // assertions above are about redaction rather than about an empty
        // ledger that never held the canaries in the first place.
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["ledger"]["restored_sales_at_startup"], 3);
    }

    /// A poisoned ledger must degrade rather than take the endpoint down. The
    /// health route is what a checker uses to tell "the box is gone" from "one
    /// component died", and panicking here would collapse that distinction at
    /// exactly the moment it matters.
    #[test]
    fn a_poisoned_ledger_is_reported_rather_than_panicking() {
        let ledger = Mutex::new(DailyLedger::new());
        let _ = std::panic::catch_unwind(|| {
            let _g = ledger.lock().unwrap();
            panic!("poison the ledger");
        });
        assert!(ledger.is_poisoned(), "fixture failed to poison the lock");

        let (status, body, _) = handle_health(
            &ledger,
            &RestoreStats {
                applied: 0,
                skipped: 0,
            },
            TEST_CAP,
        );
        assert_eq!(status, 200, "health must still answer");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["ledger"]["lock_healthy"], false,
            "a poisoned lock must be reported, not hidden behind normal-looking numbers"
        );
    }

    // ---- receipts block ---------------------------------------------------
    //
    // Driven through `receipts_json` rather than through `handle_health`, so no case
    // depends on an env var or on journalctl existing. Two tests that set
    // `ZC_ANNOUNCE_LOG` would race each other, because cargo runs them as threads in
    // one process, and the flake would read as a broken parser.
    //
    // The fixtures are the announcer's REAL lines, captured from a receipt run that
    // succeeded, rather than a shape invented to match the parser. A suite built from
    // an imagined format proves only that the parser agrees with the imagination.

    const NOW: u64 = 1_786_000_000;
    const DAY: u64 = 86_400;

    /// The instant embedded in the real success line, and its epoch value.
    const SETTLED_AT: &str = "2026-08-17T05:32:17Z";
    const SETTLED_EPOCH: u64 = 1_786_944_737;

    const SIG: &str =
        "2tR8YbFHDk99H2PkPLTKfhDL8WKFxfhR61vNRpsANRoQwyuBUZTAKPHoyDFPz6K42ZXRk26tMqB1c154J8qqbbMj";

    /// A run whose receipts all landed. Verbatim shapes from the journal.
    fn sent_run(at: &str) -> String {
        format!(
            "sent: payment received: 0.39 USDC from \
             D7o5YEE6ZTnQPRd2nbdoK1rRP83mLLoapoBWgkSJFUHL at {at} (signature {SIG})\n\
             announced 5, ledger committed\n\
             scanned 22 signature(s): 6 already recorded, 0 skipped by cache, \
             0 not an incoming settlement, 0 could not be fetched, 5 new \
             [5 transaction(s) fetched, 11 outside --only]"
        )
    }

    /// A run whose sends were refused, and which therefore did not commit.
    fn failed_run() -> String {
        format!(
            "SEND FAILED, will retry next run: payment received: 0.39 USDC from \
             D7o5YEE6ZTnQPRd2nbdoK1rRP83mLLoapoBWgkSJFUHL at {SETTLED_AT} (signature {SIG})\n\
             Error: Failed to send message via whatsapp.shop\n\
             announced 0 of 5; ledger NOT committed so the rest re-announce"
        )
    }

    /// Ordinary announcer chatter with no delivery in it at all.
    fn quiet_run() -> String {
        "scanned 22 signature(s): 6 already recorded, 0 skipped by cache, \
         0 not an incoming settlement, 0 could not be fetched, 0 new \
         [0 transaction(s) fetched, 11 outside --only]"
            .to_string()
    }

    fn read(text: String) -> Result<(String, &'static str), String> {
        Ok((text, "zc-announce journal"))
    }

    /// THE CONTROL, and it is the whole point of this block. A check that can only
    /// ever report health is worth less than no check, because it launders an absence
    /// of information into a green.
    ///
    /// Three directions, because two would leave the interesting one untested. A
    /// fresh delivery must read `connected`. A window with no delivery at all must
    /// not, and must report nothing rather than something reassuring. And a delivery
    /// that is real but OLD must not read `connected` either, which is the case a
    /// naive "did we ever send" parser passes.
    #[test]
    fn only_a_fresh_dated_delivery_reads_connected() {
        // Direction 1: fresh. `now` sits five minutes after the settlement.
        let fresh = receipts_json(read(sent_run(SETTLED_AT)), SETTLED_EPOCH + 300, DAY);
        assert_eq!(fresh["delivery"]["status"], "connected");
        assert_eq!(fresh["delivery"]["last_success_age_seconds"], 300);
        assert_eq!(fresh["delivery"]["age_basis"], "settlement_instant");
        assert_eq!(fresh["records_found"], 1);
        // The run summary rides along: five receipts, ledger committed.
        assert_eq!(fresh["last_run"]["announced"], 5);
        assert_eq!(fresh["last_run"]["ledger_committed"], true);

        // Direction 2: a perfectly readable window holding no delivery.
        let none = receipts_json(read(quiet_run()), NOW, DAY);
        assert_eq!(none["log_readable"], true);
        assert_eq!(none["records_found"], 0);
        assert_eq!(none["delivery"]["status"], "unknown");
        assert_ne!(none["delivery"]["status"], "connected");
        // The denominator, which is what makes that zero readable. Zero of zero and
        // zero of many are different verdicts about this instrument.
        assert!(
            none["lines_scanned"].as_u64().unwrap_or(0) >= 1,
            "the scan denominator must be reported: {none}"
        );

        // Direction 3: a real delivery, dated, but older than the window.
        let stale = receipts_json(read(sent_run(SETTLED_AT)), SETTLED_EPOCH + (3 * DAY), DAY);
        assert_eq!(stale["delivery"]["status"], "stale");
        assert_ne!(stale["delivery"]["status"], "connected");
        assert_eq!(stale["delivery"]["last_success_age_seconds"], 3 * DAY);
    }

    /// The one state that IS positive evidence of a broken send path, and the only
    /// line that names which channel refused.
    #[test]
    fn a_refused_send_is_reported_as_failing_and_names_the_channel() {
        let v = receipts_json(read(failed_run()), SETTLED_EPOCH + 60, DAY);
        assert_eq!(v["delivery"]["status"], "failing");
        assert_eq!(v["delivery"]["channel"], "whatsapp.shop");
        assert_eq!(v["last_run"]["announced"], 0);
        assert_eq!(v["last_run"]["ledger_committed"], false);
        // A failure is NOT a success, and the field whose name says success must stay
        // null however much is known about when the attempt happened. A consumer
        // reading a number there would conclude a receipt got through.
        assert_eq!(
            v["delivery"]["last_success_age_seconds"],
            serde_json::Value::Null,
            "a refusal reported an age under the success field: {v}"
        );

        // The control: the same window with the send succeeding instead reads the
        // other way, so the verdict tracks the record rather than the fixture.
        let ok = receipts_json(read(sent_run(SETTLED_AT)), SETTLED_EPOCH + 60, DAY);
        assert_eq!(ok["delivery"]["status"], "connected");
        assert_eq!(ok["last_run"]["ledger_committed"], true);
    }

    /// A refusal a minute old and a refusal three weeks old are different incidents:
    /// the first is a transient the next tick may clear, the second is an outage nobody
    /// noticed. Reporting them identically is a real loss of information, and it is the
    /// loss that survived a review round precisely because the failure test asserted the
    /// status and the channel but never the age.
    ///
    /// Both directions, plus the naming invariant that made this awkward to fix: the age
    /// has to travel in a field that cannot be read as a success, so `failing` keeps a
    /// null `last_success_age_seconds` in both cases while `last_attempt_age_seconds`
    /// moves.
    #[test]
    fn a_fresh_refusal_is_distinguishable_from_an_old_one() {
        let minute = receipts_json(read(failed_run()), SETTLED_EPOCH + 60, DAY);
        let weeks = receipts_json(read(failed_run()), SETTLED_EPOCH + (21 * DAY), DAY);

        assert_eq!(minute["delivery"]["last_attempt_age_seconds"], 60);
        assert_eq!(weeks["delivery"]["last_attempt_age_seconds"], 21 * DAY);
        assert_ne!(
            minute["delivery"]["last_attempt_age_seconds"],
            weeks["delivery"]["last_attempt_age_seconds"],
            "a minute-old and a three-week-old refusal reported identically"
        );

        // Both are still failures, and neither may claim a success of any age.
        for v in [&minute, &weeks] {
            assert_eq!(v["delivery"]["status"], "failing");
            assert_eq!(
                v["delivery"]["last_success_age_seconds"],
                serde_json::Value::Null
            );
            assert_eq!(v["delivery"]["age_basis"], "settlement_instant");
        }

        // An undatable refusal reports no attempt age rather than a guessed one, and
        // says so in its basis. This is the control on the two assertions above: without
        // it, a hardcoded age would satisfy them both.
        let undatable = "SEND FAILED, will retry next run: payment received: 0.39 USDC \
                         from D7o5YEE at some point (signature abc)";
        let u = receipts_json(read(undatable.to_string()), NOW, DAY);
        assert_eq!(u["delivery"]["status"], "failing");
        assert_eq!(
            u["delivery"]["last_attempt_age_seconds"],
            serde_json::Value::Null
        );
        assert_eq!(u["delivery"]["age_basis"], "none");
    }

    /// On the success path the attempt and the success are one event, so the two ages
    /// agree. Asserting it pins the schema as uniform: every branch carries both fields,
    /// and a consumer never has to discover that one of them is missing on some paths.
    #[test]
    fn a_delivered_receipt_reports_the_same_age_under_both_names() {
        let v = receipts_json(read(sent_run(SETTLED_AT)), SETTLED_EPOCH + 300, DAY);
        assert_eq!(v["delivery"]["last_success_age_seconds"], 300);
        assert_eq!(v["delivery"]["last_attempt_age_seconds"], 300);

        // And on the paths where nothing is known, both are null rather than one of
        // them silently defaulting to zero, which would read as "just now".
        let none = receipts_json(read(quiet_run()), NOW, DAY);
        assert_eq!(
            none["delivery"]["last_success_age_seconds"],
            serde_json::Value::Null
        );
        assert_eq!(
            none["delivery"]["last_attempt_age_seconds"],
            serde_json::Value::Null
        );
    }

    /// The journal is append-only, so the last outcome is the newest. A parser that
    /// kept the FIRST hit would keep reporting an old success after the send path
    /// started refusing, which is the worst available error.
    #[test]
    fn the_newest_outcome_wins_not_the_first() {
        let recovered = format!("{}\n{}", failed_run(), sent_run(SETTLED_AT));
        let v = receipts_json(read(recovered), SETTLED_EPOCH + 60, DAY);
        assert_eq!(
            v["delivery"]["status"], "connected",
            "a later success must supersede an earlier failure: {v}"
        );

        // The control, the same two runs in the other order.
        let broke = format!("{}\n{}", sent_run(SETTLED_AT), failed_run());
        let v2 = receipts_json(read(broke), SETTLED_EPOCH + 60, DAY);
        assert_eq!(v2["delivery"]["status"], "failing");
        assert_eq!(v2["delivery"]["channel"], "whatsapp.shop");
    }

    /// An unavailable source must read unknown, never as a broken send path, on
    /// exactly the reasoning that governs a missing `systemctl` above.
    ///
    /// The paired direction is that the failure must not be silent either. A block
    /// that omitted itself would be indistinguishable from a shop with no receipts,
    /// so `log_readable` has to be present and false.
    #[test]
    fn an_unavailable_journal_is_unknown_rather_than_a_broken_send_path() {
        let v = receipts_json(Err("journalctl unavailable: not found".into()), NOW, DAY);
        assert_eq!(v["log_readable"], false);
        assert_eq!(v["records_found"], 0);
        assert_eq!(v["lines_scanned"], 0);
        assert_eq!(v["delivery"]["status"], "unknown");
        assert!(
            v["detail"].as_str().is_some_and(|d| !d.is_empty()),
            "an unavailable source must say why: {v}"
        );
        // And it must not carry a path, which may hold $HOME and would put an
        // operator username in a public body.
        assert!(!v.to_string().contains("/home/"), "path leaked: {v}");
    }

    /// A delivery nobody can date is not a recent delivery. This is the case that
    /// decides whether the block can be fooled by an undated line.
    #[test]
    fn an_undatable_delivery_never_reads_connected() {
        let undated = "sent: payment received: 0.39 USDC from D7o5YEE at some point \
                       (signature abc)";
        let v = receipts_json(read(undated.to_string()), NOW, DAY);
        assert_eq!(v["records_found"], 1, "the line is still a record: {v}");
        assert_eq!(v["delivery"]["status"], "unknown");
        assert_eq!(
            v["delivery"]["last_success_age_seconds"],
            serde_json::Value::Null
        );
    }

    /// The 2026-07-27 fabrication in the SHOP daemon log invented a send record, two
    /// channel ids that resolve from nowhere, and an alphabet-sequence signature.
    ///
    /// THE PRIMARY DEFENCE IS NOW SOURCE SEPARATION rather than parsing: this block
    /// reads the announcer's journal, and the announcer is a shell script that never
    /// consults a model, so model-authored text cannot enter it. Datability is the
    /// second layer, and this pins it: the fabricated JSON does not match any
    /// announcer line, and even a fabrication rewritten into announcer prose is
    /// frozen in July and therefore cannot read `connected` against any present-day
    /// clock.
    #[test]
    fn the_july_fabrication_cannot_reach_connected() {
        let fabricated = "{\"status\": \"success\", \"channel\": \"whatsapp.default\", \
                          \"target\": \"YetAnotherSenderWalletAddress\", \
                          \"timestamp\": \"2026-07-27T10:00:00Z\"}\n\
                          print(send_message_to_peer(channel='whatsapp.owner', \
                          message='Order settled'))";
        let v = receipts_json(read(fabricated.to_string()), NOW, DAY);
        assert_eq!(
            v["records_found"], 0,
            "invented JSON became a delivery record: {v}"
        );
        assert_eq!(v["delivery"]["status"], "unknown");
        assert_eq!(v["delivery"]["channel"], serde_json::Value::Null);

        // The second layer, in case a fabrication is ever written in the announcer's
        // own words: July is not inside a present-day freshness window.
        let in_prose = receipts_json(read(sent_run("2026-07-27T10:00:00Z")), NOW, DAY);
        assert_eq!(in_prose["delivery"]["status"], "stale");
        assert_ne!(in_prose["delivery"]["status"], "connected");
    }

    /// Lines that are not delivery outcomes must not be counted as ones. The scan
    /// line and the run summary are the announcer's own chatter and appear on every
    /// tick, including ticks that delivered nothing.
    #[test]
    fn announcer_chatter_is_not_counted_as_a_delivery() {
        for line in [
            "scanned 22 signature(s): 6 already recorded, 0 skipped by cache, 0 new",
            "announced 0 of 5; ledger NOT committed so the rest re-announce",
            "channel-id    telegram.shop",
            "Error: Failed to send message via not a channel name at all",
        ] {
            let v = receipts_json(read(line.to_string()), NOW, DAY);
            assert_eq!(
                v["records_found"], 0,
                "counted chatter as a delivery: {line}"
            );
        }

        // The over-correction control. The filters must not be so tight that a
        // genuine outcome stops matching, which is how a narrowing silently turns a
        // check off.
        let v = receipts_json(read(sent_run(SETTLED_AT)), SETTLED_EPOCH + 30, DAY);
        assert_eq!(
            v["records_found"], 1,
            "the filters reject a real delivery: {v}"
        );
        assert_eq!(v["delivery"]["status"], "connected");
    }

    /// The instant parser decides every `connected` verdict, so it gets its own
    /// round trip against the formatter that already lives in this file. A calendar
    /// routine that is off by a day is wrong quietly.
    #[test]
    fn the_instant_parser_round_trips_against_the_formatter() {
        for epoch in [0u64, 1_000_000_000, SETTLED_EPOCH, 2_000_000_000] {
            let rendered = rfc3339_utc(UNIX_EPOCH + Duration::from_secs(epoch));
            assert_eq!(
                parse_rfc3339_utc(&rendered),
                Some(epoch),
                "round trip failed for {epoch} rendered as {rendered}"
            );
        }
        // And the anchor the fixtures rely on, checked against the real line rather
        // than against the parser's own output.
        assert_eq!(parse_rfc3339_utc(SETTLED_AT), Some(SETTLED_EPOCH));

        // Malformed instants are refused rather than guessed at, because a lenient
        // parse is the one way a wrong number reaches `connected`.
        for bad in [
            "2026-08-17T05:32:17",  // no zone
            "2026-08-17 05:32:17Z", // no T
            "2026-13-17T05:32:17Z", // month 13
            "2026-08-17T25:32:17Z", // hour 25
            "not-a-time",
            "",
        ] {
            assert_eq!(
                parse_rfc3339_utc(bad),
                None,
                "accepted a bad instant: {bad}"
            );
        }
    }

    /// `handle_health` must actually carry the block. The pure-function tests above
    /// prove the logic and would all pass with the block wired to nothing.
    #[test]
    fn the_health_body_carries_the_receipts_block() {
        let (_, body, _) = health_empty();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let r = &v["receipts"];
        assert!(
            r.is_object(),
            "no receipts block in the health body: {body}"
        );
        assert!(r["log_readable"].is_boolean());
        assert!(
            r["lines_scanned"].is_u64(),
            "the denominator must be numeric"
        );
        assert!(r["records_found"].is_u64());
        assert!(r["delivery"]["status"].is_string());
        assert_eq!(r["stale_after_seconds"], RECEIPT_FRESH_SECS);
        // On any machine without the announcer's journal this is the unknown path,
        // and it must never be the connected one.
        assert_ne!(
            r["delivery"]["status"], "connected",
            "a machine with no announcer reported a delivery: {body}"
        );
    }
}

#[cfg(test)]
mod selfcheck_tests {
    use super::*;

    /// The clock every case is measured against, and the epoch `rfc3339_utc` is
    /// pinned to. Fixed rather than `now()` so the arithmetic is checkable
    /// rather than approximately right.
    const FIXED_NOW_EPOCH: u64 = 1_700_000_000;

    fn at(epoch: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(epoch)
    }

    /// Shaped like what `deploy/box_selfcheck.py::build_verdict` writes: the
    /// generated_at pair, the deployed sha, the verdict, and the per-check
    /// detail lines. Kept full rather than minimised so the merge is exercised
    /// against the document that will actually arrive.
    fn verdict_bytes(generated_at_epoch: u64) -> Vec<u8> {
        serde_json::json!({
            "generated_at": "2023-11-14T22:13:20Z",
            "generated_at_epoch": generated_at_epoch,
            "deployed_sha": "68d83ded97bf0c58",
            "ok": true,
            "checks": [
                {"name": "skills_match_manifest", "ok": true, "detail": "8 of 8 byte-identical"},
                {"name": "no_foreign_mint_in_state", "ok": true, "detail": "0 candidates"},
            ],
        })
        .to_string()
        .into_bytes()
    }

    /// `ZEROCLAW_HOME` is read, because `deploy/box_selfcheck.py` honours it and
    /// a route that did not would serve 503 for a verdict sitting on disk.
    ///
    /// Its control is the test below. Either one alone passes on a resolver that
    /// ignores the other input entirely: hardcode the override and this passes
    /// while the default is broken; hardcode `$HOME` and the reverse. Read them
    /// as one case split in two, which is also why they assert the two roots
    /// produce DIFFERENT paths — a resolver returning a constant fails that and
    /// nothing else here.
    #[test]
    fn zeroclaw_home_is_honoured_when_it_is_set() {
        let overridden = resolve_verdict_path(Some("/srv/zc"), Some("/home/node")).unwrap();
        assert_eq!(overridden, "/srv/zc/state/box-selfcheck.json");

        let default = resolve_verdict_path(None, Some("/home/node")).unwrap();
        assert_ne!(
            overridden, default,
            "the override and the default resolved to one path, so one input is being ignored"
        );
    }

    /// The default still works when the override is absent, which is the state
    /// of every box that has not set it — including the one in production.
    #[test]
    fn the_default_root_is_used_when_zeroclaw_home_is_unset() {
        assert_eq!(
            resolve_verdict_path(None, Some("/home/node")).unwrap(),
            "/home/node/.zeroclaw/state/box-selfcheck.json"
        );
    }

    /// A set-but-empty variable falls back rather than resolving to the root of
    /// the filesystem. `std::env::var` returns `Ok("")` for `ZEROCLAW_HOME=` in
    /// a unit file, so `.ok()` alone would take that branch and stat
    /// `/state/box-selfcheck.json`.
    ///
    /// Driven on both variables, since `HOME=` is the same shape and reaching
    /// `/.zeroclaw/state/...` is the same defect one level down.
    #[test]
    fn an_empty_env_value_falls_back_rather_than_resolving_to_the_filesystem_root() {
        assert_eq!(
            resolve_verdict_path(Some(""), Some("/home/node")).unwrap(),
            "/home/node/.zeroclaw/state/box-selfcheck.json",
            "an empty override was treated as a real path"
        );
        // An empty HOME with a real override is still the override.
        assert_eq!(
            resolve_verdict_path(Some("/srv/zc"), Some("")).unwrap(),
            "/srv/zc/state/box-selfcheck.json"
        );
        // Nothing usable is an error with a reason, never a path at the root.
        for (zc, home) in [
            (None, None),
            (Some(""), None),
            (None, Some("")),
            (Some(""), Some("")),
        ] {
            let resolved = resolve_verdict_path(zc, home);
            assert!(
                resolved.is_err(),
                "resolved to {resolved:?} with nothing usable to resolve from"
            );
        }
    }

    /// The resolved path reaches the response: an unresolvable path is the same
    /// 503 as an unreadable file, with its own reason rather than a generic one.
    #[test]
    fn an_unresolvable_path_is_503_with_its_own_reason() {
        let reason = resolve_verdict_path(None, None).unwrap_err();
        let (status, body, _) = render_selfcheck(Err(reason), at(FIXED_NOW_EPOCH));
        assert_eq!(status, 503);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "no verdict");
        assert!(
            v["detail"]
                .as_str()
                .is_some_and(|d| d.contains("ZEROCLAW_HOME")),
            "the reason must name what was missing: {body}"
        );
    }

    /// BRANCH 1: a verdict that is present and parses is served whole, with the
    /// two server-added fields merged in.
    ///
    /// The control is that every field of the original survives. Without it, a
    /// handler that discarded the verdict and returned only the two added
    /// fields would satisfy a "200 with an age" assertion.
    #[test]
    fn a_present_verdict_is_served_whole_with_the_two_added_fields() {
        let (status, body, hdr) = render_selfcheck(
            Ok((verdict_bytes(FIXED_NOW_EPOCH), at(FIXED_NOW_EPOCH - 90))),
            at(FIXED_NOW_EPOCH),
        );
        assert_eq!(status, 200);
        assert!(hdr.is_none());

        let v: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("invalid JSON ({e}): {body}"));
        assert_eq!(v["age_seconds"], 90);
        assert_eq!(v["served_at"], "2023-11-14T22:13:20Z");

        // The control: the verdict itself came through untouched.
        assert_eq!(v["ok"], true);
        assert_eq!(v["deployed_sha"], "68d83ded97bf0c58");
        assert_eq!(v["generated_at_epoch"], FIXED_NOW_EPOCH);
        assert_eq!(v["checks"].as_array().map(Vec::len), Some(2));
        assert_eq!(v["checks"][0]["name"], "skills_match_manifest");
    }

    /// BRANCH 2: an absent or unreadable verdict is a 503, and it is not
    /// readable as a pass.
    ///
    /// The control is that second half. A 503 carrying a truthy-looking body is
    /// the exact failure this route exists to prevent, and asserting only the
    /// status code would not catch it.
    #[test]
    fn an_absent_verdict_is_503_and_carries_no_verdict_shaped_field() {
        let (status, body, hdr) = render_selfcheck(
            Err("verdict unreadable: No such file or directory (os error 2)".to_string()),
            at(FIXED_NOW_EPOCH),
        );
        assert_eq!(status, 503, "a missing verdict must never be a 200");
        assert!(hdr.is_none());

        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "no verdict");
        assert!(
            v["detail"].as_str().is_some_and(|d| !d.is_empty()),
            "the reason must be stated: {body}"
        );
        assert!(
            v.get("ok").is_none(),
            "no verdict must not be readable as a pass: {body}"
        );
        assert!(v.get("age_seconds").is_none(), "no verdict has no age");
    }

    /// BRANCH 3: content that does not parse is the same 503, reached by a
    /// different route.
    ///
    /// Driven over four shapes because "does not parse" hides three distinct
    /// cases: truncated (a run killed mid-write), empty (a run that created the
    /// file and died), and JSON that parses to something the two fields cannot
    /// be merged into. The scalar and the array are the ones that would
    /// otherwise slip through as a 200 with no age.
    #[test]
    fn malformed_content_is_503_rather_than_a_partial_200() {
        for bad in [
            &b"{\"ok\": true, \"checks\": ["[..], // truncated mid-write
            &b""[..],                             // created, never written
            &b"true"[..],                         // parses, but not an object
            &b"[1, 2, 3]"[..],                    // parses, but not an object
        ] {
            let (status, body, _) = render_selfcheck(
                Ok((bad.to_vec(), at(FIXED_NOW_EPOCH - 5))),
                at(FIXED_NOW_EPOCH),
            );
            assert_eq!(
                status,
                503,
                "malformed verdict served as {status}: {:?}",
                String::from_utf8_lossy(bad)
            );
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["error"], "no verdict");
            assert!(v.get("age_seconds").is_none());
        }
    }

    /// The control for `age_seconds` being a measurement rather than a field
    /// that is always present and always zero.
    ///
    /// Two mtimes against one clock must give two different ages, and each must
    /// be the exact difference. A hardcoded zero, a hardcoded constant, and a
    /// subtraction taken from the wrong end all fail this.
    #[test]
    fn age_tracks_the_mtime_it_was_given() {
        let age_of = |mtime_epoch: u64| -> u64 {
            let (_, body, _) = render_selfcheck(
                Ok((verdict_bytes(FIXED_NOW_EPOCH), at(mtime_epoch))),
                at(FIXED_NOW_EPOCH),
            );
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            v["age_seconds"].as_u64().expect("age must be a number")
        };

        assert_eq!(age_of(FIXED_NOW_EPOCH - 60), 60);
        assert_eq!(age_of(FIXED_NOW_EPOCH - 3_600), 3_600);
        assert_ne!(
            age_of(FIXED_NOW_EPOCH - 60),
            age_of(FIXED_NOW_EPOCH - 3_600),
            "two different mtimes produced one age, so the age is not measured"
        );

        // Same file, later clock: the age has to grow on its own.
        let (_, later, _) = render_selfcheck(
            Ok((verdict_bytes(FIXED_NOW_EPOCH), at(FIXED_NOW_EPOCH - 60))),
            at(FIXED_NOW_EPOCH + 240),
        );
        let v: serde_json::Value = serde_json::from_str(&later).unwrap();
        assert_eq!(v["age_seconds"], 300);
    }

    /// Why the contract specifies the mtime: a verdict's own `generated_at` is
    /// written by the process that writes the file, so it cannot see a run that
    /// died before writing, and it travels with the bytes if the file is copied
    /// from elsewhere.
    ///
    /// The fixture makes the two disagree deliberately. A stale file claiming a
    /// current `generated_at_epoch` must still report its real age, which is
    /// what an implementation reading the convenient field would get wrong
    /// while passing every other case here.
    #[test]
    fn age_comes_from_the_mtime_not_from_the_verdict_own_timestamp() {
        let (_, body, _) = render_selfcheck(
            // The document says it was generated a second ago; the file says it
            // was last written two hours ago.
            Ok((
                verdict_bytes(FIXED_NOW_EPOCH - 1),
                at(FIXED_NOW_EPOCH - 7_200),
            )),
            at(FIXED_NOW_EPOCH),
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v["age_seconds"], 7_200,
            "the age followed the verdict's own timestamp instead of the file's mtime"
        );
        // The control: the misleading field is still served, untouched. The fix
        // is to ignore it for the age, not to strip it from the verdict.
        assert_eq!(v["generated_at_epoch"], FIXED_NOW_EPOCH - 1);
    }

    /// An mtime ahead of the clock (a step, or a copy that preserved a newer
    /// stamp) saturates at zero rather than failing the request, because the
    /// verdict is present and a 503 there would be the sharper error.
    #[test]
    fn a_future_mtime_reports_zero_rather_than_failing() {
        let (status, body, _) = render_selfcheck(
            Ok((verdict_bytes(FIXED_NOW_EPOCH), at(FIXED_NOW_EPOCH + 500))),
            at(FIXED_NOW_EPOCH),
        );
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["age_seconds"], 0);
    }

    /// `served_at` is pinned against known epochs rather than pattern matched,
    /// so a formatter emitting a well-shaped wrong date fails.
    ///
    /// The cases are where calendar arithmetic actually breaks: both leap-year
    /// rules, the century that is not a leap year, and both ends of a year.
    #[test]
    fn served_at_is_a_correct_rfc3339_utc_timestamp() {
        for (epoch, expected) in [
            (0_u64, "1970-01-01T00:00:00Z"),
            (FIXED_NOW_EPOCH, "2023-11-14T22:13:20Z"),
            (951_782_400, "2000-02-29T00:00:00Z"), // leap day, /400 rule
            (4_107_542_400, "2100-03-01T00:00:00Z"), // 2100 is NOT a leap year
            (1_709_164_800, "2024-02-29T00:00:00Z"), // leap day, /4 rule
            (1_735_689_599, "2024-12-31T23:59:59Z"), // last second of a year
            (1_735_689_600, "2025-01-01T00:00:00Z"), // first second of the next
        ] {
            assert_eq!(rfc3339_utc(at(epoch)), expected, "epoch {epoch}");
        }

        // And it is that value which reaches the body, not merely a function
        // the body might not be calling.
        let (_, body, _) = render_selfcheck(
            Ok((verdict_bytes(FIXED_NOW_EPOCH), at(FIXED_NOW_EPOCH))),
            at(1_735_689_600),
        );
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["served_at"], "2025-01-01T00:00:00Z");
    }
}
