//! x402 feed gate — the earning-node server.
//!
//! Turns a ZeroClaw DePIN node into a machine that SELLS its own device-signed
//! on-chain feed. A client (agent or human) GETs `/reading`; if it presents no
//! valid payment it gets HTTP 402 with a price menu and a per-request nonce; it
//! pays us a stablecoin transfer on Solana, retries with an `X-PAYMENT` header
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
//!   X402_NETWORK         x402 network string (default solana-devnet)
//!   X402_PORT            listen port (default 4577)
//!   X402_PRICE_SINGLE    atomic units for one reading (default 1000000 = 1 USDC)
//!   X402_PRICE_DAYPASS   atomic units for a day pass (default 5000000)
//!   X402_DAILY_CAP       per-payer atomic-unit daily cap (default 20000000)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use base64::Engine;
use solana_core::rpc::RpcTransport;
use solana_core::{Commitment, Pubkey, RpcError, SolanaRpc};
use tiny_http::{Header, Response, Server};

use x402_feed_gate::{
    settlement_header, verify_x_payment, DailyLedger, GateConfig, Reject, VerifiedPayment,
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

/// Append a settled sale to the earnings ledger (JSON-lines). The ZeroClaw
/// agent reads this file in an SOP and reports the node's daily x402 revenue to
/// the owner's channel ("the node announces what it sold"). Best-effort: any IO
/// failure is swallowed so it can never withhold a paid response.
fn record_earning(v: &VerifiedPayment, signature: &str, day: i64) {
    use std::io::Write;
    let path = std::env::var("X402_EARNINGS_LOG")
        .unwrap_or_else(|_| "x402-earnings.jsonl".to_string());
    let line = serde_json::json!({
        "day": day,
        "payer": v.payer.to_base58(),
        "amount": v.amount,
        "is_day_pass": v.is_day_pass,
        "settlement": signature,
    })
    .to_string();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
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
    let cfg = GateConfig {
        seller_wallet: env_pubkey("X402_SELLER_WALLET"),
        mint: env_pubkey("X402_MINT"),
        network: env_or("X402_NETWORK", "solana-devnet"),
        price_single: env_or("X402_PRICE_SINGLE", "1000000").parse().unwrap_or(1_000_000),
        price_day_pass: env_or("X402_PRICE_DAYPASS", "5000000").parse().unwrap_or(5_000_000),
        daily_cap: env_or("X402_DAILY_CAP", "20000000").parse().unwrap_or(20_000_000),
    };
    let feed = env_pubkey("X402_FEED_PDA");
    let rpc_url = env_or("X402_RPC_URL", "https://api.devnet.solana.com");
    let port = env_or("X402_PORT", "4577");

    let rpc = SolanaRpc::new(UreqTransport { url: rpc_url.clone() })
        .with_commitment(Commitment::Confirmed);
    let ledger = Mutex::new(DailyLedger::new());
    let nonce_counter = AtomicU64::new(0);

    let addr = format!("127.0.0.1:{port}");
    let server = Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("failed to bind {addr}: {e}");
        std::process::exit(1);
    });
    eprintln!("x402-feed-gate listening on http://{addr}");
    eprintln!("  selling feed {}", feed.to_base58());
    eprintln!("  receiving to ATA {} for mint {}", cfg.receiving_ata().to_base58(), cfg.mint.to_base58());
    eprintln!("  GET /reading  |  GET /price  |  GET /health");

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        let x_payment = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("X-Payment"))
            .map(|h| h.value.as_str().to_string());

        let path = url.split('?').next().unwrap_or("/");
        let response_body: (u16, String, Option<String>) = match path {
            "/health" => handle_health(),
            "/price" => {
                let nonce = issue_nonce(&nonce_counter);
                (402, cfg.challenge(&nonce).to_json(), None)
            }
            "/reading" => handle_reading(&cfg, &rpc, &feed, &ledger, &nonce_counter, x_payment.as_deref()),
            _ => (404, r#"{"error":"not found"}"#.to_string(), None),
        };

        let (status, body, settle_hdr) = response_body;
        let mut resp = json_response(status, body);
        if let Some(h) = settle_hdr {
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
fn handle_health() -> (u16, String, Option<String>) {
    let unit = "zc-shop.service";

    // `is-active` exits non-zero for anything but active, so the status code is
    // the signal and stdout is only for the reason.
    let (active, state) = match std::process::Command::new("systemctl")
        .args(["--user", "is-active", unit])
        .output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            (o.status.success(), if s.is_empty() { "unknown".into() } else { s })
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
    let body = serde_json::json!({
        "gate": "ok",
        "shop": {
            "unit": unit,
            "active": active,
            "state": state,
            "trace_age_seconds": trace_age,
        },
        "proves": "this gate answered, plus the shop unit's state and when it last \
                   handled traffic. Does NOT prove the channel binding or the model \
                   provider are working: only a synthetic round-trip proves those.",
    })
    .to_string();
    (200, body, None)
}

/// The core request handler: no payment -> 402 challenge; a payment -> verify,
/// enforce the cap, simulate, broadcast, confirm, serve the reading.
fn handle_reading<T: RpcTransport>(
    cfg: &GateConfig,
    rpc: &SolanaRpc<T>,
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
        if let Err(reject) = l.commit(&verified.payer, &nonce, day, verified.amount, cfg.daily_cap) {
            return reject_to_response(cfg, nonce_counter, reject);
        }
    }

    // Simulate, then broadcast, then confirm.
    match settle(rpc, &verified) {
        Ok(signature) => {
            // Append to the earnings ledger (JSON-lines) so the ZeroClaw agent can
            // report "sold N readings, earned X" to the owner's channel. Best-effort:
            // a log-write failure never withholds a paid response.
            record_earning(&verified, &signature, day);
            let body = serde_json::json!({
                "paid": true,
                "amount": verified.amount,
                "settlement": signature,
                "reading": serde_json::from_str::<serde_json::Value>(&feed_reading_json(rpc, feed))
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
    let raw = base64::engine::general_purpose::STANDARD.decode(tx_b64.trim()).ok()?;
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

    /// The route this replaced returned a hardcoded `{"ok":true}` that could not
    /// fail, so it asserted nothing. These assert the replacement actually says
    /// something, and that it stays parseable: the body is built by `format!`
    /// over a `concat!`, which compiles happily while emitting broken JSON.
    #[test]
    fn health_body_is_valid_json_with_the_fields_a_checker_reads() {
        let (status, body, hdr) = handle_health();
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
        assert!(age.is_u64() || age.is_null(), "trace age must be numeric or null: {age}");

        assert!(v["proves"].is_string(), "the limit clause must be present");
    }

    /// The honesty clause is load-bearing rather than decorative. Without it a
    /// reader takes a 200 as proof the shop can serve an order, which this
    /// endpoint cannot know: it sees the unit and the trace, not the channel
    /// binding or the model provider.
    #[test]
    fn health_states_its_own_limit() {
        let (_, body, _) = handle_health();
        // Case-insensitive on purpose: the clause is prose and its first word
        // capitalises or not depending on where a sentence break lands. Pinning
        // the case makes the test fail on a rewording that changed nothing.
        let lower = body.to_lowercase();
        assert!(lower.contains("does not prove"), "limit clause missing: {body}");
        assert!(lower.contains("channel binding"), "limit is not specific: {body}");
        assert!(lower.contains("model provider"), "limit is not specific: {body}");
    }

    /// A missing `systemctl` must read as unknown, never as a dead shop. On a
    /// dev box or a non-systemd host this path is the normal one, and reporting
    /// an outage because the instrument is absent is worse than reporting the
    /// instrument is absent.
    #[test]
    fn absent_instrument_is_not_reported_as_an_outage() {
        let (_, body, _) = handle_health();
        if body.contains("\"state\":\"unavailable\"") {
            assert!(body.contains("\"active\":false"));
            assert!(!body.contains("\"gate\":\"down\""),
                "a missing instrument must not be reported as the gate failing");
        }
    }
}
