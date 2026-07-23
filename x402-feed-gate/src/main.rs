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
            "/health" => (200, r#"{"ok":true}"#.to_string(), None),
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
