//! Track A closed-loop end-to-end proof for the ZeroClaw payments trio.
//!
//! This harness plays the HOST/human. It reuses the plugins' REAL cores (so the
//! bytes it exercises are exactly what the wasm plugins emit) to close the full
//! Solana Pay loop against a live cluster and prove on-chain behavior that
//! mocked unit tests cannot:
//!
//!   1. `solana_pay_request::pay` builds a Solana Pay transfer-request URL with a
//!      FRESH reference pubkey (the invoice's tracking key).
//!   2. `spl_transfer_build::transfer` builds the matching UNSIGNED v0 transfer
//!      transaction (native SOL, 0.001 SOL) carrying the SAME reference key + the
//!      memo "invoice-e2e-1". Every signature slot is left EMPTY (custody T1: the
//!      plugin holds no key and can never broadcast).
//!   3. The host completes the empty fee-payer slot with the payer keypair and
//!      broadcasts. A successful confirm also byte-validates the plugin's wire
//!      bytes (they must bincode-parse as a real `solana_sdk::VersionedTransaction`
//!      and be chain-accepted).
//!   4. `payment_watch::watch` runs its REAL balance-delta detection against the
//!      cluster and returns PAID with the exact amount + the reference matched;
//!      a second check with a DIFFERENT expected reference returns NOT_YET.
//!
//! Every plugin call uses the plugin's own transport-generic function driven by a
//! REAL host `RpcTransport` (curl) -- no reimplementation of the plugin logic.
//! The Solana Pay reference is generated ONCE and threaded through all three
//! plugins, which is what makes this a closed loop rather than three isolated
//! demos.
//!
//! Run (devnet, operator-funded -- the orchestrator runs this):
//!   E2E_RPC=https://api.devnet.solana.com E2E_FUNDER=.devnet-proof/operator.json \
//!     cargo run --bin e2e-track-a
//! Or against a local validator on 127.0.0.1:8899 (airdrop funding):
//!   cargo run --bin e2e-track-a
//!
//! `E2E_RPC`   overrides the cluster (default http://127.0.0.1:8899).
//! `E2E_FUNDER=<keypair.json>` funds the ephemeral payer by transfer (devnet
//!             airdrop is rate-limited); absent -> airdrop (localnet).

use payment_watch::watch::Verdict;
use solana_client::rpc_client::RpcClient;
use solana_core::{Commitment, RpcError, RpcTransport, SolanaRpc};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signature::{Keypair, Signature, Signer};
#[allow(deprecated)]
use solana_sdk::system_instruction;
use solana_sdk::transaction::{Transaction, VersionedTransaction};
use std::process::Command;
use std::time::Duration;

const RPC_URL: &str = "http://127.0.0.1:8899";
/// 0.001 SOL, small (keeps the devnet run cheap) yet above the ~0.00089 SOL
/// rent-exempt minimum for a fresh 0-data account, so the recipient persists.
const TRANSFER_LAMPORTS: u64 = 1_000_000;
const MEMO: &str = "invoice-e2e-1";
/// Detection retry budget (payment indexing can lag a confirm by a slot or two
/// on a public RPC). Localnet resolves on the first attempt.
const WATCH_MAX_ATTEMPTS: usize = 20;

/// Host transport: POST JSON-RPC via `curl`. The wasm plugins use `waki`; the
/// bytes on the wire are identical regardless of who ships them, so driving the
/// plugin cores through this proves the exact code path the deployed plugins run.
struct CurlTransport {
    url: String,
}

impl RpcTransport for CurlTransport {
    fn post_json(&self, body: &str) -> Result<String, RpcError> {
        let out = Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                &self.url,
                "-H",
                "Content-Type: application/json",
                "-d",
                body,
            ])
            .output()
            .map_err(|e| RpcError::Transport(format!("curl spawn failed: {e}")))?;
        if !out.status.success() {
            return Err(RpcError::Transport(format!(
                "curl exited {:?}",
                out.status.code()
            )));
        }
        String::from_utf8(out.stdout).map_err(|e| RpcError::Transport(e.to_string()))
    }
}

fn main() {
    let rpc_url = std::env::var("E2E_RPC").unwrap_or_else(|_| RPC_URL.to_string());
    let cluster = if rpc_url.contains("devnet") {
        "devnet"
    } else {
        "localnet"
    };
    let funder: Option<Keypair> = std::env::var("E2E_FUNDER")
        .ok()
        .map(|p| solana_sdk::signature::read_keypair_file(&p).expect("read funder keypair"));
    println!(
        "cluster={cluster}  rpc={rpc_url}  funding={}",
        funder
            .as_ref()
            .map(|f| f.pubkey().to_string())
            .unwrap_or_else(|| "airdrop".into())
    );
    let rpc = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

    // --- keys ---
    // payer   = the agent's session key: fee payer + transfer authority (host-held).
    // recipient = the merchant wallet (fresh; only the loop's transfer touches it).
    // reference = the fresh Solana Pay tracking key threaded through all 3 plugins.
    let payer = Keypair::new();
    let recipient = Keypair::new();
    let reference = Keypair::new();
    let wrong_reference = Keypair::new();

    // Fund only the payer; the recipient is created by the transfer itself.
    fund(&rpc, &funder, &payer.pubkey(), 20_000_000); // 0.02 SOL: transfer + fees, ample.
    println!(
        "keys: payer={} recipient={} reference={}",
        payer.pubkey(),
        recipient.pubkey(),
        reference.pubkey()
    );

    // === STEP 1: solana-pay-request core builds the transfer-request URL ========
    let pay_args = format!(
        r#"{{"recipient":"{}","amount":"0.001","reference":"{}","label":"ZeroClaw E2E","memo":"{MEMO}"}}"#,
        recipient.pubkey(),
        reference.pubkey()
    );
    let req = solana_pay_request::pay::parse_and_validate(&pay_args)
        .expect("pay-request core validation");
    let url = solana_pay_request::pay::build_transfer_url(&req);
    assert!(
        url.contains(&recipient.pubkey().to_string()),
        "pay URL must carry the recipient in the path: {url}"
    );
    assert!(
        url.contains(&format!("reference={}", reference.pubkey())),
        "pay URL must carry the fresh reference key: {url}"
    );
    println!("\n[1] solana-pay-request -> {url}");
    println!(
        "    render_output: {}",
        solana_pay_request::pay::render_output(&req)
    );

    // === STEP 2: spl-transfer-build core builds the UNSIGNED v0 transfer =========
    // Native SOL, recent-blockhash mode (no nonce for this loop). The SAME
    // reference key + the SAME memo as the pay request are threaded in.
    let xfer_args = format!(
        r#"{{"recipient":"{}","amount":"0.001","mint":"SOL","memo":"{MEMO}","reference":"{}","__config":{{"payer_pubkey":"{}"}}}}"#,
        recipient.pubkey(),
        reference.pubkey(),
        payer.pubkey()
    );
    let vt = spl_transfer_build::transfer::parse_and_validate(&xfer_args)
        .expect("spl-transfer-build core validation");
    let build_rpc = SolanaRpc::new(CurlTransport {
        url: rpc_url.clone(),
    })
    .with_commitment(Commitment::Confirmed);
    let (unsigned, meta) = spl_transfer_build::transfer::build_transfer(&build_rpc, &vt)
        .expect("build_transfer against the live cluster");

    // The plugin's wire bytes MUST parse as a real solana-sdk VersionedTransaction
    // (the core emits a v0 message; this is the byte-validation gate).
    let mut vtx: VersionedTransaction =
        bincode::deserialize(&unsigned.wire).expect("plugin wire bytes must be a valid v0 tx");
    assert_eq!(
        vtx.signatures.len(),
        meta.signatures_required as usize,
        "signature slot count must match the plugin's reported requirement"
    );
    assert!(
        vtx.signatures.iter().all(|s| *s == Signature::default()),
        "every signature slot must be EMPTY (T1: plugin never signs)"
    );
    assert_eq!(
        vtx.message.static_account_keys().first(),
        Some(&payer.pubkey()),
        "fee payer must be signer account index 0"
    );
    println!(
        "\n[2] spl-transfer-build -> UNSIGNED v0 tx ({} byte wire, {} empty sig slot(s), mode={})",
        unsigned.wire.len(),
        meta.signatures_required,
        meta.mode.as_str()
    );

    // === STEP 3: host completes the empty fee-payer slot and broadcasts =========
    let msg_bytes = vtx.message.serialize();
    vtx.signatures[0] = payer.sign_message(&msg_bytes);
    let sig = rpc
        .send_and_confirm_transaction(&vtx)
        .expect("host-signed transfer must land on chain");
    let sig_str = sig.to_string();
    println!("[3] host signed + broadcast -> tx {sig_str}");

    // === STEP 4: payment-watch core DETECTS the payment (real balance delta) =====
    // Correct reference -> PAID, exact amount + reference matched.
    let watch_args = format!(
        r#"{{"address":"{}","expected_amount":0.001,"mint":"SOL","reference":"{}","invoice_label":"{MEMO}"}}"#,
        recipient.pubkey(),
        reference.pubkey()
    );
    let vw = payment_watch::watch::parse_and_validate(&watch_args)
        .expect("payment-watch core validation");
    let watch_transport = CurlTransport {
        url: rpc_url.clone(),
    };
    let verdict = detect_paid(&watch_transport, &vw);
    let report = payment_watch::watch::compose_report(&vw, &verdict);
    match &verdict {
        Verdict::Paid(p) => {
            assert_eq!(
                p.amount_base, TRANSFER_LAMPORTS as i128,
                "detected amount must be exactly 0.001 SOL in lamports"
            );
            assert_eq!(p.decimals, 9, "native SOL is 9 decimals");
            assert_eq!(
                p.signature, sig_str,
                "detected signature must be the tx we broadcast"
            );
        }
        Verdict::NotYet { .. } => unreachable!("detect_paid only returns on PAID"),
    }
    println!("\n[4] payment-watch (correct reference) -> {report}");

    // Wrong reference -> the reference gate fails -> NOT_YET (proves it is a real
    // gate, not always-PAID). The tx is already indexed, so this is deterministic.
    let watch_args_wrong = format!(
        r#"{{"address":"{}","expected_amount":0.001,"mint":"SOL","reference":"{}"}}"#,
        recipient.pubkey(),
        wrong_reference.pubkey()
    );
    let vw_wrong = payment_watch::watch::parse_and_validate(&watch_args_wrong)
        .expect("payment-watch core validation (wrong ref)");
    let verdict_wrong = payment_watch::watch::find_payment(&watch_transport, &vw_wrong)
        .expect("payment-watch #2 rpc");
    assert!(
        matches!(verdict_wrong, Verdict::NotYet { .. }),
        "a different expected reference must NOT match: {verdict_wrong:?}"
    );
    println!(
        "[4] payment-watch (wrong reference) -> {}",
        payment_watch::watch::compose_report(&vw_wrong, &verdict_wrong)
    );

    if cluster == "devnet" {
        println!("\nDEMO ARTIFACTS (Solana Explorer, devnet):");
        println!("  transfer tx:  https://explorer.solana.com/tx/{sig_str}?cluster=devnet");
        println!(
            "  recipient:    https://explorer.solana.com/address/{}?cluster=devnet",
            recipient.pubkey()
        );
        println!(
            "  reference:    https://explorer.solana.com/address/{}?cluster=devnet",
            reference.pubkey()
        );
    }
    println!(
        "\nTRACK A E2E PASS: pay-request URL -> unsigned transfer (T1) -> host sign+broadcast -> \
         payment DETECTED (reference threaded end to end; wrong-reference correctly NOT_YET)"
    );
}

/// Poll `find_payment` until it returns PAID (retrying transient NOT_YET / RPC
/// hiccups), or panic after the budget is exhausted. Returns the PAID verdict.
fn detect_paid(transport: &CurlTransport, vw: &payment_watch::watch::ValidatedArgs) -> Verdict {
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        match payment_watch::watch::find_payment(transport, vw) {
            Ok(v @ Verdict::Paid(_)) => return v,
            Ok(Verdict::NotYet { checked, .. }) => {
                if attempt >= WATCH_MAX_ATTEMPTS {
                    panic!(
                        "payment-watch never detected the payment after {attempt} attempts \
                         (last: checked {checked} recent tx)"
                    );
                }
                eprintln!("    watch: not yet (attempt {attempt}); retrying...");
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(e) => {
                if attempt >= WATCH_MAX_ATTEMPTS {
                    panic!("payment-watch RPC error after {attempt} attempts: {e:?}");
                }
                eprintln!("    watch: rpc error (attempt {attempt}): {e:?}; retrying...");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// Fund `who` with `lamports`. Devnet: transfer from the operator (airdrop is
/// rate-limited). Localnet: airdrop.
fn fund(
    rpc: &RpcClient,
    funder: &Option<Keypair>,
    who: &solana_sdk::pubkey::Pubkey,
    lamports: u64,
) {
    match funder {
        Some(f) => {
            let ix = system_instruction::transfer(&f.pubkey(), who, lamports);
            let bh = rpc.get_latest_blockhash().unwrap();
            let tx = Transaction::new_signed_with_payer(&[ix], Some(&f.pubkey()), &[f], bh);
            rpc.send_and_confirm_transaction(&tx)
                .expect("operator funding transfer");
        }
        None => {
            let sig = rpc.request_airdrop(who, lamports).unwrap();
            loop {
                if rpc.confirm_transaction(&sig).unwrap_or(false) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    }
}
