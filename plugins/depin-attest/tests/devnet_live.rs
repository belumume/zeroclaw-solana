//! LIVE devnet proof of the depin-attest pipeline.
//!
//! Gated: runs only when `ZEROCLAW_DEVNET_PROOF=1` and the one-time operator
//! setup exists (`.devnet-proof/{operator,nonce}.json`, created out-of-band via
//! `solana create-nonce-account`). It is NOT part of normal CI — it needs a live
//! network and a funded devnet nonce account.
//!
//! What it proves: it drives the plugin's REAL core (`attest::parse_and_validate`)
//! and then the EXACT solana-core primitives the wasm shim uses
//! (`decode_nonce_account` -> `advance_nonce_account` + `memo` -> `compile` ->
//! `sign_message` -> `serialize_transaction`), swapping only the wasm `waki`
//! transport for a host transport (curl). The broadcast transaction BYTES are
//! byte-identical to what the deployed wasm plugin produces. Preflight simulation
//! stays ON, so devnet itself validates the transaction before accepting it.

use depin_attest::attest;
use solana_core::{
    decode_nonce_account, instruction, message, pubkey_from_seed, serialize_transaction,
    sign_message, Commitment, Pubkey, RpcError, RpcTransport, SolanaRpc,
};
use std::process::Command;

const DEVNET: &str = "https://api.devnet.solana.com";

/// Host transport: POST JSON via `curl` (the wasm plugin uses `waki`; the tx
/// bytes are identical regardless of who ships them over the wire).
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

/// A solana-keygen keypair file is a 64-byte JSON array: [seed(32) || pubkey(32)].
fn read_seed_hex(path: &str) -> String {
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    bytes[..32].iter().map(|b| format!("{b:02x}")).collect()
}

fn read_pubkey(path: &str) -> Pubkey {
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&bytes[32..]);
    Pubkey::new(pk)
}

#[test]
fn devnet_live_attestation() {
    if std::env::var("ZEROCLAW_DEVNET_PROOF").is_err() {
        eprintln!("skipping devnet_live_attestation (set ZEROCLAW_DEVNET_PROOF=1 to run)");
        return;
    }

    // Paths are relative to the crate root (plugins/depin-attest/).
    let seed_hex = read_seed_hex("../../.devnet-proof/operator.json");
    let nonce_pk = read_pubkey("../../.devnet-proof/nonce.json");

    // 1. Drive the plugin's REAL core with the operator's jailed config.
    let args = format!(
        r#"{{"reading":"tamper_triggered","device_id":"sensor-A7","observed_at":1737300000,"__config":{{"signer_seed_hex":"{seed_hex}","nonce_account":"{}","rpc_url":"{DEVNET}"}}}}"#,
        nonce_pk.to_base58()
    );
    let v = attest::parse_and_validate(&args).expect("core validation should pass");

    // Linchpin: our RFC-8032 ed25519 derivation must match the on-chain operator.
    let signer_pk = Pubkey::new(pubkey_from_seed(&v.signer_seed));
    println!("signer (derived from seed): {}", signer_pk.to_base58());
    println!(
        "nonce account:              {}",
        v.nonce_account.to_base58()
    );
    println!("memo payload:               {}", v.memo_payload);

    // 2. Replicate the wasm shim's exact RPC flow with a host transport.
    let rpc =
        SolanaRpc::new(CurlTransport { url: DEVNET.into() }).with_commitment(Commitment::Confirmed);

    let acct = rpc
        .get_account_info(&v.nonce_account)
        .expect("rpc getAccountInfo")
        .expect("nonce account must exist on chain");
    let ns = decode_nonce_account(&acct.data).expect("decode durable-nonce account");

    // The scoped signer must be the nonce authority or the tx cannot advance it.
    assert_eq!(
        ns.authority, signer_pk,
        "operator must be the nonce authority"
    );

    // advance-nonce MUST be instruction 0; then the sanitized attestation memo.
    let ixs = [
        instruction::advance_nonce_account(&v.nonce_account, &signer_pk),
        instruction::memo(&signer_pk, v.memo_payload.as_bytes()),
    ];
    let msg = message::compile(&signer_pk, &ixs, &ns.durable_nonce).expect("compile message");
    let msg_bytes = msg.serialize_legacy();
    let sig = sign_message(&v.signer_seed, &msg_bytes);
    let tx = serialize_transaction(&[sig], &msg_bytes);

    // 3. Broadcast to REAL devnet (preflight simulation stays ON).
    let signature = rpc.send_transaction(&tx).expect("broadcast to devnet");

    println!("\n=== LIVE DEVNET ATTESTATION LANDED ===");
    println!("tx signature: {signature}");
    println!("explorer:     https://explorer.solana.com/tx/{signature}?cluster=devnet");
    assert!(
        signature.len() >= 64,
        "signature should be a base58 sig string"
    );
}
