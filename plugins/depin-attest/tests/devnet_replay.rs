//! LIVE devnet proof that the durable-nonce replay guard actually works.
//!
//! Gated identically to `devnet_live.rs` (needs `ZEROCLAW_DEVNET_PROOF=1` and the
//! funded `.devnet-proof/{operator,nonce}.json` setup). This is the concrete
//! evidence behind the threat-model claim "a replayed attestation is rejected by
//! the chain": it builds ONE attestation transaction, broadcasts it (lands), then
//! re-broadcasts the IDENTICAL bytes. The second send is rejected by the chain
//! because the durable nonce advanced when the first landed. Replay protection is
//! enforced by consensus, not by our code.

use depin_attest::attest;
use solana_core::{
    decode_nonce_account, instruction, message, pubkey_from_seed, serialize_transaction,
    sign_message, Commitment, Pubkey, RpcError, RpcTransport, SolanaRpc,
};
use std::process::Command;

const DEVNET: &str = "https://api.devnet.solana.com";

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
        String::from_utf8(out.stdout).map_err(|e| RpcError::Transport(e.to_string()))
    }
}

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
fn devnet_replay_is_rejected() {
    if std::env::var("ZEROCLAW_DEVNET_PROOF").is_err() {
        eprintln!("skipping devnet_replay_is_rejected (set ZEROCLAW_DEVNET_PROOF=1 to run)");
        return;
    }

    let seed_hex = read_seed_hex("../../.devnet-proof/operator.json");
    let nonce_pk = read_pubkey("../../.devnet-proof/nonce.json");
    let args = format!(
        r#"{{"reading":"contact_opened","device_id":"door-3","observed_at":1737300111,"__config":{{"signer_seed_hex":"{seed_hex}","nonce_account":"{}","rpc_url":"{DEVNET}"}}}}"#,
        nonce_pk.to_base58()
    );
    let v = attest::parse_and_validate(&args).expect("core validation");
    let signer_pk = Pubkey::new(pubkey_from_seed(&v.signer_seed));

    let rpc =
        SolanaRpc::new(CurlTransport { url: DEVNET.into() }).with_commitment(Commitment::Confirmed);

    // Build ONE transaction against the current durable nonce.
    let acct = rpc.get_account_info(&v.nonce_account).unwrap().unwrap();
    let ns = decode_nonce_account(&acct.data).unwrap();
    let nonce_before = ns.durable_nonce;
    let ixs = [
        instruction::advance_nonce_account(&v.nonce_account, &signer_pk),
        instruction::memo(&signer_pk, v.memo_payload.as_bytes()),
    ];
    let msg = message::compile(&signer_pk, &ixs, &ns.durable_nonce).unwrap();
    let msg_bytes = msg.serialize_legacy();
    let sig = sign_message(&v.signer_seed, &msg_bytes);
    let tx = serialize_transaction(&[sig], &msg_bytes); // these exact bytes are the "replay"

    // First broadcast: lands.
    let first = rpc
        .send_transaction(&tx)
        .expect("first attestation should land");
    println!("first attestation landed: {first}");

    // Wait for the nonce to advance on-chain (its new value becomes the blockhash).
    let mut advanced = false;
    for _ in 0..15 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if let Ok(Some(a)) = rpc.get_account_info(&v.nonce_account) {
            if let Ok(after) = decode_nonce_account(&a.data) {
                if after.durable_nonce != nonce_before {
                    advanced = true;
                    println!("durable nonce advanced (replay window closed)");
                    break;
                }
            }
        }
    }
    assert!(
        advanced,
        "durable nonce must advance once the first tx lands"
    );

    // Replay: re-send the IDENTICAL bytes. The chain rejects them (stale nonce).
    match rpc.send_transaction(&tx) {
        Ok(sig2) => panic!("REPLAY WAS ACCEPTED (should be impossible): {sig2}"),
        Err(RpcError::Rpc { code, message }) => {
            println!("replay REJECTED by chain: code={code} message={message}");
            assert!(
                message.to_lowercase().contains("nonce")
                    || message.to_lowercase().contains("blockhash")
                    || message.to_lowercase().contains("simulation"),
                "rejection should cite the stale nonce/blockhash, got: {message}"
            );
        }
        Err(other) => panic!("expected an RPC rejection, got transport error: {other:?}"),
    }
    println!("\n=== REPLAY-PROOF DEMONSTRATED: one attestation lands, the identical replay is rejected ===");
}
