//! Reference x402 CLIENT: construct, sign, and print an `X-PAYMENT` header that
//! pays the feed gate. This is the buyer side of the protocol and doubles as
//! the reproducible client in the QUICKSTART.
//!
//! It does NOT broadcast — the gate does, after verifying. The client signs a
//! `TransferChecked` (client is fee payer) to the seller's ATA plus a Memo
//! carrying the challenge nonce, and emits the base64 `X-PAYMENT` header value.
//!
//! Usage:
//!   pay_client <payer_keypair.json> <seller_wallet_b58> <mint_b58> <amount_atomic> <decimals> <nonce> <rpc_url>
//!
//! Then: curl -H "X-PAYMENT: <output>" http://127.0.0.1:4577/reading

use base64::Engine;
use solana_core::instruction::{memo as memo_ix, set_compute_unit_limit, set_compute_unit_price, AccountMeta, Instruction};
use solana_core::pubkey::token_program;
use solana_core::rpc::RpcTransport;
use solana_core::token::TRANSFER_CHECKED_TAG;
use solana_core::{compile, pubkey_from_seed, serialize_transaction, sign_message, Commitment, Pubkey, RpcError, SolanaRpc};

struct Ureq {
    url: String,
}
impl RpcTransport for Ureq {
    fn post_json(&self, body: &str) -> Result<String, RpcError> {
        ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| RpcError::Transport(format!("ureq: {e}")))?
            .into_string()
            .map_err(|e| RpcError::Transport(format!("read: {e}")))
    }
}

/// Read a 64-byte Solana keypair JSON array; the first 32 bytes are the ed25519
/// seed our signing uses.
fn read_seed(path: &str) -> [u8; 32] {
    let text = std::fs::read_to_string(path).expect("read keypair file");
    let bytes: Vec<u8> = serde_json::from_str(&text).expect("keypair is a JSON byte array");
    assert!(bytes.len() >= 32, "keypair must be >= 32 bytes");
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    seed
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 8 {
        eprintln!("usage: pay_client <payer_keypair.json> <seller_b58> <mint_b58> <amount> <decimals> <nonce> <rpc_url>");
        std::process::exit(2);
    }
    let seed = read_seed(&args[1]);
    let payer = Pubkey::new(pubkey_from_seed(&seed));
    let seller = Pubkey::from_base58(&args[2]).expect("seller b58");
    let mint = Pubkey::from_base58(&args[3]).expect("mint b58");
    let amount: u64 = args[4].parse().expect("amount");
    let decimals: u8 = args[5].parse().expect("decimals");
    let nonce = &args[6];
    let rpc_url = &args[7];

    let payer_ata = Pubkey::associated_token_address(&payer, &mint, &token_program());
    let seller_ata = Pubkey::associated_token_address(&seller, &mint, &token_program());

    // Recent blockhash from the cluster.
    let rpc = SolanaRpc::new(Ureq { url: rpc_url.clone() }).with_commitment(Commitment::Confirmed);
    let bh = rpc.get_latest_blockhash().expect("get blockhash").blockhash;

    // TransferChecked: [source, mint, dest, owner]; data = [12, amount(LE), decimals].
    let mut data = vec![TRANSFER_CHECKED_TAG];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let transfer = Instruction {
        program_id: token_program(),
        accounts: vec![
            AccountMeta::writable(payer_ata, false),
            AccountMeta::readonly(mint, false),
            AccountMeta::writable(seller_ata, false),
            AccountMeta::readonly(payer, true),
        ],
        data,
    };

    // A compute-budget preamble keeps fees predictable (x402 SVM scheme caps the
    // unit price; 1 micro-lamport is well under the ceiling).
    let ixs = vec![
        set_compute_unit_limit(50_000),
        set_compute_unit_price(1),
        transfer,
        memo_ix(&payer, nonce.as_bytes()),
    ];

    let msg = compile(&payer, &ixs, &bh).expect("compile");
    let body = msg.serialize_legacy();
    let sig = sign_message(&seed, &body);
    let raw_tx = serialize_transaction(&[sig], &body);

    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_tx);
    let envelope = serde_json::json!({
        "x402Version": 2,
        "payload": { "transaction": tx_b64 }
    });
    // Print ONLY the header value on stdout so it can be captured directly.
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(envelope.to_string())
    );
}
