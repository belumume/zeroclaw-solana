//! Deterministic, LLM-free DePIN feed publisher.
//!
//! Reuses the plugin's REAL `oracle_publish::publish::compile_and_device_sign`
//! (same bytes the wasm plugin emits): the device signs its own reading with its
//! own key; the host session key completes the fee-payer slot and broadcasts.
//! No agent, no model in the durability loop -> the feed climbs deterministically.
//! One-shot: creates the durable nonce if missing, registers the device feed if
//! missing, then publishes the next monotonic sequence.
//!
//! Env:
//!   FEED_RPC            default https://api.devnet.solana.com
//!   FEED_SESSION        keypair.json (fee payer + nonce authority + registrar)
//!   FEED_DEVICE_SEED_HEX 64 hex chars (the device signing seed we control)
//!   FEED_NONCE          keypair.json for the durable nonce account
//!   FEED_ORACLE_ID      the zeroclaw_oracle program id
//!   FEED_VALUE          i64 reading at scale -2 (e.g. 4190 = 41.90 C)
//!   FEED_OBSERVED_AT    unix seconds i64
use borsh::BorshDeserialize;
use solana_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Signer};
#[allow(deprecated)]
use solana_sdk::system_instruction;
use solana_sdk::transaction::Transaction;
use std::str::FromStr;

#[derive(BorshDeserialize)]
struct DeviceFeed {
    _authority: [u8; 32],
    _device: [u8; 32],
    _feed_kind: u8,
    value: i64,
    _scale: i8,
    _unit: [u8; 12],
    sequence: u64,
    _observed_at: i64,
    _published_at: i64,
    _bump: u8,
}

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("missing env {k}"))
}

fn read_feed(rpc: &RpcClient, pda: &Pubkey) -> Option<DeviceFeed> {
    let data = rpc.get_account_data(pda).ok()?;
    DeviceFeed::try_from_slice(&data[8..]).ok()
}

fn main() {
    let rpc_url =
        std::env::var("FEED_RPC").unwrap_or_else(|_| "https://api.devnet.solana.com".into());
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
    let session = read_keypair_file(env("FEED_SESSION")).expect("read session keypair");
    let oracle = Pubkey::from_str(&env("FEED_ORACLE_ID")).unwrap();
    let seed_hex = env("FEED_DEVICE_SEED_HEX");
    let device_seed: [u8; 32] = {
        let mut s = [0u8; 32];
        for i in 0..32 {
            s[i] = u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).expect("hex seed");
        }
        s
    };
    let device = Pubkey::new_from_array(solana_core::pubkey_from_seed(&device_seed));
    let nonce_kp = read_keypair_file(env("FEED_NONCE")).expect("read nonce keypair");
    let value: i64 = env("FEED_VALUE").parse().expect("FEED_VALUE i64");
    let observed_at: i64 = env("FEED_OBSERVED_AT")
        .parse()
        .expect("FEED_OBSERVED_AT i64");

    // 1. durable nonce account (authority = session), create if missing
    if rpc.get_account(&nonce_kp.pubkey()).is_err() {
        let rent = rpc
            .get_minimum_balance_for_rent_exemption(solana_sdk::nonce::State::size())
            .unwrap();
        let ixs = system_instruction::create_nonce_account(
            &session.pubkey(),
            &nonce_kp.pubkey(),
            &session.pubkey(),
            rent,
        );
        let bh = rpc.get_latest_blockhash().unwrap();
        let tx = Transaction::new_signed_with_payer(
            &ixs,
            Some(&session.pubkey()),
            &[&session, &nonce_kp],
            bh,
        );
        rpc.send_and_confirm_transaction(&tx).expect("create nonce");
        eprintln!("created durable nonce account {}", nonce_kp.pubkey());
    }

    // 2. register the device feed if missing (admin = session)
    let (feed_pda, _bump) = Pubkey::find_program_address(&[b"feed", device.as_ref()], &oracle);
    if read_feed(&rpc, &feed_pda).is_none() {
        let mut data = solana_core::instruction_sighash("register_device").to_vec();
        data.push(0u8); // temperature_c
        let reg = Instruction {
            program_id: oracle,
            accounts: vec![
                AccountMeta::new(feed_pda, false),
                AccountMeta::new_readonly(device, false),
                AccountMeta::new(session.pubkey(), true),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            ],
            data,
        };
        let bh = rpc.get_latest_blockhash().unwrap();
        let tx =
            Transaction::new_signed_with_payer(&[reg], Some(&session.pubkey()), &[&session], bh);
        rpc.send_and_confirm_transaction(&tx)
            .expect("register device");
        eprintln!("registered device feed {feed_pda} (device {device})");
    }

    // 3. next monotonic sequence = on-chain sequence + 1
    let seq = read_feed(&rpc, &feed_pda).expect("feed exists").sequence + 1;

    // 4. publish via the plugin's REAL core: device signs, host completes fee-payer
    let args = format!(
        r#"{{"feed_kind":"temperature_c","value":{value},"scale":-2,"unit":"C","observed_at":{observed_at},"sequence":{seq},"__config":{{"signer_seed_hex":"{seed_hex}","nonce_account":"{}","oracle_program_id":"{}","agent_session_pubkey":"{}"}}}}"#,
        nonce_kp.pubkey(),
        oracle,
        session.pubkey()
    );
    let v = oracle_publish::publish::parse_and_validate(&args).expect("validate");
    let nonce_acct = rpc.get_account(&nonce_kp.pubkey()).expect("get nonce");
    let ns = solana_core::decode_nonce_account(&nonce_acct.data).expect("decode nonce");
    let partial =
        oracle_publish::publish::compile_and_device_sign(&v, &ns.durable_nonce).expect("compile");
    let mut tx: Transaction = bincode::deserialize(&partial).expect("bincode tx");
    let msg = tx.message.serialize();
    tx.signatures[0] = session.sign_message(&msg);
    let sig = rpc.send_and_confirm_transaction(&tx).expect("send");

    let now = read_feed(&rpc, &feed_pda).expect("feed after publish");
    println!(
        "landed seq={} value={} tx=https://explorer.solana.com/tx/{}?cluster=devnet",
        now.sequence, now.value, sig
    );
    println!("feed_pda={feed_pda} device={device}");
}
