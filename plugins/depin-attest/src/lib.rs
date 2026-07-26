//! `depin-attest` — a ZeroClaw tool plugin that signs and broadcasts a
//! replay-proof on-chain attestation of a physical DePIN sensor reading.
//! Custody tier T2: it signs with a host-injected, scoped session key held in
//! jailed config; it holds no user wallet and can only ever produce ONE
//! transaction shape (advance-nonce + a sanitized attestation memo).
//!
//! Pure-core / thin-shim: [`attest`] is host-testable with no wasm toolchain;
//! the `#[cfg(target_family = "wasm")]` shim below adds only the RPC round-trip
//! (fetch nonce account -> compile -> sign -> send) via the shared solana-core.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod attest;

pub use attest::{parse_and_validate, Reading, ValidatedAttestation};

#[cfg(target_family = "wasm")]
#[allow(unsafe_code)]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::attest;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_core::{
        decode_nonce_account, instruction, message, pubkey_from_seed, serialize_transaction,
        sign_message, Pubkey, SolanaRpc, WakiTransport,
    };
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct DepinAttest;

    const PLUGIN_NAME: &str = "depin-attest";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "depin_attest_reading";

    impl PluginInfo for DepinAttest {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for DepinAttest {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Sign and broadcast a replay-proof on-chain attestation that a physical sensor observed \
             an event (motion, contact, tamper). Uses a durable nonce so each attestation is \
             single-use: a replayed transaction is rejected by the chain. Signs with a scoped \
             session key from operator config — holds no user wallet. Inputs: reading (allowlisted \
             event id), device_id, observed_at (unix seconds)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "reading": {
                        "type": "string",
                        "enum": [
                            "motion_detected", "motion_cleared",
                            "contact_opened", "contact_closed", "tamper_triggered"
                        ],
                        "description": "The physical event observed (allowlisted)."
                    },
                    "device_id": { "type": "string", "description": "Sensor/device identifier." },
                    "observed_at": { "type": "integer", "description": "Unix seconds of the reading." }
                },
                "required": ["reading", "device_id", "observed_at"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // ALL validation + the fail-closed safety gates run in the pure core
            // BEFORE any key is touched or any network call is made.
            let v = match attest::parse_and_validate(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(e)),
            };

            let signer = pubkey_from_seed(&v.signer_seed);
            let signer_pk = Pubkey::new(signer);
            let rpc = SolanaRpc::new(WakiTransport::new(&v.rpc_url));

            // Fetch the durable-nonce account; its STORED nonce is the blockhash.
            let nonce_acct = match rpc.get_account_info(&v.nonce_account) {
                Ok(Some(a)) => a,
                Ok(None) => return Ok(fail("nonce account not found on chain".to_string())),
                Err(e) => return Ok(fail(format!("rpc error fetching nonce: {e:?}"))),
            };
            let nonce_state = match decode_nonce_account(&nonce_acct.data) {
                Ok(s) => s,
                Err(e) => return Ok(fail(format!("nonce account decode failed: {e:?}"))),
            };
            // The signer must be the nonce authority, or the tx cannot advance it.
            if nonce_state.authority != signer_pk {
                return Ok(fail(
                    "scoped signer is not the nonce authority: refusing to sign".to_string(),
                ));
            }

            // advance-nonce MUST be instruction 0; then the attestation memo.
            let ixs = [
                instruction::advance_nonce_account(&v.nonce_account, &signer_pk),
                instruction::memo(&signer_pk, v.memo_payload.as_bytes()),
            ];
            let msg = match message::compile(&signer_pk, &ixs, &nonce_state.durable_nonce) {
                Ok(m) => m,
                Err(e) => return Ok(fail(format!("message compile failed: {e:?}"))),
            };
            let msg_bytes = msg.serialize_legacy();
            let sig = sign_message(&v.signer_seed, &msg_bytes);
            let tx = serialize_transaction(&[sig], &msg_bytes);

            match rpc.send_transaction(&tx) {
                Ok(signature) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        v.reading.as_str(),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: attest::compose_report(&v, &signature),
                        error: None,
                    })
                }
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "broadcast failed",
                    );
                    Ok(fail(format!("broadcast failed: {e:?}")))
                }
            }
        }
    }

    fn fail(message: String) -> ToolResult {
        ToolResult {
            success: false,
            output: String::new(),
            error: Some(message),
        }
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "depin_attest::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(DepinAttest);
}
