//! oracle-publish: a ZeroClaw tool-plugin that publishes a device-signed,
//! replay-proof sensor reading to an on-chain `zeroclaw_oracle` DeviceFeed that
//! downstream Solana programs consume. The plugin holds no wallet: it returns a
//! partially-signed (device-co-signed) transaction the host completes with the
//! agent's capped session key (T1), so a compromised plugin can never move funds.
//!
//! Pure-core / thin-shim: [`publish`] is host-testable with no wasm toolchain;
//! the `#[cfg(target_family = "wasm")]` component below adds only the RPC round-
//! trip (fetch the durable-nonce account -> compile -> device-sign) via the
//! shared solana-core, and returns the base64 partial transaction.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod publish;

pub use publish::{parse_and_validate, FeedKind, ValidatedPublish};

#[cfg(target_family = "wasm")]
#[allow(unsafe_code)]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::publish;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_core::{decode_nonce_account, SolanaRpc, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct OraclePublish;

    const PLUGIN_NAME: &str = "oracle-publish";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "oracle_publish_reading";

    impl PluginInfo for OraclePublish {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for OraclePublish {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Publish a device-signed sensor reading to an on-chain ZeroClaw device-oracle feed that \
             downstream Solana programs consume. A scoped device key co-signs the reading (proving \
             which physical device produced it); a durable nonce makes a replayed publish rejected by \
             the chain; a strictly-increasing sequence makes a stale reading rejected by the program. \
             The plugin holds no wallet and moves no funds -- it returns a base64 transaction the host \
             completes with the agent's capped session key and broadcasts. Inputs: feed_kind \
             (allowlisted), value, scale (-9..=0; real = value*10^scale), unit, observed_at, sequence."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "feed_kind": {
                        "type": "string",
                        "enum": ["temperature_c","humidity_pct","energy_kwh","pressure_hpa","co2_ppm","motion_count","generic_scaled"],
                        "description": "Allowlisted sensor feed kind."
                    },
                    "value": { "type": "integer", "description": "Fixed-point mantissa; real = value * 10^scale." },
                    "scale": { "type": "integer", "minimum": -9, "maximum": 0, "description": "Fixed-point exponent." },
                    "unit": { "type": "string", "description": "Short unit label (sanitized, <=12 bytes)." },
                    "observed_at": { "type": "integer", "description": "Unix seconds of the reading." },
                    "sequence": { "type": "integer", "description": "Strictly-increasing per-feed sequence." }
                },
                "required": ["feed_kind","value","scale","observed_at","sequence"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // All validation + the fail-closed safety gates run in the pure core
            // BEFORE any key material is touched or any network call is made.
            let v = match publish::parse_and_validate(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(e)),
            };

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
            // The FEE PAYER (agent session key) must be the nonce authority, or the
            // advance-nonce instruction cannot succeed. The device never pays.
            if nonce_state.authority != v.agent_session_pubkey {
                return Ok(fail(
                    "agent session key is not the nonce authority: refusing to build".to_string(),
                ));
            }

            // Device-co-sign; the fee-payer slot is left empty for the host.
            let partial_tx = match publish::compile_and_device_sign(&v, &nonce_state.durable_nonce)
            {
                Ok(tx) => tx,
                Err(e) => return Ok(fail(e)),
            };
            let b64 = STANDARD.encode(&partial_tx);

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                v.feed_kind.as_str(),
            );
            Ok(ToolResult {
                success: true,
                output: publish::compose_report(&v, &b64),
                error: None,
            })
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
                function_name: "oracle_publish::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(OraclePublish);
}
