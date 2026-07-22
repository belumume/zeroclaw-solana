//! `spl-transfer-build` -- a ZeroClaw tool plugin that builds an UNSIGNED
//! versioned (v0) SPL-token or native-SOL transfer for a human approval gate. It
//! derives and idempotently creates the recipient's associated token account,
//! attaches an on-chain memo for invoice reconciliation, appends reference keys
//! so a payment watcher can locate the transfer, and (in durable-nonce mode)
//! fronts the transaction with an advance-nonce so the unsigned tx survives an
//! approval queue indefinitely.
//!
//! Custody tier T1 (unsigned-transaction builder). Secrets held: None. The plugin
//! holds no wallet and touches no private key; it returns a base64 UNSIGNED
//! transaction (every signature slot empty) plus a human-readable summary the
//! host completes with the operator's key and broadcasts. The plugin output alone
//! can never be submitted, so a compromised plugin can never move funds.
//!
//! Pure-core / thin-shim: [`transfer`] holds all validation, instruction
//! encoding, and the transport-generic RPC orchestration, and is host-tested with
//! `MockTransport` (no wasm toolchain, no network). The
//! `#[cfg(target_family = "wasm")]` component below only wires the shared
//! solana-core `waki` transport to [`transfer::build_transfer`].
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod transfer;

pub use transfer::{
    build_transfer, build_unsigned_tx, parse_and_validate, render_output, to_base_units, Asset,
    BlockhashMode, OutputMeta, ValidatedTransfer,
};

// wit-bindgen generates the C-ABI export glue, which is necessarily `unsafe`.
// Our own code stays unsafe-free; the allow is scoped to the generated module.
#[cfg(target_family = "wasm")]
#[allow(unsafe_code)]
mod component {
    wit_bindgen::generate!({
        path: "../../wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use crate::transfer;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_core::{SolanaRpc, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct SplTransferBuild;

    const PLUGIN_NAME: &str = "spl-transfer-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "spl_transfer_build";

    impl PluginInfo for SplTransferBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SplTransferBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED versioned (v0) transaction that transfers an SPL token or native SOL \
             to a recipient, for a human approval gate to review and the host to sign. Derives and \
             idempotently creates the recipient's associated token account, uses transfer_checked \
             (decimals validated on-chain), attaches an on-chain memo for invoice reconciliation, \
             and appends reference keys a payment watcher can detect. Supports durable-nonce mode so \
             the unsigned transaction never expires while it sits in an approval queue. The plugin \
             holds no wallet and moves no funds -- it returns base64 + a human-readable summary. \
             Inputs: recipient (base58 wallet), amount (UI-unit decimal string, exact), mint (base58 \
             or 'SOL'/'native'), optional memo and reference(s)."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Base58 recipient WALLET address (not an associated token account)."
                    },
                    "amount": {
                        "type": ["string", "number"],
                        "description": "Amount in UI units as an exact decimal (string preferred): 25 = 25 USDC, 0.5 = 0.5 SOL. Never lamports/raw."
                    },
                    "mint": {
                        "type": "string",
                        "description": "Base58 SPL/Token-2022 mint address, or the sentinel 'SOL'/'native' for a native SOL transfer."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional on-chain memo for invoice reconciliation (sanitized + byte-capped)."
                    },
                    "reference": {
                        "type": ["string", "array"],
                        "items": { "type": "string" },
                        "description": "Optional base58 reference key(s) appended as read-only keys so a payment watcher can locate the transfer."
                    }
                },
                "required": ["recipient", "amount", "mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // All validation + fail-closed gates run in the pure core BEFORE any
            // network call, and no key material is ever touched (T1).
            let v = match transfer::parse_and_validate(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(e)),
            };

            let rpc = SolanaRpc::new(WakiTransport::new(&v.rpc_url));

            // The transport-generic orchestration (host-tested with MockTransport)
            // does the getAccountInfo / getLatestBlockhash lookups and compiles the
            // UNSIGNED transaction. The wasm shim only supplies the waki transport.
            let (tx, meta) = match transfer::build_transfer(&rpc, &v) {
                Ok(x) => x,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "build failed");
                    return Ok(fail(e));
                }
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                meta.mode.as_str(),
            );
            Ok(ToolResult {
                success: true,
                output: transfer::render_output(&v, &tx, &meta),
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
                function_name: "spl_transfer_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(SplTransferBuild);
}
