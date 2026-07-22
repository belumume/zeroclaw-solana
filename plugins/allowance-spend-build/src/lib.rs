//! `allowance-spend-build` -- a ZeroClaw tool plugin that builds an UNSIGNED
//! versioned (v0) transaction spending under a Solana Foundation Subscriptions &
//! Allowances delegation. The agent is the delegatee; the amount cap, per-period
//! accounting, and expiry are enforced ON-CHAIN by the Cantina/Spearbit-audited
//! program (`De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44`), so even a fully
//! prompt-injected agent cannot exceed the allowance. The plugin reads the
//! on-chain delegation (auto-detecting fixed vs recurring), fails closed unless
//! the agent is the delegatee, converts the amount exactly, derives + idempotently
//! creates the receiver token account, and (durable-nonce mode) fronts the
//! transaction with an advance-nonce so the unsigned tx survives an approval queue.
//!
//! Custody tier T1 (unsigned-transaction builder), doubly bounded. Secrets held:
//! None. The plugin holds no wallet and touches no private key; it returns a base64
//! UNSIGNED transaction (every signature slot empty) plus a human-readable summary
//! the host completes with the agent's key and broadcasts. The plugin output alone
//! can never be submitted, and the audited on-chain program caps the spend a second
//! time -- the agent proposes; an audited on-chain allowance disposes.
//!
//! Pure-core / thin-shim: [`allowance`] holds all validation, the audited program's
//! instruction encoding (known-answer-validated against the program source), and the
//! transport-generic RPC orchestration, and is host-tested with `MockTransport` (no
//! wasm toolchain, no network). The `#[cfg(target_family = "wasm")]` component below
//! only wires the shared solana-core `waki` transport to [`allowance::build_spend`].
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod allowance;

pub use allowance::{
    build_spend, build_unsigned_tx, decode_delegation, parse_and_validate, render_output,
    to_base_units, BlockhashMode, Cap, DecodedDelegation, DelegationKind, OutputMeta, SpendResolved,
    ValidatedSpend,
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

    use crate::allowance;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_core::{SolanaRpc, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct AllowanceSpendBuild;

    const PLUGIN_NAME: &str = "allowance-spend-build";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "allowance_spend_build";

    impl PluginInfo for AllowanceSpendBuild {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for AllowanceSpendBuild {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Build an UNSIGNED versioned (v0) transaction that spends under a Solana Foundation \
             Subscriptions & Allowances delegation, for a human approval gate to review and the host \
             to sign. The agent is the delegatee: this reads the on-chain delegation (auto-detecting \
             fixed one-time vs recurring per-period), fails closed unless the agent is the delegatee, \
             converts the amount to exact base units, derives + idempotently creates the receiver's \
             token account, and supports durable-nonce mode so the unsigned tx never expires in an \
             approval queue. The amount cap, period accounting, and expiry are enforced ON-CHAIN by \
             the Cantina/Spearbit-audited program, so even a prompt-injected agent cannot exceed the \
             allowance. The plugin holds no wallet and moves no funds -- it returns base64 + a \
             human-readable summary. Inputs: delegation (base58 delegation account), amount (UI-unit \
             decimal string, exact), receiver (base58 wallet), optional memo."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "delegation": {
                        "type": "string",
                        "description": "Base58 address of the fixed or recurring Subscriptions & Allowances delegation account the agent is the delegatee of."
                    },
                    "amount": {
                        "type": ["string", "number"],
                        "description": "Amount to spend in UI units as an exact decimal (string preferred): 25 = 25 USDC. Never lamports/raw. Capped on-chain by the delegation."
                    },
                    "receiver": {
                        "type": "string",
                        "description": "Base58 receiver WALLET address (not a token account); its associated token account is derived and idempotently created if absent."
                    },
                    "memo": {
                        "type": "string",
                        "description": "Optional on-chain memo for invoice reconciliation (sanitized + byte-capped)."
                    }
                },
                "required": ["delegation", "amount", "receiver"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // All validation + fail-closed gates run in the pure core BEFORE any
            // network call, and no key material is ever touched (T1).
            let v = match allowance::parse_and_validate(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(e)),
            };

            let rpc = SolanaRpc::new(WakiTransport::new(&v.rpc_url));

            // The transport-generic orchestration (host-tested with MockTransport)
            // does the getAccountInfo / getLatestBlockhash lookups and compiles the
            // UNSIGNED transaction. The wasm shim only supplies the waki transport.
            let (tx, meta) = match allowance::build_spend(&rpc, &v) {
                Ok(x) => x,
                Err(e) => {
                    emit(PluginAction::Fail, PluginOutcome::Failure, "build failed");
                    return Ok(fail(e));
                }
            };

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                meta.kind.as_str(),
            );
            Ok(ToolResult {
                success: true,
                output: allowance::render_output(&v, &tx, &meta),
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
                function_name: "allowance_spend_build::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(AllowanceSpendBuild);
}
