//! `payment-watch` is a ZeroClaw tool plugin that watches an address for an
//! expected inbound payment (SPL / Token-2022 / native SOL) and returns a
//! compact PAID / NOT_YET verdict. One `execute()` call is one CHECK; a NOT_YET
//! carries the newest signature as a cursor so a ZeroClaw cron SOP can poll
//! cheaply. Read-only (custody tier T0): no keys, no signing, no transactions.
//!
//! It closes the loop on the pay/publish plugins: the agent kicks off a payment
//! (or waits on an invoice), then this fires an inbound event the moment the
//! expected amount + reference lands: "Invoice #412 paid -> 25 USDC from 7xK..".
//!
//! Pure-core / thin-shim: [`watch`] is host-testable with no wasm toolchain; the
//! `#[cfg(target_family = "wasm")]` component shim below wires it to `wasi:http`
//! via the shared `solana-core` WakiTransport and the tool-plugin WIT world.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod watch;

pub use watch::{
    compose_report, find_payment, parse_and_validate, Asset, PaymentMatch, ValidatedArgs, Verdict,
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

    use crate::watch;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_core::WakiTransport;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct PaymentWatch;

    const PLUGIN_NAME: &str = "payment-watch";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "payment_watch";

    impl PluginInfo for PaymentWatch {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for PaymentWatch {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Watch an address for an expected inbound payment and report when it lands. One call \
             is one check: given a recipient address, an expected amount, and (optionally) a mint, \
             a Solana-Pay reference, an invoice label, and a signature cursor, it scans recent \
             transactions to the address for a matching inbound SPL / Token-2022 or native SOL \
             transfer. Returns PAID (amount, sender, tx signature, when) or NOT_YET with the newest \
             signature as a cursor so a cron SOP can poll cheaply. Read-only: holds no keys and \
             builds no transactions. Amounts are UI units (25 = 25 USDC); addresses are base58."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Base58 recipient address (wallet) to watch."
                    },
                    "expected_amount": {
                        "type": "number",
                        "description": "Expected inbound amount in UI units (e.g. 25 for 25 USDC, 0.5 for 0.5 SOL). Matched exactly."
                    },
                    "mint": {
                        "type": "string",
                        "description": "Optional. Base58 SPL / Token-2022 mint. Omit for USDC. Use \"SOL\" or \"native\" for native SOL lamports."
                    },
                    "reference": {
                        "type": "string",
                        "description": "Optional base58 reference pubkey (Solana Pay); when set it must appear in the matched transaction's account keys."
                    },
                    "invoice_label": {
                        "type": "string",
                        "description": "Optional human label for the report (e.g. \"Invoice #412\")."
                    },
                    "since_signature": {
                        "type": "string",
                        "description": "Optional cursor: only transactions newer than this signature are considered. Feed back the cursor from a prior NOT_YET for cheap polling."
                    }
                },
                "required": ["address", "expected_amount"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // ALL validation happens in the pure core, before any network call:
            // a prompt-injected non-address can never reach an RPC or crafted
            // URL, and a misspelled/unknown config key fails closed.
            let v = match watch::parse_and_validate(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(e)),
            };

            let transport = WakiTransport::new(&v.rpc_url);
            let verdict = match watch::find_payment(&transport, &v) {
                Ok(vd) => vd,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "rpc fetch failed",
                    );
                    return Ok(fail(format!("rpc error: {e:?}")));
                }
            };

            // A landed payment is reported as an INBOUND event, per the loop this
            // plugin closes; a no-match is a normal COMPLETE.
            let (action, message) = match &verdict {
                watch::Verdict::Paid(_) => (PluginAction::Inbound, "payment detected"),
                watch::Verdict::NotYet { .. } => (PluginAction::Complete, "no matching payment yet"),
            };
            emit(action, PluginOutcome::Success, message);

            Ok(ToolResult {
                success: true,
                output: watch::compose_report(&v, &verdict),
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
                function_name: "payment_watch::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(PaymentWatch);
}
