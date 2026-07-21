//! `lending-health` — a ZeroClaw tool plugin that reports Kamino Lend
//! liquidation health for a wallet. Read-only (custody tier T0): no keys, no
//! signing, no transactions. It fetches `GET /portfolio/{wallet}` over
//! `http_client` and returns a compact health verdict.
//!
//! Pure-core / thin-shim: [`health`] is host-testable with no wasm toolchain;
//! the `#[cfg(target_family = "wasm")]` component shim below wires it to
//! `wasi:http` via `waki` and the tool-plugin WIT world.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod health;

pub use health::{HealthReport, HealthStatus, PositionHealth};

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

    use crate::health::HealthReport;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct LendingHealth;

    const PLUGIN_NAME: &str = "lending-health";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "kamino_lending_health";
    const KAMINO_BASE: &str = "https://api.kamino.finance";

    // deny_unknown_fields for fail-closed parity with the two sibling plugins:
    // an injected extra field (e.g. a `__config` override or a `drain_to`) is
    // rejected instead of silently accepted.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        wallet: String,
    }

    impl PluginInfo for LendingHealth {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for LendingHealth {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Report Kamino Lend liquidation health for a Solana wallet. Read-only: holds no keys and \
             builds no transactions. Returns each borrowing position's status \
             (Safe/Warning/Critical/Liquidatable), how close it sits to its liquidation threshold, and \
             the borrowed assets. Input: a base58 wallet address."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "wallet": {
                        "type": "string",
                        "description": "Base58 Solana wallet address to check."
                    }
                },
                "required": ["wallet"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => return Ok(fail(format!("invalid arguments: {e}"))),
            };

            // Validate the wallet is a real base58 pubkey BEFORE any network
            // call: a prompt-injected non-address cannot reach an attacker URL.
            let wallet = parsed.wallet.trim();
            if solana_core::Pubkey::from_base58(wallet).is_err() {
                return Ok(fail(format!(
                    "not a valid base58 wallet address: {}",
                    solana_core::sanitize_onchain(wallet, 64).text
                )));
            }

            let url = format!("{KAMINO_BASE}/portfolio/{wallet}");
            let value = match fetch_json(&url) {
                Ok(v) => v,
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "kamino fetch failed",
                    );
                    return Ok(fail(format!("could not reach Kamino: {e}")));
                }
            };

            let report = HealthReport::from_value(&value);
            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                report.worst.label(),
            );
            Ok(ToolResult {
                success: true,
                output: report.to_compact_text(&solana_core::short_pubkey(wallet)),
                error: None,
            })
        }
    }

    /// GET a URL and parse the JSON body. Rejects non-2xx before parsing, and
    /// surfaces at most a 200-char snippet of an error body so an operator sees
    /// the API's own message without flooding agent context.
    /// The host performs TLS; this plugin only declares `http_client`.
    fn fetch_json(url: &str) -> Result<serde_json::Value, String> {
        let resp = waki::Client::new()
            .get(url)
            .header("Accept", "application/json")
            .connect_timeout(std::time::Duration::from_secs(10))
            .send()
            .map_err(|e| format!("request failed: {e}"))?;
        let status = resp.status_code();
        if !(200..300).contains(&status) {
            let snippet: String = resp
                .body()
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default()
                .chars()
                .take(200)
                .collect();
            return Err(format!("HTTP {status}: {snippet}"));
        }
        resp.json::<serde_json::Value>()
            .map_err(|e| format!("invalid JSON body: {e}"))
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
                function_name: "lending_health::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(LendingHealth);
}
