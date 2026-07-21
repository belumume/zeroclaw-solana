//! `token-risk-check` — a ZeroClaw tool plugin that grades an SPL / Token-2022
//! mint RED/AMBER/GREEN from its on-chain state (authorities + Token-2022 TLV
//! extensions), corroborated by RugCheck. Read-only (custody tier T0): no keys,
//! no signing, no transactions.
//!
//! Pure-core / thin-shim: [`risk`] is host-testable with no wasm toolchain; the
//! `#[cfg(target_family = "wasm")]` component shim below wires it to `wasi:http`
//! via the shared `solana-core` WakiTransport and the tool-plugin WIT world.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod risk;

pub use risk::{assess, compose_report, parse_and_validate, RiskAssessment, RiskLevel};

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

    use crate::risk;
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_core::{decode_mint, pubkey, short_pubkey, SolanaRpc, WakiTransport};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    struct TokenRiskCheck;

    const PLUGIN_NAME: &str = "token-risk-check";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "token_risk_check";
    const RUGCHECK_BASE: &str = "https://api.rugcheck.xyz";

    impl PluginInfo for TokenRiskCheck {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }
        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for TokenRiskCheck {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Grade an SPL or Token-2022 mint RED/AMBER/GREEN from its on-chain state: permanent \
             delegate, transfer hook, default-frozen accounts, transfer fees, freeze/mint \
             authorities, plus RugCheck corroboration. Read-only: holds no keys and builds no \
             transactions. Input: the mint ADDRESS (base58) — never a token symbol, symbols can \
             be faked."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "mint": {
                        "type": "string",
                        "description": "Base58 mint address of the token to check (not a symbol)."
                    }
                },
                "required": ["mint"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            // ALL validation happens in the pure core, before any network call:
            // a prompt-injected non-address cannot reach an RPC or crafted URL,
            // and a misspelled/unknown config key fails closed.
            let v = match risk::parse_and_validate(&args) {
                Ok(v) => v,
                Err(e) => return Ok(fail(e)),
            };

            let rpc = SolanaRpc::new(WakiTransport::new(&v.rpc_url));
            let acct = match rpc.get_account_info(&v.mint) {
                Ok(Some(a)) => a,
                Ok(None) => return Ok(fail(format!("mint account not found: {}", v.mint_b58))),
                Err(e) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "rpc fetch failed",
                    );
                    return Ok(fail(format!("rpc error: {e:?}")));
                }
            };

            let token_2022 = acct.owner == pubkey::token_2022_program();
            if !token_2022 && acct.owner != pubkey::token_program() {
                return Ok(fail(format!(
                    "not an SPL token mint (owner {})",
                    acct.owner.to_base58()
                )));
            }

            let decoded = match decode_mint(&acct.data, token_2022) {
                Ok(d) => d,
                Err(e) => return Ok(fail(format!("mint decode failed (fail-closed): {e:?}"))),
            };
            let assessment = risk::assess(&decoded);
            let rug = fetch_rugcheck(&v.mint_b58);

            emit(
                PluginAction::Complete,
                PluginOutcome::Success,
                assessment.level.label(),
            );
            Ok(ToolResult {
                success: true,
                output: risk::compose_report(
                    &short_pubkey(&v.mint_b58),
                    &decoded,
                    &assessment,
                    rug.as_ref(),
                ),
                error: None,
            })
        }
    }

    /// RugCheck is corroboration only: any failure (network, rate limit — it
    /// allows ~15 requests per window — or shape drift) degrades to `None` and
    /// the on-chain verdict stands alone, stated honestly in the report.
    fn fetch_rugcheck(mint: &str) -> Option<risk::RugSummary> {
        let url = format!("{RUGCHECK_BASE}/v1/tokens/{mint}/report/summary");
        let resp = waki::Client::new()
            .get(&url)
            .header("Accept", "application/json")
            .connect_timeout(std::time::Duration::from_secs(10))
            .send()
            .ok()?;
        if !(200..300).contains(&resp.status_code()) {
            return None;
        }
        let v = resp.json::<serde_json::Value>().ok()?;
        // parse_rugcheck returns None when the body has no `risks` array (an
        // error object served with 200, schema drift): degrade to "unavailable",
        // never a false clean corroboration.
        risk::parse_rugcheck(&v)
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
                function_name: "token_risk_check::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    export!(TokenRiskCheck);
}
