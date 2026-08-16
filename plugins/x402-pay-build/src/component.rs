//! The wasm shim. Deliberately thin: it fetches, then calls the pure core in order.
//!
//! Everything that decides anything lives in [`crate::args`], [`crate::pay`], [`crate::resolve`]
//! and [`crate::compose`], all host-tested with no network. This module owns only the two things
//! that cannot be tested without a runtime: an HTTP GET and an RPC transport. Keeping it this
//! small is what makes "the security property is host-tested" a true sentence rather than a
//! hopeful one, because there is almost nothing here for a test to have missed.

#![allow(unsafe_code)] // wit-bindgen's generated C-ABI glue is necessarily unsafe; ours is not.

wit_bindgen::generate!({
    path: "../../wit/v0",
    world: "tool-plugin",
    features: ["plugins-wit-v0"],
});

use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
use solana_core::{Pubkey, SolanaRpc, WakiTransport};
use zeroclaw::plugin::logging::{log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome};

use crate::{args, compose, pay, resolve};

struct X402PayBuild;

const PLUGIN_NAME: &str = "x402-pay-build";
const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
const TOOL_NAME: &str = "x402_pay_build";
/// Production default. The operator overrides it via `__config.rpc_url`, https only.
const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";
/// A 402 body is small. A cap stops a hostile seller streaming until something falls over.
const MAX_CHALLENGE_BYTES: usize = 64 * 1024;

impl PluginInfo for X402PayBuild {
    fn plugin_name() -> String {
        PLUGIN_NAME.to_string()
    }
    fn plugin_version() -> String {
        PLUGIN_VERSION.to_string()
    }
}

impl Tool for X402PayBuild {
    fn name() -> String {
        TOOL_NAME.to_string()
    }

    fn description() -> String {
        "Decide whether an x402 402-Payment-Required challenge describes a payment the operator \
         authorised, and if so return the arguments for allowance_spend_build to turn into an \
         unsigned transaction. The payee, mint, network and funding delegation come from jailed \
         operator config and are CROSS-CHECKED against the challenge, because a challenge is \
         written by the party being paid and the on-chain delegation bounds amount rather than \
         payee. A mismatch fails closed. This tool holds no wallet, signs nothing, and builds no \
         transaction. Inputs: challenge_body OR challenge_url (https), and an optional tier index; \
         omit the tier to take the cheapest option that matches the configuration."
            .to_string()
    }

    fn parameters_schema() -> String {
        serde_json::json!({
            "type": "object",
            "properties": {
                "challenge_body": {
                    "type": "string",
                    "description": "The 402 response body as JSON text, if you already fetched it. Mutually exclusive with challenge_url."
                },
                "challenge_url": {
                    "type": "string",
                    "description": "An https URL to GET the 402 challenge from. Mutually exclusive with challenge_body. Plain http is refused."
                },
                "tier": {
                    "type": "integer",
                    "description": "Index into the challenge's accepts[] array. Omit to take the cheapest tier that matches the operator's configuration."
                }
            }
        })
        .to_string()
    }

    fn execute(args_json: String) -> Result<ToolResult, String> {
        // Every gate runs in the pure core BEFORE any network call, and no key material is ever
        // touched. Custody tier T1.
        let parsed = match args::parse(&args_json) {
            Ok(p) => p,
            Err(e) => return Ok(fail(e)),
        };

        let body = match &parsed.source {
            args::ChallengeSource::Body(b) => b.clone(),
            args::ChallengeSource::Url(u) => match fetch_challenge(u) {
                Ok(b) => b,
                Err(e) => return Ok(fail(e)),
            },
        };

        let challenge: pay::Challenge = match serde_json::from_str(&body) {
            Ok(c) => c,
            Err(e) => {
                return Ok(fail(format!(
                    "the 402 body is not a v2 challenge this can read: {e}"
                )))
            }
        };

        let authorised = match pay::authorise(&challenge, &parsed.cfg, parsed.tier) {
            Ok(a) => a,
            Err(e) => {
                emit(PluginAction::Fail, PluginOutcome::Failure, "refused");
                return Ok(fail(e));
            }
        };

        let mint = match Pubkey::from_base58(&authorised.mint) {
            Ok(m) => m,
            Err(_) => {
                return Ok(fail(
                    "the configured mint is not a valid address".to_string(),
                ))
            }
        };
        let rpc_url = parsed.rpc_url.as_deref().unwrap_or(DEFAULT_RPC);
        let rpc = SolanaRpc::new(WakiTransport::new(rpc_url));
        let decimals = match resolve::mint_decimals(&rpc, &mint) {
            Ok(d) => d,
            Err(e) => return Ok(fail(e)),
        };

        let spend = match compose::compose(&authorised, decimals) {
            Ok(s) => s,
            Err(e) => return Ok(fail(e)),
        };

        emit(PluginAction::Complete, PluginOutcome::Success, "authorised");
        Ok(ToolResult {
            success: true,
            output: compose::render_output(&authorised, &spend, decimals),
            error: None,
        })
    }
}

/// GET the 402 challenge. A 402 status is the EXPECTED one here, so it is not an error.
fn fetch_challenge(url: &str) -> Result<String, String> {
    let resp = waki::Client::new()
        .get(url)
        .header("Accept", "application/json")
        .connect_timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("could not reach {url}: {e}"))?;

    // 402 is the point of the exchange. 200 is accepted too, because a gate that has already been
    // paid answers with the resource, and reporting that as a failure would be misleading.
    let status = resp.status_code();
    if status != 402 && !(200..300).contains(&status) {
        return Err(format!(
            "{url} answered {status}, which is not a payment challenge"
        ));
    }
    let bytes = resp
        .body()
        .map_err(|e| format!("could not read the body: {e}"))?;
    if bytes.len() > MAX_CHALLENGE_BYTES {
        return Err(format!(
            "the 402 body is {} bytes, over the {MAX_CHALLENGE_BYTES} cap; a price list is small \
             and this one is not behaving like one",
            bytes.len()
        ));
    }
    String::from_utf8(bytes).map_err(|_| "the 402 body is not valid UTF-8".to_string())
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
            function_name: "x402_pay_build::tool::execute".to_string(),
            action,
            outcome: Some(outcome),
            duration_ms: None,
            attrs: None,
            message: message.to_string(),
        },
    );
}

export!(X402PayBuild);
