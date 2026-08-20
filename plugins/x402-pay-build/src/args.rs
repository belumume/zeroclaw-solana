//! Parse the tool call, and keep the operator's settings out of the agent's reach.
//!
//! THE BOUNDARY THIS FILE DEFENDS. The payee, mint, network, delegation and ceiling come from
//! `__config`, which the host injects from the jailed operator configuration. Everything else in
//! the argument object is chosen by the AGENT, and an agent is the thing an injected challenge
//! influences. If a top-level `receiver` could reach [`crate::pay::PayConfig`], the whole
//! cross-check would be an agent arguing with itself.
//!
//! So a top-level key that shadows a config field is REFUSED, not ignored. Ignoring it silently is
//! worse than either accepting or refusing: the caller believes the value took effect, the payment
//! goes somewhere else, and nothing in the output says which value won.
//!
//! `challenge_body` and `challenge_url` are mutually exclusive because "fetch it yourself" and
//! "here is what I fetched" are different trust stories, and quietly preferring one hides which
//! bytes were actually checked.

use serde::Deserialize;

use crate::pay::{echo_field, PayConfig};

/// The refusal for a `challenge_url` GET that never completed.
///
/// It lives in the pure core rather than in the wasm shim that raises it, so it is host-testable;
/// the shim is the one module with no test coverage by construction. Same reason `lending-health`
/// keeps `invalid_arguments_message` beside its core.
///
/// The URL is bounded and the transport error is not. That split is deliberate: `url` is the
/// AGENT's argument and reaches this line having passed nothing but a `starts_with("https://")`
/// prefix test, so `https://` followed by forty kilobytes satisfies it; the transport error is the
/// host's own `waki` text about a connection it attempted.
pub fn unreachable_challenge_error(url: &str, transport_error: &str) -> String {
    format!("could not reach {}: {transport_error}", echo_field(url))
}

/// The refusal for a `challenge_url` that answered with a status that is not a payment challenge.
/// Bounded for the same reason as [`unreachable_challenge_error`]; the status is a `u16`.
pub fn unexpected_challenge_status_error(url: &str, status: u16) -> String {
    format!(
        "{} answered {status}, which is not a payment challenge",
        echo_field(url)
    )
}

/// The operator's settings, injected by the host under `__config`. Never agent-supplied.
///
/// THAT CLAIM IS HOST-ENFORCED AND WAS VERIFIED AGAINST UPSTREAM SOURCE, not assumed. An audit
/// rated it a HIGH on the reasoning that `__config` is a normal serde field, so `deny_unknown_fields`
/// ADMITS it rather than excluding it: if a model could supply the section, the payee cross-check
/// below would compare a challenge against values the same model chose, and the strongest
/// money-binding control in the suite would be self-referential.
///
/// It does not hold. `inject_config` in the host's `crates/zeroclaw-plugins/src/runtime.rs` calls
/// `obj.remove("__config")` on the caller's args BEFORE inserting the resolved operator config, so
/// a forged section is stripped unconditionally rather than merged. Its own doc comment says
/// "stripping any caller-supplied `__config` so the section cannot be spoofed", and two of its
/// tests pin both directions. Where the operator has no config section for a plugin the key is
/// absent entirely, which `parse` below refuses; that is fail-closed, not a gap.
///
/// This is an UPSTREAM guarantee, so it can drift the way the vendored WIT did. If that stripping
/// is ever weakened, no plugin can defend itself against a forged config and every payee check
/// here becomes decorative. `host-drift.yml` already clones upstream daily for interface parity
/// and is the natural place to assert this too.
#[derive(Debug, Clone, Deserialize)]
struct InjectedConfig {
    receiver: Option<String>,
    mint: Option<String>,
    network: Option<String>,
    delegation: Option<String>,
    /// Atomic base units, as a decimal string so a JSON number cannot lose precision.
    max_amount: Option<String>,
    rpc_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawArgs {
    challenge_body: Option<String>,
    challenge_url: Option<String>,
    tier: Option<usize>,
    #[serde(rename = "__config", default)]
    config: Option<InjectedConfig>,
    /// Captured ONLY so a shadowing attempt can be refused by name rather than ignored.
    receiver: Option<String>,
    mint: Option<String>,
    network: Option<String>,
    delegation: Option<String>,
    max_amount: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeSource {
    /// Bytes the caller already holds.
    Body(String),
    /// An https URL for the shim to GET. Plain http is refused: a 402 challenge names where money
    /// goes, and reading it over a channel anyone can rewrite defeats the cross-check by making
    /// the "seller's" answer whatever the network says it is.
    Url(String),
}

#[derive(Debug, Clone)]
pub struct ParsedArgs {
    pub source: ChallengeSource,
    pub tier: Option<usize>,
    pub cfg: PayConfig,
    pub rpc_url: Option<String>,
}

/// Field names that exist in `__config` and must never be honoured at the top level.
const CONFIG_ONLY: [&str; 5] = ["receiver", "mint", "network", "delegation", "max_amount"];

pub fn parse(json: &str) -> Result<ParsedArgs, String> {
    // `RawArgs` is a TYPED struct, so this is not a syntax-only failure: serde's `invalid type`
    // message embeds the offending value VERBATIM. MEASURED on this crate's own `Challenge` shape,
    // which fails the same way: a 2,000-codepoint value produced an 8,058-byte error. Bounded
    // rather than trusted.
    let raw: RawArgs = serde_json::from_str(json).map_err(|e| {
        format!(
            "arguments are not valid JSON: {}",
            crate::pay::sanitize_arg_error(&e.to_string())
        )
    })?;

    // Shadowing is refused BY NAME, so the message tells the caller exactly what to move.
    let shadowed: Vec<&str> = CONFIG_ONLY
        .iter()
        .zip([
            raw.receiver.as_ref(),
            raw.mint.as_ref(),
            raw.network.as_ref(),
            raw.delegation.as_ref(),
            raw.max_amount.as_ref(),
        ])
        .filter_map(|(name, v)| v.map(|_| *name))
        .collect();
    // NOT ECHO-BOUNDED, deliberately: `shadowed` holds `&'static str` NAMES from `CONFIG_ONLY`,
    // never the caller's values. The caller chooses WHICH of five literals appear and nothing else,
    // so the widest this message can be is the five of them joined.
    if !shadowed.is_empty() {
        return Err(format!(
            "{} supplied as a tool argument, and {} operator configuration. These come from \
             `__config` only: an agent that could set them would be cross-checking a challenge \
             against values the same challenge influenced",
            shadowed.join(", "),
            if shadowed.len() == 1 {
                "it is"
            } else {
                "they are"
            }
        ));
    }

    let source =
        match (raw.challenge_body, raw.challenge_url) {
            (Some(_), Some(_)) => return Err(
                "give either challenge_body or challenge_url, not both; they are different trust \
                 stories and preferring one silently hides which bytes were checked"
                    .to_string(),
            ),
            (Some(b), None) if !b.trim().is_empty() => ChallengeSource::Body(b),
            (None, Some(u)) => {
                // BOUNDED, and this is the site where the inversion is easiest to miss. On the
                // ACCEPTED path `u` is an https URL and short; this branch fires precisely BECAUSE
                // it is not one, so nothing has constrained it. The refusal echoed it raw.
                if !u.starts_with("https://") {
                    return Err(format!(
                    "challenge_url {} is not https. A 402 challenge names where money goes, so \
                     reading it over a channel anyone can rewrite defeats the cross-check",
                    echo_field(&u)
                ));
                }
                ChallengeSource::Url(u)
            }
            _ => return Err("give one of challenge_body or challenge_url".to_string()),
        };

    let c = raw.config.ok_or(
        "no `__config` was injected; this tool cannot authorise a payment without the \
                operator's receiver, mint, network and delegation",
    )?;

    // NOT ECHO-BOUNDED, deliberately: `name` is one of five string LITERALS this function passes
    // in, never a caller value.
    let need = |v: Option<String>, name: &str| -> Result<String, String> {
        v.filter(|s| !s.trim().is_empty())
            .ok_or_else(|| format!("`__config.{name}` is missing, and it has no safe default"))
    };
    let max_amount = need(c.max_amount, "max_amount")?;
    // NOT ECHO-BOUNDED, deliberately, and this is the one refusal in this file where the decision
    // turned on provenance rather than on shape. `max_amount` is `__config`, which the host injects
    // from the jailed operator configuration AFTER removing any caller-supplied section (see
    // `InjectedConfig` above, where that claim is checked against upstream source). So this echoes
    // the operator's own value back to the operator, who is the only reader of it, and capping it
    // would cost them the `…` marker that distinguishes a truncated paste from a mistyped one.
    // Verified per site rather than assumed: there is no path by which an agent or a seller reaches
    // this string, and if `inject_config` ever stops stripping, EVERY payee check in this crate
    // becomes decorative long before this echo matters.
    let max_amount = max_amount.parse::<u64>().map_err(|_| {
        format!("`__config.max_amount` is {max_amount:?}, not a decimal count of atomic base units")
    })?;
    if max_amount == 0 {
        return Err("`__config.max_amount` is 0, which authorises nothing".to_string());
    }

    Ok(ParsedArgs {
        source,
        tier: raw.tier,
        cfg: PayConfig {
            receiver: need(c.receiver, "receiver")?,
            mint: need(c.mint, "mint")?,
            network: need(c.network, "network")?,
            delegation: need(c.delegation, "delegation")?,
            max_amount,
        },
        rpc_url: c.rpc_url.filter(|s| s.starts_with("https://")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_json() -> String {
        serde_json::json!({
            "receiver": "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ",
            "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "delegation": "HVVeimGq8VD4CuBgrvqWsgQV1GRVhfVNYQxJxTocUNY9",
            "max_amount": "1000000",
        })
        .to_string()
    }

    fn args(extra: serde_json::Value) -> String {
        let mut v = serde_json::json!({"challenge_body": "{}"});
        let cfg: serde_json::Value = serde_json::from_str(&cfg_json()).unwrap();
        v["__config"] = cfg;
        for (k, val) in extra.as_object().expect("object") {
            v[k] = val.clone();
        }
        v.to_string()
    }

    #[test]
    fn a_well_formed_call_parses() {
        let p = parse(&args(serde_json::json!({"tier": 1}))).expect("parses");
        assert_eq!(p.tier, Some(1));
        assert_eq!(p.cfg.max_amount, 1_000_000);
        assert!(matches!(p.source, ChallengeSource::Body(_)));
    }

    #[test]
    fn every_config_field_is_refused_at_the_top_level_by_name() {
        // Not ignored. An ignored value is the worst outcome: the caller believes it took effect,
        // the payment goes elsewhere, and nothing in the output says which value won.
        for name in CONFIG_ONLY {
            let e = parse(&args(serde_json::json!({name: "1"})))
                .expect_err("a shadowing argument must be refused");
            assert!(e.contains(name), "{name} not named in: {e}");
            assert!(e.contains("__config"), "{e}");
        }
    }

    #[test]
    fn several_shadowing_arguments_are_all_named() {
        let e = parse(&args(serde_json::json!({"receiver": "x", "mint": "y"}))).unwrap_err();
        assert!(e.contains("receiver") && e.contains("mint"), "{e}");
    }

    #[test]
    fn a_plain_http_challenge_url_is_refused() {
        let mut v: serde_json::Value = serde_json::from_str(&args(serde_json::json!({}))).unwrap();
        v["challenge_body"] = serde_json::Value::Null;
        v["challenge_url"] = serde_json::json!("http://seller.example/price");
        let e = parse(&v.to_string()).unwrap_err();
        assert!(e.contains("not https"), "{e}");
    }

    #[test]
    fn an_https_challenge_url_is_accepted() {
        let mut v: serde_json::Value = serde_json::from_str(&args(serde_json::json!({}))).unwrap();
        v["challenge_body"] = serde_json::Value::Null;
        v["challenge_url"] = serde_json::json!("https://seller.example/price");
        assert!(matches!(
            parse(&v.to_string()).unwrap().source,
            ChallengeSource::Url(_)
        ));
    }

    #[test]
    fn supplying_both_a_body_and_a_url_is_refused() {
        let e = parse(&args(
            serde_json::json!({"challenge_url": "https://seller.example/price"}),
        ))
        .unwrap_err();
        assert!(e.contains("not both"), "{e}");
    }

    #[test]
    fn supplying_neither_is_refused() {
        let e = parse(&format!(r#"{{"__config":{}}}"#, cfg_json())).unwrap_err();
        assert!(e.contains("one of challenge_body or challenge_url"), "{e}");
    }

    #[test]
    fn a_missing_config_is_refused_rather_than_defaulted() {
        let e = parse(r#"{"challenge_body":"{}"}"#).unwrap_err();
        assert!(e.contains("__config"), "{e}");
    }

    #[test]
    fn every_config_field_is_required_and_none_has_a_default() {
        for drop in ["receiver", "mint", "network", "delegation", "max_amount"] {
            let mut c: serde_json::Value = serde_json::from_str(&cfg_json()).unwrap();
            c[drop] = serde_json::Value::Null;
            let body = serde_json::json!({"challenge_body": "{}", "__config": c}).to_string();
            let e = parse(&body).expect_err("a missing config field must refuse");
            assert!(e.contains(drop), "{drop} not named in: {e}");
        }
    }

    #[test]
    fn a_zero_ceiling_authorises_nothing_and_says_so() {
        let mut c: serde_json::Value = serde_json::from_str(&cfg_json()).unwrap();
        c["max_amount"] = serde_json::json!("0");
        let body = serde_json::json!({"challenge_body": "{}", "__config": c}).to_string();
        assert!(parse(&body).unwrap_err().contains("authorises nothing"));
    }

    #[test]
    fn a_non_numeric_ceiling_is_refused() {
        let mut c: serde_json::Value = serde_json::from_str(&cfg_json()).unwrap();
        c["max_amount"] = serde_json::json!("1.5");
        let body = serde_json::json!({"challenge_body": "{}", "__config": c}).to_string();
        assert!(parse(&body).unwrap_err().contains("atomic base units"));
    }

    #[test]
    fn a_plain_http_rpc_override_is_dropped_rather_than_honoured() {
        let mut c: serde_json::Value = serde_json::from_str(&cfg_json()).unwrap();
        c["rpc_url"] = serde_json::json!("http://rpc.example");
        let body = serde_json::json!({"challenge_body": "{}", "__config": c}).to_string();
        assert_eq!(parse(&body).unwrap().rpc_url, None);
    }

    // ---- error-path echo bounding -----------------------------------------

    /// A 4-byte codepoint: not a control character, not escaped by `Debug`, and four times its
    /// character count in bytes. It is what separates a char cap from a byte ceiling.
    const ASTRAL: &str = "\u{1F600}";
    /// The char-only form the crate no longer calls. It survives in these tests because the
    /// controls reconstruct the pre-fix behaviour with it, which is what proves the byte cap is
    /// load-bearing rather than decorative.
    use solana_core::sanitize_onchain;

    /// `RawArgs` is a TYPED struct, so a shape mismatch is not a syntax error: serde embeds the
    /// offending value VERBATIM.
    #[test]
    fn the_arguments_parse_error_is_byte_bounded() {
        let flood = ASTRAL.repeat(2000);
        // `tier` is typed `Option<usize>`; hand it a string and serde quotes the string back.
        let json = format!(r#"{{"challenge_body":"{{}}","tier":"{flood}"}}"#);

        const PROSE: &str = "arguments are not valid JSON: ";
        let err = parse(&json).expect_err("a string where a usize belongs must be refused");
        assert!(
            err.starts_with(PROSE),
            "the message no longer opens with the prose this bound subtracts. Got: {err}"
        );
        let echoed = err.len() - PROSE.len();
        assert!(
            echoed > 0,
            "the serde error capped away to nothing, so the bound below proves nothing"
        );
        assert!(
            echoed <= 120,
            "echoed {echoed} bytes, over the 120-byte budget"
        );

        // CONTROL, measured against what serde ACTUALLY produced rather than an assumed shape.
        let raw = serde_json::from_str::<RawArgs>(&json)
            .expect_err("the fixture parsed, so there is no error to bound")
            .to_string();
        assert!(
            raw.len() > 480,
            "serde no longer embeds the offending value ({} bytes), so this test is measuring a \
             fixed message rather than an attacker-chosen one",
            raw.len()
        );
        let char_only = sanitize_onchain(&raw, 120).text.len();
        assert!(
            char_only > 120,
            "the char cap alone yields {char_only} bytes, already inside the budget, so the byte \
             cap is not what holds it"
        );
        eprintln!(
            "MEASURED x402-pay-build arguments parse echo: {echoed} B (raw serde: {} B, \
             char-capped only: {char_only} B, budget 120 B)",
            raw.len()
        );
    }

    /// The `challenge_url` refusal is the site where the inversion is easiest to miss: on the
    /// ACCEPTED path the value is an https URL, and this branch fires precisely because it is not.
    #[test]
    fn a_non_https_challenge_url_echo_is_byte_bounded() {
        let flood = format!("http://evil.example/{}", ASTRAL.repeat(2000));

        // Derive the fixed prose by driving the same branch with a one-byte-per-character value.
        let short = "http://e";
        let short_err = parse(&args(serde_json::json!({
            "challenge_body": serde_json::Value::Null, "challenge_url": short
        })))
        .expect_err("plain http must be refused");
        assert!(short_err.contains("is not https"), "{short_err}");
        let short_echo = format!("{short:?}");
        assert!(
            short_err.contains(&short_echo),
            "the refused URL never reached the echo, so this case is vacuous: {short_err}"
        );
        let prefix = short_err.len() - short_echo.len();

        let err = parse(&args(serde_json::json!({
            "challenge_body": serde_json::Value::Null, "challenge_url": flood
        })))
        .expect_err("plain http must be refused");
        assert!(err.contains("is not https"), "{err}");
        let echoed = err.len() - prefix;
        assert!(echoed > 0, "the echo capped away to nothing");
        assert!(
            echoed <= 64,
            "echoed {echoed} bytes, over the 64-byte budget"
        );

        let char_only = sanitize_onchain(&format!("{flood:?}"), 64).text.len();
        assert!(
            char_only > 64,
            "the char cap alone yields {char_only} bytes, already inside the budget"
        );
        eprintln!(
            "MEASURED x402-pay-build challenge_url refusal echo: {echoed} B (char-capped only: \
             {char_only} B, budget 64 B)"
        );
    }

    /// The two refusals the wasm shim raises around its GET. They live here, in the pure core, for
    /// exactly this reason: the shim is the one module with no test coverage by construction, and a
    /// message built inside it is a message nothing can measure.
    ///
    /// The fixed prose is DERIVED by driving each builder with a short URL, not subtracted from a
    /// pinned string. The first draft of this test subtracted only the SUFFIX and reported 78 bytes
    /// against a 64-byte budget, which is the accounting failing rather than the bound: the prose
    /// sits on BOTH sides of the echo here. Deriving it removes the arithmetic entirely.
    #[test]
    fn the_shim_url_refusals_are_byte_bounded() {
        let flood = format!("https://evil.example/{}", ASTRAL.repeat(2000));
        let short = "https://e";
        let short_echo = format!("{short:?}");

        type Builder = fn(&str) -> String;
        let builders: [(&str, Builder); 2] = [
            ("unreachable", |u| {
                unreachable_challenge_error(u, "connection refused")
            }),
            ("status", |u| unexpected_challenge_status_error(u, 503)),
        ];

        let mut checked = 0usize;
        for (name, build) in builders {
            let short_msg = build(short);
            assert!(
                short_msg.contains(&short_echo),
                "{name}: the URL never reached the echo, so this case is vacuous: {short_msg}"
            );
            let prefix = short_msg.len() - short_echo.len();

            let msg = build(&flood);
            let echoed = msg.len() - prefix;
            assert!(echoed > 0, "{name}: the echo capped away to nothing");
            assert!(
                echoed <= 64,
                "{name}: echoed {echoed} bytes, over the 64-byte budget"
            );
            let char_only = sanitize_onchain(&format!("{flood:?}"), 64).text.len();
            assert!(
                char_only > 64,
                "{name}: the char cap alone yields {char_only} bytes, already inside the budget"
            );
            eprintln!(
                "MEASURED x402-pay-build shim {name} refusal echo: {echoed} B (char-capped only: \
                 {char_only} B, budget 64 B)"
            );
            checked += 1;
        }
        assert_eq!(checked, 2, "a case was skipped");
    }

    /// An ordinary URL survives its own refusal intact. A cap that mangles a real value is a
    /// different defect from the one it fixes.
    #[test]
    fn an_ordinary_url_is_untouched_by_the_echo_cap() {
        let url = "http://x402.perfpilot.dev/reading";
        let err = parse(&args(serde_json::json!({
            "challenge_body": serde_json::Value::Null, "challenge_url": url
        })))
        .expect_err("plain http must be refused");
        assert!(
            err.contains(&format!("{url:?}")),
            "a real URL was altered by the echo cap: {err}"
        );
    }

    /// The operator's own `__config.max_amount` is DELIBERATELY not echo-bounded, and that decision
    /// is pinned here so it reads as a choice rather than as an omission a later sweep should
    /// "fix". The host strips any caller-supplied `__config` before injecting the operator's, so
    /// this string is the operator's, read by the operator, and capping it would only cost them the
    /// `…` marker that distinguishes a truncated paste from a mistyped value.
    #[test]
    fn the_operator_config_echo_is_deliberately_not_capped() {
        let long = "1".repeat(500);
        let mut cfg: serde_json::Value = serde_json::from_str(&cfg_json()).unwrap();
        cfg["max_amount"] = serde_json::json!(long);
        let json = serde_json::json!({"challenge_body": "{}", "__config": cfg}).to_string();

        let err = parse(&json).expect_err("500 digits is not a u64");
        assert!(
            err.contains(&long),
            "the operator's value was truncated; if that is now intended, this test is the record \
             of the decision it reverses, not a stale assertion to delete: {err}"
        );
    }
}
