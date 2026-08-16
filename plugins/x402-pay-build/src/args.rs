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

use crate::pay::PayConfig;

/// The operator's settings, injected by the host under `__config`. Never agent-supplied.
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
    let raw: RawArgs =
        serde_json::from_str(json).map_err(|e| format!("arguments are not valid JSON: {e}"))?;

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
                if !u.starts_with("https://") {
                    return Err(format!(
                    "challenge_url {u:?} is not https. A 402 challenge names where money goes, so \
                     reading it over a channel anyone can rewrite defeats the cross-check"
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

    let need = |v: Option<String>, name: &str| -> Result<String, String> {
        v.filter(|s| !s.trim().is_empty())
            .ok_or_else(|| format!("`__config.{name}` is missing, and it has no safe default"))
    };
    let max_amount = need(c.max_amount, "max_amount")?;
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
}
