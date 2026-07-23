//! Pure, network-free core of the x402 feed gate.
//!
//! An x402 seller that lets an autonomous client BUY one reading of our
//! device-signed on-chain feed. The whole trust model is: the client pays us a
//! stablecoin transfer on Solana, signs it themselves (client is the fee
//! payer), and we verify the *bytes* of that signed transaction before we
//! broadcast it and serve the data. We hold no keys beyond our public receiving
//! wallet address — there is nothing here to prompt-inject into moving funds,
//! because this process cannot move funds. It can only *recognise* a payment
//! made to us.
//!
//! This module is deliberately free of HTTP and RPC so the whole verification
//! and accounting policy is unit-testable; `main.rs` wires it to `tiny_http`
//! and a real Solana RPC endpoint.

use base64::Engine;
use serde::{Deserialize, Serialize};
use solana_core::pubkey::{associated_token_program, memo_program, token_program};
use solana_core::{decode_transaction, find_payment, has_memo, Pubkey};

/// A single purchasable option, rendered into the `accepts` array of the 402
/// body. Several of these in one response IS the x402 tiered price menu:
/// the client picks in a single round trip, no negotiation protocol needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriceOption {
    pub scheme: String,
    pub network: String,
    /// SPL mint (base58) the payment must be denominated in.
    pub asset: String,
    /// Our receiving wallet (base58); payment lands in its ATA for `asset`.
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// Price in atomic base units, as a decimal string (x402 convention).
    pub amount: String,
    #[serde(rename = "maxTimeoutSeconds")]
    pub max_timeout_seconds: u64,
    /// What this option buys, for a human/agent reading the menu.
    pub description: String,
}

/// The 402 response body (x402 `PaymentRequirements`). `extra.memo` carries the
/// per-request nonce the payment MUST echo, binding the payment to this exact
/// challenge and defeating replay against a different request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    pub error: String,
    pub accepts: Vec<PriceOption>,
    pub extra: ChallengeExtra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeExtra {
    /// The nonce the payer must include as a Memo instruction.
    pub memo: String,
}

impl Challenge {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Challenge serializes")
    }
}

/// Static config for the gate: what we sell and where we receive.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Our receiving wallet (fee we receive lands in its ATA for the mint).
    pub seller_wallet: Pubkey,
    /// The stablecoin mint we price in (e.g. devnet USDC).
    pub mint: Pubkey,
    /// CAIP-2 / x402 network string (e.g. "solana-devnet").
    pub network: String,
    /// Price of a single reading, atomic base units.
    pub price_single: u64,
    /// Price of a day-pass (unlimited reads that UTC day), atomic base units.
    pub price_day_pass: u64,
    /// Per-payer per-day spend cap, atomic base units. A hard, in-code ceiling
    /// (the brief mandates a code-enforced cap in either commerce direction).
    pub daily_cap: u64,
}

impl GateConfig {
    /// The associated token account payments must land in.
    pub fn receiving_ata(&self) -> Pubkey {
        Pubkey::associated_token_address(&self.seller_wallet, &self.mint, &token_program())
    }

    /// Build a 402 challenge with the two-option price menu and the given nonce.
    pub fn challenge(&self, nonce: &str) -> Challenge {
        let opt = |amount: u64, desc: &str| PriceOption {
            scheme: "exact".into(),
            network: self.network.clone(),
            asset: self.mint.to_base58(),
            pay_to: self.seller_wallet.to_base58(),
            amount: amount.to_string(),
            max_timeout_seconds: 60,
            description: desc.into(),
        };
        Challenge {
            x402_version: 2,
            error: "payment required to read this feed".into(),
            accepts: vec![
                opt(self.price_single, "one feed reading"),
                opt(self.price_day_pass, "day pass: unlimited reads this UTC day"),
            ],
            extra: ChallengeExtra { memo: nonce.into() },
        }
    }
}

/// Why a presented X-PAYMENT was rejected. Every variant is a fail-closed
/// refusal to serve; none of them can move funds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The header was not valid base64 / JSON / lacked a transaction.
    Malformed(String),
    /// The transaction bytes did not decode.
    Undecodable,
    /// No TransferChecked to our ATA for our mint of at least the price.
    NoValidPayment,
    /// The payment did not carry the challenge nonce as a memo (replay guard).
    MissingMemo,
    /// This nonce was already spent (double-serve guard).
    NonceReused,
    /// Paying this would exceed the payer's daily cap.
    DailyCapExceeded { would_be: u64, cap: u64 },
    /// Amount paid did not match either menu price.
    PriceMismatch { paid: u64 },
}

/// A verified, ready-to-broadcast payment. `raw_tx` is the exact bytes to send;
/// `payer` is the fee payer (used for daily-cap accounting); `amount` is what
/// was actually paid; `is_day_pass` records which menu tier was purchased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub raw_tx: Vec<u8>,
    pub payer: Pubkey,
    pub amount: u64,
    pub is_day_pass: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct XPaymentEnvelope {
    #[serde(default)]
    payload: Option<XPaymentPayload>,
}

#[derive(Debug, Clone, Deserialize)]
struct XPaymentPayload {
    /// base64 of the signed transaction.
    transaction: Option<String>,
}

/// Verify a presented `X-PAYMENT` header value against this gate's config and
/// the nonce we issued. On success the returned bytes are safe to broadcast;
/// on failure we serve nothing. Purely local: decodes the client's signed
/// transaction and checks it pays us. Does NOT touch the network — the caller
/// simulates/submits/confirms the returned bytes.
pub fn verify_x_payment(
    cfg: &GateConfig,
    header_value: &str,
    nonce: &str,
) -> Result<VerifiedPayment, Reject> {
    // 1. base64 -> JSON envelope -> signed-tx base64 -> raw bytes.
    let json_bytes = base64::engine::general_purpose::STANDARD
        .decode(header_value.trim())
        .map_err(|e| Reject::Malformed(format!("header not base64: {e}")))?;
    let env: XPaymentEnvelope = serde_json::from_slice(&json_bytes)
        .map_err(|e| Reject::Malformed(format!("header not x402 JSON: {e}")))?;
    let tx_b64 = env
        .payload
        .and_then(|p| p.transaction)
        .ok_or_else(|| Reject::Malformed("no payload.transaction".into()))?;
    let raw_tx = base64::engine::general_purpose::STANDARD
        .decode(tx_b64.trim())
        .map_err(|e| Reject::Malformed(format!("transaction not base64: {e}")))?;

    // 2. Decode the transaction and confirm it pays us.
    let decoded = decode_transaction(&raw_tx).map_err(|_| Reject::Undecodable)?;
    let our_ata = cfg.receiving_ata();

    // 3. Memo must equal the nonce we issued for THIS challenge.
    if !has_memo(&decoded, &memo_program(), nonce.as_bytes()) {
        return Err(Reject::MissingMemo);
    }

    // 4. A TransferChecked to our ATA for our mint of at least the single price.
    let found = find_payment(&decoded, &cfg.mint, &our_ata, cfg.price_single)
        .map_err(|_| Reject::NoValidPayment)?;

    // 5. The amount must equal one of the menu tiers exactly (no odd amounts).
    let is_day_pass = found.amount == cfg.price_day_pass;
    if found.amount != cfg.price_single && !is_day_pass {
        return Err(Reject::PriceMismatch { paid: found.amount });
    }

    // 6. Fee payer = account_keys[0] = the payer we meter against the cap.
    let payer = *decoded
        .message
        .account_keys
        .first()
        .ok_or(Reject::Undecodable)?;

    Ok(VerifiedPayment {
        raw_tx,
        payer,
        amount: found.amount,
        is_day_pass,
    })
}

/// Per-payer daily spend accounting, enforced in code. Pure: the caller passes
/// the current UTC day so the boundary logic is deterministic and testable.
#[derive(Debug, Default)]
pub struct DailyLedger {
    /// (payer_base58, utc_day) -> cumulative atomic units spent.
    spent: std::collections::HashMap<(String, i64), u64>,
    /// nonces already redeemed (single-use).
    used_nonces: std::collections::HashSet<String>,
}

impl DailyLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Would recording `amount` for `payer` on `utc_day` stay within `cap`?
    pub fn within_cap(&self, payer: &Pubkey, utc_day: i64, amount: u64, cap: u64) -> bool {
        let already = self
            .spent
            .get(&(payer.to_base58(), utc_day))
            .copied()
            .unwrap_or(0);
        already.saturating_add(amount) <= cap
    }

    /// Commit a verified payment: enforce single-use nonce and the daily cap,
    /// then record the spend. Returns `Ok(())` or the specific rejection.
    pub fn commit(
        &mut self,
        payer: &Pubkey,
        nonce: &str,
        utc_day: i64,
        amount: u64,
        cap: u64,
    ) -> Result<(), Reject> {
        if self.used_nonces.contains(nonce) {
            return Err(Reject::NonceReused);
        }
        let key = (payer.to_base58(), utc_day);
        let already = self.spent.get(&key).copied().unwrap_or(0);
        let would_be = already.saturating_add(amount);
        if would_be > cap {
            return Err(Reject::DailyCapExceeded { would_be, cap });
        }
        self.used_nonces.insert(nonce.to_string());
        self.spent.insert(key, would_be);
        Ok(())
    }
}

/// The 200-OK settlement header (`X-PAYMENT-RESPONSE`) value: base64 of a small
/// JSON receipt naming the settled signature.
pub fn settlement_header(signature: &str, network: &str, payer: &Pubkey) -> String {
    let receipt = serde_json::json!({
        "success": true,
        "transaction": signature,
        "network": network,
        "payer": payer.to_base58(),
    });
    base64::engine::general_purpose::STANDARD.encode(receipt.to_string())
}

/// Keep the ATA-program import used so a future refactor that inlines the
/// derivation does not silently drop the dependency.
#[allow(dead_code)]
fn _ata_program_anchor() -> Pubkey {
    associated_token_program()
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_core::instruction::{memo as memo_ix, AccountMeta, Instruction};
    use solana_core::message::compile;
    use solana_core::pubkey::token_program;
    use solana_core::signing::{pubkey_from_seed, serialize_transaction, sign_message};
    use solana_core::token::TRANSFER_CHECKED_TAG;

    fn cfg() -> GateConfig {
        // Deterministic pubkeys for the test.
        let seller = Pubkey::new(pubkey_from_seed(&[100; 32]));
        let mint = Pubkey::new(pubkey_from_seed(&[101; 32]));
        GateConfig {
            seller_wallet: seller,
            mint,
            network: "solana-devnet".into(),
            price_single: 1_000_000,   // 1 USDC (6 decimals)
            price_day_pass: 5_000_000, // 5 USDC
            daily_cap: 10_000_000,     // 10 USDC/day
        }
    }

    /// Build a client X-PAYMENT header paying `amount` to the gate's ATA with
    /// the given nonce as a memo. `payer_seed` identifies the paying wallet.
    fn build_header(cfg: &GateConfig, payer_seed: u8, amount: u64, nonce: &str) -> String {
        let payer_seed = [payer_seed; 32];
        let payer = Pubkey::new(pubkey_from_seed(&payer_seed));
        let our_ata =
            Pubkey::associated_token_address(&cfg.seller_wallet, &cfg.mint, &token_program());
        let src_ata = Pubkey::associated_token_address(&payer, &cfg.mint, &token_program());

        let mut data = vec![TRANSFER_CHECKED_TAG];
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(6); // decimals
        let transfer = Instruction {
            program_id: token_program(),
            accounts: vec![
                AccountMeta::writable(src_ata, false),
                AccountMeta::readonly(cfg.mint, false),
                AccountMeta::writable(our_ata, false),
                AccountMeta::readonly(payer, true),
            ],
            data,
        };
        let memo = memo_ix(&payer, nonce.as_bytes());

        let msg = compile(&payer, &[transfer, memo], &[9u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(&payer_seed, &body);
        let raw_tx = serialize_transaction(&[sig], &body);

        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_tx);
        let envelope = serde_json::json!({
            "x402Version": 2,
            "payload": { "transaction": tx_b64 }
        });
        base64::engine::general_purpose::STANDARD.encode(envelope.to_string())
    }

    #[test]
    fn challenge_has_two_priced_options_and_nonce() {
        let c = cfg().challenge("nonce-xyz");
        assert_eq!(c.accepts.len(), 2);
        assert_eq!(c.accepts[0].amount, "1000000");
        assert_eq!(c.accepts[1].amount, "5000000");
        assert_eq!(c.extra.memo, "nonce-xyz");
        assert_eq!(c.accepts[0].scheme, "exact");
        // round-trips as JSON
        assert!(c.to_json().contains("payTo"));
    }

    #[test]
    fn valid_single_payment_verifies() {
        let cfg = cfg();
        let header = build_header(&cfg, 7, cfg.price_single, "n1");
        let v = verify_x_payment(&cfg, &header, "n1").unwrap();
        assert_eq!(v.amount, cfg.price_single);
        assert!(!v.is_day_pass);
        assert_eq!(v.payer, Pubkey::new(pubkey_from_seed(&[7; 32])));
    }

    #[test]
    fn valid_day_pass_verifies() {
        let cfg = cfg();
        let header = build_header(&cfg, 7, cfg.price_day_pass, "n2");
        let v = verify_x_payment(&cfg, &header, "n2").unwrap();
        assert!(v.is_day_pass);
    }

    #[test]
    fn wrong_nonce_rejected_as_missing_memo() {
        let cfg = cfg();
        let header = build_header(&cfg, 7, cfg.price_single, "issued-nonce");
        // Verify against a DIFFERENT nonce than the tx carried.
        assert_eq!(
            verify_x_payment(&cfg, &header, "expected-other-nonce"),
            Err(Reject::MissingMemo)
        );
    }

    #[test]
    fn underpayment_rejected() {
        let cfg = cfg();
        let header = build_header(&cfg, 7, cfg.price_single - 1, "n3");
        assert_eq!(
            verify_x_payment(&cfg, &header, "n3"),
            Err(Reject::NoValidPayment)
        );
    }

    #[test]
    fn odd_amount_between_tiers_rejected() {
        let cfg = cfg();
        // Pays more than single, less than day-pass, matching neither tier.
        let header = build_header(&cfg, 7, 2_000_000, "n4");
        assert_eq!(
            verify_x_payment(&cfg, &header, "n4"),
            Err(Reject::PriceMismatch { paid: 2_000_000 })
        );
    }

    #[test]
    fn garbage_header_rejected_not_panicked() {
        let cfg = cfg();
        for bad in ["", "not-base64!!", "YWJj", "e30="] {
            assert!(verify_x_payment(&cfg, bad, "n").is_err());
        }
    }

    #[test]
    fn daily_ledger_enforces_cap_and_single_use_nonce() {
        let cfg = cfg();
        let payer = Pubkey::new(pubkey_from_seed(&[7; 32]));
        let mut ledger = DailyLedger::new();
        let day = 20_000;

        // Spend up to the cap across several payments.
        assert!(ledger.commit(&payer, "a", day, 5_000_000, cfg.daily_cap).is_ok());
        assert!(ledger.commit(&payer, "b", day, 5_000_000, cfg.daily_cap).is_ok());
        // One more would exceed 10 USDC.
        assert_eq!(
            ledger.commit(&payer, "c", day, 1_000_000, cfg.daily_cap),
            Err(Reject::DailyCapExceeded {
                would_be: 11_000_000,
                cap: 10_000_000
            })
        );
        // Reusing a spent nonce is refused.
        assert_eq!(
            ledger.commit(&payer, "a", day, 1, cfg.daily_cap),
            Err(Reject::NonceReused)
        );
        // A NEW day resets the cap for the same payer.
        assert!(ledger.commit(&payer, "d", day + 1, 5_000_000, cfg.daily_cap).is_ok());
    }

    #[test]
    fn within_cap_predicate_matches_commit() {
        let cfg = cfg();
        let payer = Pubkey::new(pubkey_from_seed(&[8; 32]));
        let mut ledger = DailyLedger::new();
        let day = 20_001;
        assert!(ledger.within_cap(&payer, day, cfg.daily_cap, cfg.daily_cap));
        assert!(!ledger.within_cap(&payer, day, cfg.daily_cap + 1, cfg.daily_cap));
        ledger.commit(&payer, "x", day, cfg.daily_cap, cfg.daily_cap).unwrap();
        assert!(!ledger.within_cap(&payer, day, 1, cfg.daily_cap));
    }

    #[test]
    fn settlement_header_is_base64_json_receipt() {
        let payer = Pubkey::new(pubkey_from_seed(&[7; 32]));
        let h = settlement_header("5xSig", "solana-devnet", &payer);
        let decoded = base64::engine::general_purpose::STANDARD.decode(&h).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(v["success"], true);
        assert_eq!(v["transaction"], "5xSig");
    }
}
