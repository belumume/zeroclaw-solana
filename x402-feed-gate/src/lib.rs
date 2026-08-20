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
use solana_core::{decode_transaction, find_payment, has_memo, verify_declared_signatures, Pubkey};

/// A single purchasable option, rendered into the `accepts` array of the 402
/// body. Several of these in one response IS the x402 tiered price menu:
/// the client picks in a single round trip, no negotiation protocol needed.
///
/// Field names and types are the x402 v2 `PaymentRequirements` shape
/// (`specs/x402-specification-v2.md` section 5.1.2). Note `amount` rather than
/// v1's `maxAmountRequired`: the two versions differ here and we declare v2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriceOption {
    pub scheme: String,
    /// CAIP-2 network identifier. v2 REQUIRES the `namespace:reference` form
    /// (`solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` for devnet); the friendly
    /// `solana-devnet` spelling is v1-only and fails v2 validation.
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
    /// Scheme-specific data. For `exact` on Solana this is where the memo the
    /// payer must echo belongs, per `specs/schemes/exact/scheme_exact_svm.md`:
    /// "When present, the client MUST use this value as the Memo instruction
    /// data instead of a random nonce."
    pub extra: PriceExtra,
    /// What this option buys, for a human/agent reading the menu.
    ///
    /// NOT a v2 `PaymentRequirements` field (v2 moved the human-readable text up
    /// to `resource.description`). Kept because this gate serves a two-tier menu
    /// and a per-tier label is the only thing distinguishing the rows to a human.
    /// It is additive: the reference validator's schemas declare no `.strict()`,
    /// so unknown keys are stripped rather than rejected, verified by parsing a
    /// live challenge through the published `@x402/core` validator.
    pub description: String,
}

/// Scheme-specific `extra` for the `exact` scheme on Solana.
///
/// The SVM scheme also defines `extra.feePayer`, the SPONSOR that adds the final
/// signature. This gate has no sponsor: the client is its own fee payer and signs
/// the transaction completely, and we hold no key with which to co-sign. Naming a
/// `feePayer` we do not sign with would be a false claim about custody AND would
/// break honest clients, which would then submit a partially-signed transaction
/// waiting for a signature that never comes. Omitted deliberately, documented in
/// the README, rather than fabricated to satisfy a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriceExtra {
    /// The nonce the payer must include as a Memo instruction.
    pub memo: String,
}

/// Describes the resource being sold. REQUIRED at the top level in x402 v2
/// (`resource: ResourceInfo`), and the field a discovery registry indexes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceInfo {
    pub url: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Printable ASCII, max 32 chars (spec-enforced).
    #[serde(rename = "serviceName")]
    pub service_name: String,
    /// Max 5 entries, each printable ASCII max 32 chars (spec-enforced).
    pub tags: Vec<String>,
}

/// The 402 response body (x402 v2 `PaymentRequired`). `accepts[].extra.memo`
/// carries the per-request nonce the payment MUST echo, binding the payment to
/// this exact challenge and defeating replay against a different request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "x402Version")]
    pub x402_version: u8,
    pub error: String,
    pub resource: ResourceInfo,
    pub accepts: Vec<PriceOption>,
    /// Retained at the top level for clients written against this gate before
    /// the nonce moved into `accepts[].extra`. It is NOT a v2 field, so a spec
    /// client ignores it; removing it would break existing payers for no
    /// compliance gain, since unknown keys are stripped rather than rejected.
    pub extra: PriceExtra,
}

impl Challenge {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Challenge serializes")
    }

    /// Base64 of the JSON body, for the `PAYMENT-REQUIRED` response header.
    ///
    /// v2's HTTP transport makes the header the canonical wire location
    /// (`specs/transports-v2/http.md`: "All x402 protocol information is
    /// communicated through headers"), and the reference client reads ONLY the
    /// header. The JSON body is kept alongside it because the same spec says
    /// "Response bodies are a server implementation concern", so serving both
    /// costs no compliance and keeps the endpoint readable by a human with curl.
    pub fn to_payment_required_header(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.to_json())
    }
}

/// Static config for the gate: what we sell and where we receive.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Our receiving wallet (fee we receive lands in its ATA for the mint).
    pub seller_wallet: Pubkey,
    /// The stablecoin mint we price in (e.g. devnet USDC).
    pub mint: Pubkey,
    /// CAIP-2 network identifier. x402 v2 requires `namespace:reference`, e.g.
    /// `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` (devnet) or
    /// `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` (mainnet).
    pub network: String,
    /// Absolute URL of the resource being sold, for the required `resource`
    /// object. Configured rather than derived, because the gate sits behind a
    /// proxy and cannot see its own public origin from the request.
    pub resource_url: String,
    /// Price of a single reading, atomic base units.
    pub price_single: u64,
    /// The amount a cached client may still pay, atomic base units. It buys exactly one
    /// read, the same as `price_single`: the tier this named was withdrawn from the menu
    /// because nothing in the gate ever granted the second read it advertised.
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
            extra: PriceExtra { memo: nonce.into() },
            description: desc.into(),
        };
        Challenge {
            x402_version: 2,
            error: "payment required to read this feed".into(),
            resource: ResourceInfo {
                url: self.resource_url.clone(),
                description: "One device-signed reading from a ZeroClaw DePIN feed on Solana"
                    .into(),
                mime_type: "application/json".into(),
                // Both of the below are length- and charset-constrained by the
                // spec (serviceName <= 32 printable ASCII; <= 5 tags, each <= 32).
                // A test asserts the shipped values stay inside those bounds, so
                // a future rename cannot silently produce a challenge that a
                // discovery registry rejects.
                service_name: "ZeroClaw DePIN feed".into(),
                tags: vec![
                    "depin".into(),
                    "solana".into(),
                    "oracle".into(),
                    "telemetry".into(),
                ],
            },
            // WITHDRAWN: the day-pass tier is no longer advertised.
            //
            // It was priced at 5x the single read and described as "unlimited reads this UTC day",
            // and nothing in the gate ever granted a second read. `is_day_pass` was computed,
            // stored on the receipt and logged, and no code path consulted it: the nonce burns on
            // the first request, so the next one is refused with NonceReused whatever tier was
            // bought. A buyer paid five times the price for identical service, and on an
            // agent-to-agent paywall the buyer is a machine that would keep doing it.
            //
            // Removed rather than implemented, deliberately. Granting it properly means keying an
            // entitlement on the token AUTHORITY (not the fee payer, which is a separate account
            // and is what the daily cap currently meters), persisting it across restart, and
            // giving repeat reads a replay story that the single-use nonce does not currently
            // provide. That is a real feature on a money path, and shipping it half-built is worse
            // than not selling it. Advertising something not delivered is the part that had to
            // stop today.
            //
            // `verify_x_payment` still ACCEPTS the day-pass amount, so a client holding a cached
            // challenge is served rather than refused. Withdrawing the offer must not strand
            // anyone who already took it.
            accepts: vec![opt(self.price_single, "one feed reading")],
            extra: PriceExtra { memo: nonce.into() },
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
    /// A signature the message declares does not verify against the message bytes.
    ///
    /// Distinct from `Undecodable`: these bytes parse perfectly and name a signer set.
    /// Nobody signed for it. Until this check existed the gate could not tell the two
    /// apart and treated the second as a valid payment from whoever the message named.
    BadSignature,
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

/// A verified, ready-to-broadcast payment. `raw_tx` is the exact bytes to send; `payer`
/// is the TOKEN AUTHORITY, whose signature over `raw_tx` has been checked and whose
/// tokens move; `fee_payer` is recorded for the receipt only; `amount` is what was
/// actually paid; `is_day_pass` records which menu tier was purchased.
///
/// `is_day_pass` IS NOT AN ENTITLEMENT and never was. It is a record of the amount paid, kept for
/// the receipt and the log. The tier it names is no longer advertised, because nothing granted the
/// unlimited reads it promised. Do not start reading this flag as permission without also building
/// the entitlement it would need: keyed on the token authority rather than the fee payer,
/// persisted across restart, and with a replay story for repeat reads.
///
/// `payer` is the TOKEN AUTHORITY rather than the fee payer, because in SVM the two are
/// independent and a quota is about whoever's tokens moved. Metering the fee payer let a buyer
/// behind rotating sponsors spend past their own ceiling while every payment verified. The
/// authority is verified to be in the signer set AND to have actually signed, so it is an
/// identity the ledger can be keyed on rather than one the sender asserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub raw_tx: Vec<u8>,
    /// The TOKEN AUTHORITY: the account whose tokens moved, verified to be a signer. This is what
    /// the daily cap meters, because it is the identity a quota is about.
    pub payer: Pubkey,
    /// The fee payer, `account_keys[0]`. Kept for the receipt and the log only. It is INDEPENDENT
    /// of `payer` in SVM, which is the whole reason the cap no longer keys on it.
    pub fee_payer: Pubkey,
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

    // 2b. EVERY DECLARED SIGNATURE MUST ACTUALLY VERIFY, and this must run before any
    // other step reads the decoded message.
    //
    // Decoding proves the header is self-consistent, which makes the signer PREFIX
    // well-formed and says nothing about whether anyone signed. Every check below, and
    // the ledger write the caller performs on the strength of them, keys on identities
    // taken from that prefix. Without this a sender supplies 64 arbitrary bytes per slot,
    // names any account as the token authority, and the gate meters the spend against a
    // stranger who never touched it.
    //
    // Settlement would still refuse such a transaction, which is exactly why this is not
    // redundant: everything the gate decides BEFORE broadcast is decided on these bytes.
    verify_declared_signatures(&raw_tx, &decoded).map_err(|_| Reject::BadSignature)?;

    let our_ata = cfg.receiving_ata();

    // 3. The payment must carry `nonce` as a Memo.
    //
    // Nothing here looks the value up in an issued set, and the caller does not hand one
    // down: `handle_reading` reads the nonce OUT of this payment's own memo and passes it
    // straight back in, so on its own this step is a tautology. A gate that describes this
    // as a check against an issued set is describing a binding it does not implement.
    //
    // What defeats replay is the pair of properties around it. The memo sits inside the
    // signed message, so step 2b binds it to the account that signed and a sender cannot
    // vary it without the key. The ledger then burns it once, so the same signed
    // transaction is refused the second time it arrives. A payment carrying no memo at
    // all is refused here.
    if !has_memo(&decoded, &memo_program(), nonce.as_bytes()) {
        return Err(Reject::MissingMemo);
    }

    // 4. A TransferChecked to our ATA for our mint of at least the single price.
    let found = find_payment(&decoded, &cfg.mint, &our_ata, cfg.price_single)
        .map_err(|_| Reject::NoValidPayment)?;

    // 5. The amount must equal one of the menu tiers exactly (no odd amounts).
    //
    // The day-pass amount is still accepted even though the tier is no longer advertised (see
    // `challenge`), so a client holding a cached menu is served rather than refused. It buys
    // exactly what the single read buys; the flag below records what was paid, never an
    // entitlement, and no code grants a second read on it.
    let is_day_pass = found.amount == cfg.price_day_pass;
    if found.amount != cfg.price_single && !is_day_pass {
        return Err(Reject::PriceMismatch { paid: found.amount });
    }

    // 6. The daily cap meters the TOKEN AUTHORITY, not the fee payer.
    //
    // It used to meter `account_keys[0]`. In SVM the fee payer and the account whose tokens move
    // are independent, and the x402 SVM scheme defines sponsorship through `extra.feePayer`
    // explicitly, so a buyer behind rotating fee sponsors could spend past their own ceiling while
    // every individual payment verified correctly. It stayed latent only because this gate
    // declines to advertise a feePayer, so honest clients self-pay -- which is a property of our
    // menu rather than of the check, and menus change.
    //
    // `find_payment` returns the authority already verified to be in the signer set, so this is
    // the party who actually authorised the spend.
    let payer = found.authority;

    // Kept for the receipt and the log: traceability of WHO paid the fee is still useful, it is
    // just not the identity a quota should key on.
    let fee_payer = *decoded
        .message
        .account_keys
        .first()
        .ok_or(Reject::Undecodable)?;

    Ok(VerifiedPayment {
        raw_tx,
        payer,
        fee_payer,
        amount: found.amount,
        is_day_pass,
    })
}

/// A held place in the ledger, outstanding while a payment is being settled.
///
/// Returned by [`DailyLedger::reserve`] and resolved by exactly one of
/// [`DailyLedger::confirm`] or [`DailyLedger::release`]. Both take it BY VALUE, so a
/// resolved reservation cannot be resolved twice.
///
/// HONEST LIMIT ON THE `must_use` BELOW: it catches a reservation DISCARDED outright, and
/// it does NOT catch one bound to a variable and then dropped. That path leaks a hold --
/// the cap stays consumed and the nonce stays burned for the rest of the UTC day -- and
/// nothing in the compiler or this suite would report it. What contains it is that
/// `handle_reading` resolves both arms of one `match` in straight-line code, which is
/// worth re-reading rather than assuming whenever that function grows an early return.
///
/// Its fields are private on purpose, and it is deliberately NOT `Clone`. A caller able
/// to build or duplicate one could release spend it never reserved, which is this type's
/// own defect pointed the other way: measured, a double release of a 900 hold against a
/// row also holding 100 of settled money took the settled 100 to zero.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "resolve a reservation with confirm or release, or the cap stays consumed for money that never moved"]
pub struct Reservation {
    payer: String,
    nonce: String,
    day: i64,
    amount: u64,
}

/// Per-payer daily spend accounting, enforced in code. Pure: the caller passes
/// the current UTC day so the boundary logic is deterministic and testable.
///
/// WHAT THIS TRACKS IS SETTLED MONEY, plus whatever is in flight at this instant. It used
/// to track ATTEMPTED money: the gate recorded the spend and burned the nonce before
/// broadcasting, and a payment that never reached the network left both behind for the
/// rest of the UTC day. An unauthenticated sender could therefore exhaust a stranger's
/// daily cap with payments that settlement refused, and `/health` published the total as
/// revenue.
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

    /// Take a place in the ledger for a payment that is about to be settled: enforce the
    /// single-use nonce and the daily cap, then hold the room the payment needs.
    ///
    /// The hold is what makes the cap safe to enforce without freezing the ledger across a
    /// network round trip. Checking with [`within_cap`](Self::within_cap) and recording
    /// afterwards would be a check-then-act with a settlement in the gap, and two requests
    /// that both read before either wrote would both be told there was room. Here the
    /// decision and the taking are one critical section, so they cannot interleave.
    ///
    /// The caller MUST resolve the returned [`Reservation`] with
    /// [`confirm`](Self::confirm) or [`release`](Self::release).
    pub fn reserve(
        &mut self,
        payer: &Pubkey,
        nonce: &str,
        utc_day: i64,
        amount: u64,
        cap: u64,
    ) -> Result<Reservation, Reject> {
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
        self.spent.insert(key.clone(), would_be);
        Ok(Reservation {
            payer: key.0,
            nonce: nonce.to_string(),
            day: utc_day,
            amount,
        })
    }

    /// Settlement succeeded: the held spend is real money and stays.
    ///
    /// Nothing is written here because `reserve` already wrote it, which is deliberate --
    /// the cap has to bind while the payment is in flight. The method exists to CONSUME the
    /// reservation, so a path that resolves neither way is a value left unused rather than
    /// an invisible omission.
    pub fn confirm(&mut self, reservation: Reservation) {
        debug_assert!(
            self.used_nonces.contains(&reservation.nonce),
            "confirming a reservation whose nonce the ledger is not holding"
        );
    }

    /// Settlement failed: give the room back and un-burn the nonce.
    ///
    /// No money moved, so the ledger must not say any did. Returning the nonce is the
    /// correct half too: the payment it belongs to was never accepted by the network, so
    /// refusing a retry of it would charge a buyer for a failure that was ours or the
    /// cluster's. A payment that DID settle keeps its nonce burned, which is where replay
    /// protection actually lives.
    pub fn release(&mut self, reservation: Reservation) {
        self.used_nonces.remove(&reservation.nonce);
        let key = (reservation.payer, reservation.day);
        if let Some(entry) = self.spent.get_mut(&key) {
            *entry = entry.saturating_sub(reservation.amount);
            // Drop an emptied row rather than leaving a zero behind, so `tracked_payer_days`
            // counts payers who actually bought something.
            if *entry == 0 {
                self.spent.remove(&key);
            }
        }
    }

    /// Reserve and immediately confirm, for a caller with NO settlement step between the
    /// two -- a test, or a replay of something already known to have settled.
    ///
    /// `handle_reading` must NOT use this. Its whole defect was recording the spend before
    /// the money moved, so it needs the two phases held apart across the broadcast.
    pub fn commit(
        &mut self,
        payer: &Pubkey,
        nonce: &str,
        utc_day: i64,
        amount: u64,
        cap: u64,
    ) -> Result<(), Reject> {
        let reservation = self.reserve(payer, nonce, utc_day, amount, cap)?;
        self.confirm(reservation);
        Ok(())
    }

    /// Restore spend and redeemed nonces from settled sales.
    ///
    /// Without this the ledger lived only in process memory while the unit is
    /// `Restart=always`, so every restart re-opened the full per-payer daily
    /// allowance and forgot every redeemed nonce. A cap that resets whenever the
    /// process does is not the per-day cap the brief asks for, and nothing in the
    /// output would have shown it.
    ///
    /// SCOPE, and it has one honest gap. This replays what actually SETTLED, because that
    /// is what the earnings ledger records. A payment whose broadcast is DEFINITELY refused
    /// has its reservation released and so consumes nothing in either place, which is the
    /// agreement that matters and did not hold before.
    ///
    /// The gap is the UNKNOWN outcome: a broadcast the node accepted whose confirmation
    /// never arrived. The gate holds that spend in memory, because the transaction may still
    /// land, and does not write it here, because it is not known to be revenue. So a restart
    /// reopens that one payment's cap room. That is a strictly smaller leniency than
    /// releasing it outright, which would reopen the room immediately and let a payer with a
    /// slow endpoint exceed their cap on every request rather than only after a restart.
    ///
    /// Returns the number of records applied, so the caller can say so at startup
    /// instead of leaving a silent no-op indistinguishable from an empty ledger.
    pub fn rehydrate(&mut self, records: impl IntoIterator<Item = EarningRecord>) -> usize {
        let mut applied = 0usize;
        for r in records {
            let key = (r.payer, r.day);
            let entry = self.spent.entry(key).or_insert(0);
            *entry = entry.saturating_add(r.amount);
            if let Some(nonce) = r.nonce {
                self.used_nonces.insert(nonce);
            }
            applied += 1;
        }
        applied
    }

    /// How many single-use nonces have been redeemed.
    ///
    /// These three accessors exist so the health endpoint can report that the
    /// ledger survived a restart. The restart-survival property was previously
    /// asserted in the write-up and checkable by nobody: the only way to observe
    /// it was to be the operator reading a startup line on stderr.
    ///
    /// They deliberately return COUNTS AND SUMS AND NOTHING ELSE. The keys of the
    /// two collections are payer addresses and nonces, the endpoint that reads
    /// this is public and unauthenticated, and an accessor handing out the maps
    /// would let anyone enumerate who bought from this node and replay-test the
    /// nonces. A caller that wants the aggregate cannot accidentally get the
    /// identities, because there is no method that returns them.
    pub fn redeemed_nonce_count(&self) -> usize {
        self.used_nonces.len()
    }

    /// How many distinct (payer, UTC day) pairs carry spend.
    pub fn tracked_payer_days(&self) -> usize {
        self.spent.len()
    }

    /// Total atomic units settled across every payer and day currently tracked.
    ///
    /// Saturating, so a corrupt ledger reports a clamped total rather than
    /// wrapping to a small number that would read as a healthy quiet day.
    pub fn total_settled(&self) -> u64 {
        self.spent.values().fold(0u64, |a, b| a.saturating_add(*b))
    }
}

/// One settled sale, as the earnings ledger records it. Only the fields the
/// rebuild above needs.
///
/// `nonce` is optional because lines written before the gate started recording it
/// have none. Those still restore their spend, which is the half that bounds
/// money; their nonces stay unredeemed, which is the half Solana would catch
/// anyway when the duplicate signature reaches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarningRecord {
    pub day: i64,
    pub payer: String,
    pub amount: u64,
    pub nonce: Option<String>,
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
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".into(),
            resource_url: "https://x402.perfpilot.dev/reading".into(),
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
    fn challenge_has_one_priced_option_and_nonce() {
        let c = cfg().challenge("nonce-xyz");
        // One row since the ungranted day pass was withdrawn from the menu. The row's CONTENT is
        // what this pins; the count changed because the menu did, not because an assertion was
        // weakened -- every other assertion here is unchanged.
        assert_eq!(c.accepts.len(), 1);
        assert_eq!(c.accepts[0].amount, "1000000");
        assert_eq!(c.extra.memo, "nonce-xyz");
        assert_eq!(c.accepts[0].scheme, "exact");
        // round-trips as JSON
        assert!(c.to_json().contains("payTo"));
    }

    // ---- x402 v2 wire compliance ---------------------------------------------
    //
    // The gate declared `x402Version: 2` while serving a v1-shaped body: a
    // friendly `solana-devnet` network and no `resource` object. Both are HARD
    // failures against the published reference validator (`@x402/core`
    // PaymentRequiredV2Schema), not stylistic drift, so a spec client could not
    // read our price menu at all. These pin the two fields that failed, plus the
    // spec's length limits on the discovery metadata.

    #[test]
    fn every_accepts_row_carries_a_caip2_network() {
        // v2's NetworkSchemaV2 is `.min(3).refine(v => v.includes(":"))`, so the
        // colon is the whole test the reference validator applies.
        let c = cfg().challenge("n");
        // Non-EMPTY rather than a fixed count: the loop below is the actual test, and a loop over
        // an empty vector satisfies every assertion inside it vacuously. This guards that, and
        // does not break the next time a tier is added or withdrawn.
        assert!(
            !c.accepts.is_empty(),
            "an empty menu would pass the loop below vacuously"
        );
        for row in &c.accepts {
            assert!(
                row.network.contains(':'),
                "network {:?} is not CAIP-2; v2 rejects the v1 friendly form",
                row.network
            );
            assert!(row.network.len() >= 3);
        }
    }

    #[test]
    fn the_friendly_v1_network_name_would_fail_the_same_check() {
        // Over-correction control. Without this, the assertion above passes just
        // as happily against a gate that stopped emitting a network at all, or
        // one whose check cannot distinguish the form it exists to reject.
        let mut c = cfg();
        c.network = "solana-devnet".into();
        let ch = c.challenge("n");
        assert!(
            !ch.accepts[0].network.contains(':'),
            "the v1 spelling must still be recognisable as non-CAIP-2"
        );
    }

    #[test]
    fn the_required_resource_object_is_present_and_within_spec_limits() {
        let c = cfg().challenge("n");
        assert!(
            !c.resource.url.is_empty(),
            "resource.url is required non-empty"
        );
        assert_eq!(c.resource.mime_type, "application/json");
        // ResourceInfoSchema: serviceName min 1, max 32, printable ASCII.
        let sn = &c.resource.service_name;
        assert!(
            (1..=32).contains(&sn.len()),
            "serviceName length {}",
            sn.len()
        );
        assert!(
            sn.chars().all(|ch| ('\x20'..='\x7e').contains(&ch)),
            "serviceName must be printable ASCII"
        );
        // tags: max 5 entries, each min 1 / max 32 printable ASCII.
        assert!(c.resource.tags.len() <= 5, "max 5 tags");
        for t in &c.resource.tags {
            assert!((1..=32).contains(&t.len()), "tag {t:?} length");
            assert!(t.chars().all(|ch| ('\x20'..='\x7e').contains(&ch)));
        }
    }

    #[test]
    fn the_memo_is_in_the_scheme_defined_place_as_well_as_the_legacy_one() {
        // scheme_exact_svm.md puts the seller-defined memo at accepts[].extra.memo
        // and says the client MUST use it as the Memo data. Top-level `extra` is
        // retained for older clients, so BOTH must carry the same nonce.
        let c = cfg().challenge("bind-me");
        assert_eq!(c.extra.memo, "bind-me", "legacy top-level location");
        for row in &c.accepts {
            assert_eq!(row.extra.memo, "bind-me", "v2 scheme location");
        }
    }

    #[test]
    fn the_payment_required_header_decodes_back_to_the_body() {
        // v2's HTTP transport carries PaymentRequired in a base64 header, and the
        // reference client reads only that. Serving a header that disagrees with
        // the body would be worse than serving none.
        let c = cfg().challenge("hdr-nonce");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(c.to_payment_required_header())
            .expect("header is valid base64");
        let s = String::from_utf8(decoded).expect("header decodes to UTF-8");
        assert_eq!(s, c.to_json(), "header and body must not diverge");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["x402Version"], 2);
        assert!(v["resource"]["url"].is_string());
    }

    /// A SPONSORED payment: the fee payer and the token authority are DIFFERENT accounts, both
    /// signing. This is the shape the x402 SVM scheme defines via `extra.feePayer`.
    ///
    /// It exists because every other fixture here has payer == authority, so the whole suite went
    /// green both before and after the cap was re-keyed. A change nothing can distinguish is a
    /// change nothing is testing.
    fn build_sponsored_header(
        cfg: &GateConfig,
        sponsor_seed: u8,
        authority_seed: u8,
        amount: u64,
        nonce: &str,
    ) -> String {
        let (sponsor_seed, authority_seed) = ([sponsor_seed; 32], [authority_seed; 32]);
        let sponsor = Pubkey::new(pubkey_from_seed(&sponsor_seed));
        let authority = Pubkey::new(pubkey_from_seed(&authority_seed));
        let our_ata =
            Pubkey::associated_token_address(&cfg.seller_wallet, &cfg.mint, &token_program());
        let src_ata = Pubkey::associated_token_address(&authority, &cfg.mint, &token_program());

        let mut data = vec![TRANSFER_CHECKED_TAG];
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(6);
        let transfer = Instruction {
            program_id: token_program(),
            accounts: vec![
                AccountMeta::writable(src_ata, false),
                AccountMeta::readonly(cfg.mint, false),
                AccountMeta::writable(our_ata, false),
                AccountMeta::readonly(authority, true), // signs, but is NOT the fee payer
            ],
            data,
        };
        let memo = memo_ix(&sponsor, nonce.as_bytes());
        // Fee payer is the SPONSOR, so it lands at account_keys[0].
        let msg = compile(&sponsor, &[transfer, memo], &[9u8; 32]).unwrap();
        let body = msg.serialize_legacy();

        // Two required signers now, so two signatures, in signer-prefix order rather than assumed.
        let n = msg.num_required_signatures as usize;
        assert_eq!(n, 2, "fixture expects sponsor + authority to both sign");
        let sigs: Vec<[u8; 64]> = msg.account_keys[..n]
            .iter()
            .map(|k| {
                let seed = if *k == sponsor {
                    sponsor_seed
                } else if *k == authority {
                    authority_seed
                } else {
                    panic!("unexpected signer in the prefix")
                };
                sign_message(&seed, &body)
            })
            .collect();
        let raw_tx = serialize_transaction(&sigs, &body);
        let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_tx);
        base64::engine::general_purpose::STANDARD.encode(
            serde_json::json!({"x402Version": 2, "payload": {"transaction": tx_b64}}).to_string(),
        )
    }

    /// THE CAP METERS THE TOKEN AUTHORITY, NOT THE FEE PAYER. Keyed on the fee payer, a buyer
    /// behind rotating sponsors spends past their own ceiling while every payment verifies.
    #[test]
    fn the_cap_meters_the_token_authority_not_the_fee_payer() {
        let cfg = cfg();
        let sponsor = Pubkey::new(pubkey_from_seed(&[41u8; 32]));
        let authority = Pubkey::new(pubkey_from_seed(&[42u8; 32]));
        let header = build_sponsored_header(&cfg, 41, 42, cfg.price_single, "sp1");
        let v = verify_x_payment(&cfg, &header, "sp1").expect("a sponsored payment is valid");

        assert_ne!(sponsor, authority, "fixture must use two distinct accounts");
        assert_eq!(
            v.payer, authority,
            "the cap identity must be the token authority whose USDC moved"
        );
        assert_eq!(
            v.fee_payer, sponsor,
            "the fee payer is still recorded, just not metered"
        );
    }

    /// CONTROL: with no sponsor the two collapse to one account, which is the ordinary case and
    /// must be unaffected. Without this, the test above is equally consistent with the cap having
    /// been re-keyed to something arbitrary.
    #[test]
    fn without_a_sponsor_the_authority_and_fee_payer_are_the_same_account() {
        let cfg = cfg();
        let header = build_header(&cfg, 7, cfg.price_single, "sp2");
        let v = verify_x_payment(&cfg, &header, "sp2").unwrap();
        assert_eq!(v.payer, v.fee_payer, "self-paid: one account in both roles");
        assert_eq!(v.payer, Pubkey::new(pubkey_from_seed(&[7; 32])));
    }

    /// The menu must NOT advertise an entitlement the gate does not grant. It offered a day pass
    /// at 5x for "unlimited reads this UTC day" and delivered exactly one read, because the nonce
    /// burns on first use and nothing consulted the flag.
    #[test]
    fn the_menu_no_longer_advertises_an_ungranted_day_pass() {
        let c = cfg().challenge("menu-nonce");
        let json = c.to_json();
        assert!(
            !json.contains("day pass"),
            "the menu still advertises a day pass; nothing grants one: {json}"
        );
        assert_eq!(c.accepts.len(), 1, "exactly one tier should be offered");
        // CONTROL: the single tier IS still advertised, so this is not passing on an empty menu.
        assert!(
            json.contains("one feed reading"),
            "the single-read tier must still be offered: {json}"
        );
    }

    /// Withdrawing the offer must not strand a client holding a cached challenge. The amount is
    /// still accepted; it simply buys what the single read buys.
    #[test]
    fn a_cached_day_pass_amount_is_still_honoured_not_refused() {
        let cfg = cfg();
        let header = build_header(&cfg, 9, cfg.price_day_pass, "cached");
        let v = verify_x_payment(&cfg, &header, "cached")
            .expect("a client on the old menu must still be served, not refused");
        assert_eq!(v.amount, cfg.price_day_pass);
        assert!(
            v.is_day_pass,
            "the receipt still records which amount was paid"
        );
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
        assert!(ledger
            .commit(&payer, "a", day, 5_000_000, cfg.daily_cap)
            .is_ok());
        assert!(ledger
            .commit(&payer, "b", day, 5_000_000, cfg.daily_cap)
            .is_ok());
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
        assert!(ledger
            .commit(&payer, "d", day + 1, 5_000_000, cfg.daily_cap)
            .is_ok());
    }

    #[test]
    fn within_cap_predicate_matches_commit() {
        let cfg = cfg();
        let payer = Pubkey::new(pubkey_from_seed(&[8; 32]));
        let mut ledger = DailyLedger::new();
        let day = 20_001;
        assert!(ledger.within_cap(&payer, day, cfg.daily_cap, cfg.daily_cap));
        assert!(!ledger.within_cap(&payer, day, cfg.daily_cap + 1, cfg.daily_cap));
        ledger
            .commit(&payer, "x", day, cfg.daily_cap, cfg.daily_cap)
            .unwrap();
        assert!(!ledger.within_cap(&payer, day, 1, cfg.daily_cap));
    }

    #[test]
    fn settlement_header_is_base64_json_receipt() {
        let payer = Pubkey::new(pubkey_from_seed(&[7; 32]));
        // CAIP-2, matching what the gate now puts in a real receipt: the SVM
        // `exact` scheme's SettlementResponse carries the same network form.
        let h = settlement_header("5xSig", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", &payer);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&h)
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(v["success"], true);
        assert_eq!(v["transaction"], "5xSig");
    }

    // ---- ledger rebuild across a restart -------------------------------------
    //
    // The unit is Restart=always and the ledger lived only in memory, so every
    // restart handed each payer a fresh full allowance. These pin that it no longer
    // does, and the last one is the control: it shows the assertions can fail, by
    // running the same scenario WITHOUT the rebuild and requiring the cap to reopen.
    // Without that, all three would pass just as happily against a no-op rehydrate.

    fn earning(payer: &Pubkey, day: i64, amount: u64, nonce: Option<&str>) -> EarningRecord {
        EarningRecord {
            day,
            payer: payer.to_base58(),
            amount,
            nonce: nonce.map(str::to_string),
        }
    }

    #[test]
    fn rehydrate_restores_spend_so_a_restart_does_not_reopen_the_daily_cap() {
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let cap = 1_000;
        let mut fresh = DailyLedger::new();
        let applied = fresh.rehydrate([earning(&payer, 42, 900, Some("n1"))]);
        assert_eq!(applied, 1);

        // 900 already spent today, so 200 more must not fit under a 1000 cap.
        assert!(!fresh.within_cap(&payer, 42, 200, cap));
        assert!(fresh.within_cap(&payer, 42, 100, cap));
    }

    #[test]
    fn rehydrate_is_scoped_to_its_own_day_and_payer() {
        let a = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let b = Pubkey::new(pubkey_from_seed(&[10; 32]));
        let cap = 1_000;
        let mut l = DailyLedger::new();
        l.rehydrate([earning(&a, 42, 900, None)]);

        // A different payer, and the same payer on a different day, both start clean.
        assert!(l.within_cap(&b, 42, 900, cap));
        assert!(l.within_cap(&a, 43, 900, cap));
    }

    #[test]
    fn rehydrate_restores_nonces_so_a_replayed_payment_is_still_refused() {
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let mut l = DailyLedger::new();
        l.rehydrate([earning(&payer, 42, 10, Some("memo-abc"))]);
        assert!(matches!(
            l.commit(&payer, "memo-abc", 42, 10, 1_000),
            Err(Reject::NonceReused)
        ));
        // A nonce it never saw is still spendable, so this is not refusing everything.
        assert!(l.commit(&payer, "memo-xyz", 42, 10, 1_000).is_ok());
    }

    #[test]
    fn a_record_without_a_nonce_still_restores_its_spend() {
        // Lines written before the gate recorded the memo. The half that bounds money
        // must survive them; only the replay half is unavailable.
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let mut l = DailyLedger::new();
        l.rehydrate([earning(&payer, 42, 900, None)]);
        assert!(!l.within_cap(&payer, 42, 200, 1_000));
        assert!(l.commit(&payer, "any-memo", 42, 50, 1_000).is_ok());
    }

    // ---- reserve / confirm / release -----------------------------------------
    //
    // The gate used to record the spend and burn the nonce BEFORE broadcasting, with no
    // rollback, so a payment that never settled still consumed the payer's day. Splitting
    // the write into a hold and a resolution is what fixes that, and the hold is also what
    // keeps the cap safe to enforce across the settlement round trip.

    #[test]
    fn a_released_reservation_leaves_no_trace_at_all() {
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let mut l = DailyLedger::new();
        let r = l.reserve(&payer, "n", 42, 400, 1_000).unwrap();
        assert_eq!(l.total_settled(), 400, "the hold is real while it is held");

        l.release(r);
        assert_eq!(
            l.total_settled(),
            0,
            "released money must not read as settled"
        );
        assert_eq!(
            l.redeemed_nonce_count(),
            0,
            "the nonce must be spendable again"
        );
        assert_eq!(
            l.tracked_payer_days(),
            0,
            "an emptied row would count a payer who bought nothing"
        );
        assert!(
            l.within_cap(&payer, 42, 1_000, 1_000),
            "the whole day is free again"
        );
        // And the same payment can now be retried, which is the point: the failure was
        // not the buyer's.
        assert!(l.reserve(&payer, "n", 42, 400, 1_000).is_ok());
    }

    #[test]
    fn a_confirmed_reservation_stays_and_keeps_its_nonce_burned() {
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let mut l = DailyLedger::new();
        let r = l.reserve(&payer, "n", 42, 400, 1_000).unwrap();
        l.confirm(r);
        assert_eq!(l.total_settled(), 400);
        assert_eq!(l.redeemed_nonce_count(), 1);
        assert!(matches!(
            l.reserve(&payer, "n", 42, 1, 1_000),
            Err(Reject::NonceReused)
        ));
    }

    /// THE CONCURRENCY QUESTION, answered as a test rather than as an argument.
    ///
    /// A `within_cap` check followed by a later write is a check-then-act: two requests
    /// that both read before either wrote would both be told there was room, and the pair
    /// would settle past the cap. Reserving decides and takes inside one critical section,
    /// so the second request sees the first one's hold even though nothing has settled.
    ///
    /// The gate is single-threaded today, so this cannot happen in the shipped binary. It
    /// is asserted anyway because the ledger sits behind a `Mutex`, which is a promise the
    /// type makes to any future caller, and because the settlement round trip inside the
    /// request is exactly the reason someone would add a worker pool.
    #[test]
    fn a_second_request_cannot_slip_under_the_cap_while_the_first_is_in_flight() {
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let cap = 1_000;
        let mut l = DailyLedger::new();

        // First payment is reserved and still settling: nothing is confirmed yet.
        let first = l.reserve(&payer, "a", 42, 700, cap).unwrap();

        // A concurrent second payment must be refused on the HELD total, not on the
        // settled one, which is still zero.
        assert_eq!(
            l.reserve(&payer, "b", 42, 700, cap),
            Err(Reject::DailyCapExceeded {
                would_be: 1_400,
                cap
            }),
            "an in-flight payment must count against the cap while it is in flight"
        );

        // CONTROL: the refusal is about the cap and not about refusing everything. A
        // payment that genuinely fits is still accepted while the first is in flight.
        let small = l.reserve(&payer, "c", 42, 300, cap).unwrap();
        l.confirm(first);
        l.confirm(small);
        assert_eq!(l.total_settled(), 1_000);
    }

    /// CONTROL for the case above: once the in-flight payment is RELEASED, the room it was
    /// holding really does come back. Without this, the assertion above is equally
    /// consistent with a reservation that permanently consumes the cap.
    #[test]
    fn releasing_an_in_flight_payment_frees_the_room_it_was_holding() {
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let cap = 1_000;
        let mut l = DailyLedger::new();
        let first = l.reserve(&payer, "a", 42, 700, cap).unwrap();
        assert!(l.reserve(&payer, "b", 42, 700, cap).is_err());

        l.release(first);
        assert!(
            l.reserve(&payer, "b", 42, 700, cap).is_ok(),
            "the released room never came back"
        );
    }

    /// A release must give back exactly what its own hold took, and nothing that was
    /// already settled in the same row.
    ///
    /// This case is why [`Reservation`] is not `Clone`. Written first with a double
    /// release, it went red: the second subtraction came out of the settled 100 sitting
    /// beside the hold and took the row to zero, so a stray extra release erased real
    /// revenue. Dropping `Clone` makes that a compile error rather than a runtime hazard,
    /// which is what the type's own doc had been claiming all along.
    #[test]
    fn a_release_returns_its_own_hold_and_leaves_settled_money_alone() {
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let mut l = DailyLedger::new();
        l.commit(&payer, "settled", 42, 100, 1_000).unwrap();
        let held = l.reserve(&payer, "inflight", 42, 900, 1_000).unwrap();
        assert_eq!(
            l.total_settled(),
            1_000,
            "settled plus held while in flight"
        );

        l.release(held);
        assert_eq!(
            l.total_settled(),
            100,
            "the settled payment beside the hold must survive the release"
        );
        assert!(
            !l.within_cap(&payer, 42, 901, 1_000),
            "the settled 100 must still count against the day"
        );
        assert!(l.within_cap(&payer, 42, 900, 1_000));
    }

    /// The control that keeps the case above honest, since a compile-time property cannot
    /// be exercised at runtime: re-adding `Clone` to `Reservation` would silently restore
    /// the double release, and nothing else in this suite would notice.
    ///
    /// Source-level, like the lockfile scope guard in the binary, because that is the only
    /// instrument available without pulling in a compile-fail harness.
    #[test]
    fn the_reservation_type_is_still_not_cloneable() {
        let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
            .expect("the crate can read its own source");

        let derive_above = |struct_line: &str| -> String {
            let at = src
                .find(struct_line)
                .unwrap_or_else(|| panic!("{struct_line} not found"));
            src[..at]
                .lines()
                .rev()
                .find(|l| l.trim_start().starts_with("#[derive("))
                .unwrap_or_else(|| panic!("no derive above {struct_line}"))
                .to_string()
        };

        let reservation = derive_above("pub struct Reservation {");
        assert!(
            !reservation.contains("Clone"),
            "Reservation became Clone again, which re-enables the double release: {reservation}"
        );

        // POSITIVE CONTROL. Without it, a helper that always returned a Clone-free string
        // (a bad search, a renamed struct, an empty read) would pass the assertion above
        // while checking nothing at all.
        let earning = derive_above("pub struct EarningRecord {");
        assert!(
            earning.contains("Clone"),
            "the check cannot detect Clone at all, so its verdict above is worthless: {earning}"
        );
    }

    #[test]
    fn control_without_the_rebuild_a_restart_does_reopen_the_cap() {
        // The assertions above are only meaningful if they would notice a rehydrate
        // that did nothing. This is that scenario: same payer, same day, same prior
        // spend, no rebuild. The full allowance is available again, which is the
        // defect the rebuild exists to remove.
        let payer = Pubkey::new(pubkey_from_seed(&[9; 32]));
        let restarted = DailyLedger::new();
        assert!(restarted.within_cap(&payer, 42, 1_000, 1_000));
    }
}
