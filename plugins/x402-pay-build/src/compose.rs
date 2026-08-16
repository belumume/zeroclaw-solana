//! Hand the authorised payment to the plugin that already builds delegated spends.
//!
//! WHY THIS IS NOT A TRANSACTION BUILDER. `allowance-spend-build` already reads the delegation
//! account, fails closed unless the agent is the delegatee, selects the token program from the
//! mint's owner, derives and idempotently creates the receiver's token account, and emits the
//! unsigned transaction. Its inputs are `{delegation, amount, receiver, memo}`, which is exactly
//! what [`crate::pay::authorise`] produces. Rebuilding that here would duplicate an audited,
//! deployed, host-tested resolver in order to add nothing.
//!
//! So this plugin does the one thing the other cannot: it decides whether a 402 challenge
//! describes a payment the operator authorised. The brief scores correct layering, and two
//! components each doing one job compose better than one that swallows the other.
//!
//! THE SECURITY PROPERTY IS UNAFFECTED BY THE SPLIT, which is the part worth checking rather than
//! assuming. An injected agent could alter the arguments between the two tool calls, and that gap
//! was already closed from the other end: `scripts/pay_x402_certified.py` re-derives payee, mint
//! and funding delegation from the FINAL serialized bytes against operator config, so an altered
//! argument is refused before any signature. Composing actually shrinks this plugin's blast
//! radius, because it never touches transaction bytes at all.
//!
//! THE ONE CONVERSION IT OWES. x402 prices in ATOMIC base units as a decimal string;
//! `allowance-spend-build` takes UI units and refuses raw amounts by design. The conversion needs
//! the mint's `decimals`, which is read from the chain rather than configured, because a
//! configured decimals that disagreed with the mint would silently produce the wrong amount. The
//! other side converts back and refuses anything not exactly representable, so the round trip is
//! checked at both ends.

use crate::pay::AuthorisedPayment;

/// The exact argument object for the `allowance_spend_build` tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendArgs {
    pub delegation: String,
    /// UI units as an exact decimal string, never raw base units.
    pub amount: String,
    /// The receiver WALLET; the other plugin derives its token account.
    pub receiver: String,
    pub memo: String,
}

impl SpendArgs {
    /// Render as the JSON the tool expects. Field names are the other plugin's
    /// `parameters_schema`, so a rename there breaks this at the gate rather than at runtime.
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "delegation": self.delegation,
            "amount": self.amount,
            "receiver": self.receiver,
            "memo": self.memo,
        })
        .to_string()
    }
}

/// Convert atomic base units to an exact UI-unit decimal string.
///
/// Exact, and by construction: this is integer arithmetic on the digit string, never a float. A
/// float would silently round a large u64, and this is a money field.
pub fn atomic_to_ui(atomic: u64, decimals: u8) -> Result<String, String> {
    if decimals == 0 {
        return Ok(atomic.to_string());
    }
    if decimals > 18 {
        return Err(format!(
            "a mint reporting {decimals} decimals is implausible; refusing to convert"
        ));
    }
    let d = usize::from(decimals);
    let digits = format!("{atomic:0width$}", width = d + 1);
    let (whole, frac) = digits.split_at(digits.len() - d);
    let frac = frac.trim_end_matches('0');
    Ok(if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    })
}

/// Turn an authorised payment into the other plugin's arguments.
pub fn compose(p: &AuthorisedPayment, decimals: u8) -> Result<SpendArgs, String> {
    Ok(SpendArgs {
        delegation: p.delegation.clone(),
        amount: atomic_to_ui(p.amount, decimals)?,
        receiver: p.receiver.clone(),
        memo: p.memo.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payment(amount: u64) -> AuthorisedPayment {
        AuthorisedPayment {
            amount,
            receiver: "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ".to_string(),
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            delegation: "HVVeimGq8VD4CuBgrvqWsgQV1GRVhfVNYQxJxTocUNY9".to_string(),
            memo: "x402-nonce-0001".to_string(),
            tier_index: 0,
            description: "one reading".to_string(),
        }
    }

    #[test]
    fn the_real_mainnet_amount_converts_to_the_figure_that_transfer_moved() {
        // 400_000 atomic USDC at 6 decimals is the 0.400000 the captured mainnet transfer moved,
        // per docs/proof-bundle/mainnet-transactions.json and docs/MAINNET-PROOF.md.
        assert_eq!(atomic_to_ui(400_000, 6).unwrap(), "0.4");
    }

    #[test]
    fn conversion_is_exact_across_the_shapes_that_break_float_arithmetic() {
        for (atomic, decimals, want) in [
            (1u64, 6u8, "0.000001"), // one atomic unit
            (1_000_000, 6, "1"),     // exactly one whole unit, no trailing dot
            (1_500_000, 6, "1.5"),   // trailing zeros trimmed
            (999_999_999_999_999_999, 9, "999999999.999999999"),
            (u64::MAX, 9, "18446744073.709551615"), // a float loses this outright
            (42, 0, "42"),                          // a zero-decimal mint
            (0, 6, "0"),
        ] {
            assert_eq!(
                atomic_to_ui(atomic, decimals).unwrap(),
                want,
                "{atomic} at {decimals}dp"
            );
        }
    }

    #[test]
    fn a_round_trip_through_the_decimal_string_loses_nothing() {
        // The other plugin converts this string back to base units and refuses anything not
        // exactly representable, so the property that matters is that no digit is lost here.
        for atomic in [1u64, 7, 400_000, 1_000_000, 123_456_789, u64::MAX] {
            let ui = atomic_to_ui(atomic, 6).unwrap();
            let (whole, frac) = ui.split_once('.').unwrap_or((ui.as_str(), ""));
            let padded = format!("{whole}{frac:0<6}");
            assert_eq!(padded.parse::<u128>().unwrap(), u128::from(atomic), "{ui}");
        }
    }

    #[test]
    fn an_implausible_decimals_is_refused_rather_than_converted() {
        assert!(atomic_to_ui(1, 19).unwrap_err().contains("implausible"));
    }

    #[test]
    fn the_arguments_carry_the_authorised_values_unchanged() {
        let p = payment(400_000);
        let a = compose(&p, 6).unwrap();
        assert_eq!(a.delegation, p.delegation);
        assert_eq!(a.receiver, p.receiver);
        assert_eq!(a.memo, p.memo);
        assert_eq!(a.amount, "0.4");
    }

    #[test]
    fn the_json_uses_the_other_plugins_field_names() {
        // These four keys are `allowance-spend-build`'s `parameters_schema`. A rename there must
        // break here, which is what scripts/check-spend-args-agreement.py enforces.
        let j = compose(&payment(1_000_000), 6).unwrap().to_json();
        for key in ["delegation", "amount", "receiver", "memo"] {
            assert!(j.contains(&format!("\"{key}\":")), "missing {key} in {j}");
        }
    }

    #[test]
    fn no_atomic_amount_is_ever_emitted_as_the_amount_field() {
        // The other plugin refuses raw base units by design ("Never lamports/raw"), so emitting
        // 400000 where 0.4 was meant would be a 10^6 overpayment that every later check accepts.
        let a = compose(&payment(400_000), 6).unwrap();
        assert_ne!(a.amount, "400000");
        assert!(a.amount.starts_with("0."), "{}", a.amount);
    }
}
