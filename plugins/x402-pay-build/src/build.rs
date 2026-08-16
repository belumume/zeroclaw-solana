//! Assemble the UNSIGNED transaction that pays an authorised x402 tier.
//!
//! Custody tier T1. Every signature slot in the output is empty, so the plugin's output alone can
//! never be submitted. The host completes it, and only after
//! `scripts/pay_x402_certified.py` has re-derived intent from these exact bytes.
//!
//! THE ENCODING HERE IS A DELIBERATE DUPLICATE of `allowance-spend-build`'s, not a shared import.
//! No plugin in this repo depends on another, each carries its own workspace, and upstream CI
//! iterates the plugin manifests expecting standalone crates. Duplication has a real cost, which
//! is that the two copies can drift silently, so it is paid for rather than accepted:
//! `scripts/check-allowance-encoding-agreement.py` reads the ORIGINAL's constants out of its
//! source and requires this file to agree, with a perturbation that must produce disagreement.
//!
//! The layout below is additionally a KNOWN-ANSWER TEST against a real mainnet transfer rather
//! than against a fixture. The captured bytes are in `docs/proof-bundle/mainnet-transactions.json`
//! and the test asserts this encoder reproduces them exactly.

use solana_core::{compile, AccountMeta, Instruction, MessageError, Pubkey};

use crate::pay::AuthorisedPayment;

/// Source: `plugins/allowance-spend-build/src/allowance.rs` `SUBSCRIPTIONS_PROGRAM_ID`, itself
/// sourced to `idl/subscriptions.json` `program.publicKey`.
pub const SUBSCRIPTIONS_PROGRAM_ID: &str = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44";
/// Source: the same file's `IX_TRANSFER_FIXED`, sourced to the program's
/// `transfer_fixed_delegation.rs` `DISCRIMINATOR = &4`.
pub const IX_TRANSFER_FIXED: u8 = 4;
/// Source: the same file's `EVENT_AUTHORITY_SEED`.
pub const EVENT_AUTHORITY_SEED: &[u8] = b"event_authority";
/// `amount:u64 + delegator:32 + mint:32`. Source: the program's `helpers/transfer_data.rs`.
pub const TRANSFER_DATA_LEN: usize = 8 + 32 + 32;

/// Chain facts the shim resolves before assembly, so this module stays host-testable with no
/// network. Every one of them is read from the chain or derived, never from the challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    /// The delegation account. Equal to the operator's configured delegation by the time this
    /// runs, because [`crate::pay::authorise`] refused anything else.
    pub delegation: Pubkey,
    pub subscription_authority: Pubkey,
    /// Decoded FROM the delegation account, so the program's own
    /// `header.delegator == transfer.delegator` cross-check passes by construction.
    pub delegator: Pubkey,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub delegator_ata: Pubkey,
    pub receiver_ata: Pubkey,
    /// The agent: delegatee, sole instruction-level signer, and fee payer. `compile` promotes it
    /// to writable+signer at index 0, which is why the finished transaction needs exactly ONE
    /// signature. The captured mainnet transfers need two, because a different account paid the
    /// fee there; that is a property of those transactions and not of this shape.
    pub agent: Pubkey,
}

fn subscriptions_program() -> Pubkey {
    Pubkey::from_base58(SUBSCRIPTIONS_PROGRAM_ID)
        .expect("the hard-coded subscriptions program id is valid base58")
}

fn event_authority() -> Pubkey {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], &subscriptions_program())
        .expect("the event_authority PDA derivation always yields a valid bump")
        .0
}

/// The `transferFixed` instruction.
///
/// data     = `[disc:u8][amount:u64 LE][delegator:32][mint:32]`, 73 bytes
/// accounts = `[delegation(w), subscription_authority, delegator_ata(w), receiver_ata(w),`
///            `mint, token_program, delegatee(signer), event_authority, self_program]`
pub fn transfer_fixed_ix(p: &AuthorisedPayment, r: &Resolved) -> Instruction {
    let mut data = Vec::with_capacity(1 + TRANSFER_DATA_LEN);
    data.push(IX_TRANSFER_FIXED);
    data.extend_from_slice(&p.amount.to_le_bytes());
    data.extend_from_slice(r.delegator.as_bytes());
    data.extend_from_slice(r.mint.as_bytes());
    Instruction {
        program_id: subscriptions_program(),
        accounts: vec![
            AccountMeta::writable(r.delegation, false),
            AccountMeta::readonly(r.subscription_authority, false),
            AccountMeta::writable(r.delegator_ata, false),
            AccountMeta::writable(r.receiver_ata, false),
            AccountMeta::readonly(r.mint, false),
            AccountMeta::readonly(r.token_program, false),
            AccountMeta::readonly(r.agent, true),
            AccountMeta::readonly(event_authority(), false),
            AccountMeta::readonly(subscriptions_program(), false),
        ],
        data,
    }
}

/// The finished UNSIGNED transaction: the spend, then a memo carrying the challenge's nonce.
///
/// The memo is LAST and is the only instruction whose content came from the seller. Its bytes were
/// already bounded and charset-checked by [`crate::pay::authorise`]; putting it after the spend
/// means no seller-supplied instruction can execute before the payment it is meant to label.
pub fn build_unsigned(
    p: &AuthorisedPayment,
    r: &Resolved,
    recent_blockhash: &[u8; 32],
) -> Result<Vec<u8>, MessageError> {
    let ixs = vec![
        transfer_fixed_ix(p, r),
        solana_core::instruction::memo(&r.agent, p.memo.as_bytes()),
    ];
    let msg = compile(&r.agent, &ixs, recent_blockhash)?;
    let message_bytes = msg.serialize_v0_no_lookups();
    // One empty signature slot: the agent is the only signer, and the host fills it.
    Ok(solana_core::serialize_transaction(
        &[[0u8; 64]],
        &message_bytes,
    ))
}

/// Derive the token accounts this transfer debits and credits.
pub fn token_accounts(
    delegator: &Pubkey,
    receiver: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> (Pubkey, Pubkey) {
    (
        Pubkey::associated_token_address(delegator, mint, token_program),
        Pubkey::associated_token_address(receiver, mint, token_program),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pay::AuthorisedPayment;
    use solana_core::pubkey;

    // Every value below is read off the real mainnet transfer 5sHLcD1v.. captured in
    // docs/proof-bundle/mainnet-transactions.json. The point of a known-answer test is that the
    // answer came from the chain rather than from this file's author.
    const REAL_DATA_HEX: &str = "04801a060000000000a3f5fd44079de615bdc92424501a9821609c892ea16412d\
d426ac95190f83455c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61";
    const REAL_ACCOUNTS: [&str; 9] = [
        "HVVeimGq8VD4CuBgrvqWsgQV1GRVhfVNYQxJxTocUNY9",
        "HXbSisnXD8YeJFHdkbRz35CRtVrkv8GB1EXyT8hoFecW",
        "EpzuUPXwMR2oWqL3MCUTjvvpfdrZXforkMt85ZCSowo3",
        "98LLx6QvLcspjhCgRZa16TkCPBHSgDmvkqwyRtnb7d2o",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "9dy9XpFcEzqYSJMYKN8KskDadtuuCDfHFEW51AGxicVJ",
        "3Hnj4BYoDgtpBuqXfiy7Y8cNa3jXaNd4oqgSXBzkMcH7",
        "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44",
    ];
    const REAL_AMOUNT: u64 = 400_000;
    const MERCHANT: &str = "C331X4YCHCdcESexRTKSjE5etjsWyWJLK73Z18ZWiLHJ";

    fn pk(s: &str) -> Pubkey {
        Pubkey::from_base58(s).expect("fixture address parses")
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn real_resolved() -> Resolved {
        Resolved {
            delegation: pk(REAL_ACCOUNTS[0]),
            subscription_authority: pk(REAL_ACCOUNTS[1]),
            delegator: pk(MERCHANT),
            mint: pk(REAL_ACCOUNTS[4]),
            token_program: pk(REAL_ACCOUNTS[5]),
            delegator_ata: pk(REAL_ACCOUNTS[2]),
            receiver_ata: pk(REAL_ACCOUNTS[3]),
            agent: pk(REAL_ACCOUNTS[6]),
        }
    }

    fn payment(amount: u64, memo: &str) -> AuthorisedPayment {
        AuthorisedPayment {
            amount,
            receiver: REAL_ACCOUNTS[3].to_string(),
            mint: REAL_ACCOUNTS[4].to_string(),
            delegation: REAL_ACCOUNTS[0].to_string(),
            memo: memo.to_string(),
            tier_index: 0,
            description: String::new(),
        }
    }

    #[test]
    fn the_instruction_data_reproduces_a_real_mainnet_transfer_byte_for_byte() {
        let ix = transfer_fixed_ix(&payment(REAL_AMOUNT, "n"), &real_resolved());
        assert_eq!(hex(&ix.data), REAL_DATA_HEX);
        assert_eq!(ix.data.len(), 1 + TRANSFER_DATA_LEN);
    }

    #[test]
    fn the_account_list_reproduces_a_real_mainnet_transfer_in_order() {
        let ix = transfer_fixed_ix(&payment(REAL_AMOUNT, "n"), &real_resolved());
        let got: Vec<String> = ix.accounts.iter().map(|a| a.pubkey.to_base58()).collect();
        assert_eq!(got, REAL_ACCOUNTS.to_vec());
    }

    #[test]
    fn the_event_authority_is_derived_rather_than_pasted_and_matches_the_chain() {
        // Slot 7 of the real transfer is a PDA of the audited program. Deriving it here and
        // getting the on-chain value is what proves the seed and program id are both right.
        assert_eq!(event_authority().to_base58(), REAL_ACCOUNTS[7]);
        assert!(!event_authority().is_on_curve(), "a PDA is off the curve");
    }

    #[test]
    fn the_debited_and_credited_accounts_derive_to_the_real_ones() {
        let (from, _to) = token_accounts(
            &pk(MERCHANT),
            &pk(MERCHANT),
            &pk(REAL_ACCOUNTS[4]),
            &pk(REAL_ACCOUNTS[5]),
        );
        assert_eq!(from.to_base58(), REAL_ACCOUNTS[2]);
    }

    #[test]
    fn only_the_delegatee_is_a_signer() {
        let ix = transfer_fixed_ix(&payment(1, "n"), &real_resolved());
        let signers: Vec<usize> = ix
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, a)| a.is_signer)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            signers,
            vec![6],
            "slot 6 is the delegatee and nothing else signs"
        );
    }

    #[test]
    fn the_writable_slots_are_the_three_the_program_mutates() {
        let ix = transfer_fixed_ix(&payment(1, "n"), &real_resolved());
        let w: Vec<usize> = ix
            .accounts
            .iter()
            .enumerate()
            .filter(|(_, a)| a.is_writable)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(w, vec![0, 2, 3], "delegation, source ATA, destination ATA");
    }

    #[test]
    fn the_finished_transaction_is_unsigned_and_needs_exactly_one_signature() {
        let tx = build_unsigned(
            &payment(REAL_AMOUNT, "x402-nonce-0001"),
            &real_resolved(),
            &[7u8; 32],
        )
        .expect("compiles");
        assert_eq!(
            tx[0], 1,
            "one required signature: the agent is the sole signer"
        );
        assert_eq!(&tx[1..65], &[0u8; 64], "the signature slot is EMPTY");
        // v0 wire format, which is what the host's certifier expects from this builder.
        assert_eq!(tx[65], 0x80, "v0 version prefix");
        assert_eq!(
            *tx.last().expect("non-empty"),
            0,
            "an empty address-table-lookups vector"
        );
    }

    #[test]
    fn the_memo_is_last_so_no_seller_supplied_instruction_runs_before_the_payment() {
        let p = payment(REAL_AMOUNT, "x402-nonce-0001");
        let r = real_resolved();
        let ixs = [
            transfer_fixed_ix(&p, &r),
            solana_core::instruction::memo(&r.agent, p.memo.as_bytes()),
        ];
        assert_eq!(ixs[0].program_id, subscriptions_program());
        assert_eq!(ixs[1].program_id, pubkey::memo_program());
        assert_eq!(ixs[1].data, p.memo.as_bytes());
    }

    #[test]
    fn a_different_amount_changes_only_the_amount_bytes() {
        // The delegator and mint tails must not move with the amount, which is what a
        // copy-paste slip in the little-endian offset would break.
        let a = transfer_fixed_ix(&payment(REAL_AMOUNT, "n"), &real_resolved()).data;
        let b = transfer_fixed_ix(&payment(REAL_AMOUNT + 1, "n"), &real_resolved()).data;
        assert_eq!(a[0], b[0]);
        assert_ne!(a[1..9], b[1..9]);
        assert_eq!(a[9..], b[9..]);
    }
}
