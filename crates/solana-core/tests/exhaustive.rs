//! Domains small enough to ENUMERATE rather than sample.
//!
//! The property tests next door sample 1024 cases each, which is the right tool when the
//! input space is large. It is the wrong tool when the space is small enough to walk, because
//! sampling 1024 of 65,536 leaves 98% of it unvisited and reports green either way. The
//! shortvec proof already applies this reasoning to a 3-byte header; this file is the result
//! of auditing the rest of the crate for spaces nobody had walked.
//!
//! The space walked here is the Token-2022 extension discriminant: a `u16`, so 65,535 live
//! values (0 is the padding sentinel that terminates the TLV walk). It earns the treatment
//! because `token-risk-check` derives a user-facing RED / AMBER / GREEN verdict from flags
//! keyed on six of those values, and the interesting question is not whether the six work.
//! It is whether any of the other 65,529 can reach a flag it should not.

use solana_core::mint::{
    decode_mint, DecodedMint, ACCOUNT_TYPE_OFFSET, EXT_DEFAULT_ACCOUNT_STATE,
    EXT_MINT_CLOSE_AUTHORITY, EXT_PAUSABLE, EXT_PERMANENT_DELEGATE, EXT_TRANSFER_FEE_CONFIG,
    EXT_TRANSFER_HOOK, LEGACY_MINT_LEN, TLV_START,
};

const KNOWN: [u16; 6] = [
    EXT_TRANSFER_FEE_CONFIG,
    EXT_MINT_CLOSE_AUTHORITY,
    EXT_DEFAULT_ACCOUNT_STATE,
    EXT_PERMANENT_DELEGATE,
    EXT_TRANSFER_HOOK,
    EXT_PAUSABLE,
];

/// A Token-2022 mint carrying exactly one TLV entry: `discriminant`, with `payload` bytes.
fn mint_with(discriminant: u16, payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; LEGACY_MINT_LEN];
    d[0] = 1; // mint authority present
    d[36..44].copy_from_slice(&1_000_000u64.to_le_bytes());
    d[44] = 6;
    d[45] = 1; // initialized
    d.resize(TLV_START, 0);
    d[ACCOUNT_TYPE_OFFSET] = 1; // AccountType::Mint
    d.extend_from_slice(&discriminant.to_le_bytes());
    d.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    d.extend_from_slice(payload);
    d
}

/// A payload that would light every risk flag if the discriminant were believed.
fn hot_payload() -> Vec<u8> {
    // 64 nonzero bytes covers PermanentDelegate's pubkey and TransferHook's
    // authority+program pair; byte 0 = 2 is DefaultAccountState's Frozen.
    let mut p = vec![0xAAu8; 108];
    p[0] = 2;
    p
}

/// Walk every live discriminant. Two claims, and the second is the one that matters.
#[test]
fn every_extension_discriminant_is_total_and_cannot_reach_a_flag_it_should_not() {
    let hot = hot_payload();
    let mut decoded_ok = 0u32;

    for discriminant in 1..=u16::MAX {
        // 1. Totality. Decoding must not panic for any discriminant, and a well-formed
        //    single-entry mint must not be rejected merely for carrying an unknown one:
        //    unknown extensions are the normal case on a chain that keeps adding them.
        let bytes = mint_with(discriminant, &hot);
        let m: DecodedMint = match decode_mint(&bytes, true) {
            Ok(m) => m,
            Err(e) => panic!("discriminant {discriminant} rejected a well-formed mint: {e:?}"),
        };
        decoded_ok += 1;

        // The raw entry survives regardless, so a caller can still see what it was.
        assert_eq!(m.extensions.len(), 1, "discriminant {discriminant}");
        assert_eq!(m.extensions[0].discriminant, discriminant);

        // 2. Flag isolation. Each risk flag fires for EXACTLY its own discriminant.
        //    A false positive would condemn a safe token; a false negative would let a
        //    mint with a real permanent delegate read as safe, which is the dangerous
        //    direction because the verdict is what a human acts on.
        assert_eq!(
            m.permanent_delegate_active(),
            discriminant == EXT_PERMANENT_DELEGATE,
            "permanent_delegate_active fired for discriminant {discriminant}"
        );
        assert_eq!(
            m.transfer_hook_program_active(),
            discriminant == EXT_TRANSFER_HOOK,
            "transfer_hook_program_active fired for discriminant {discriminant}"
        );
        assert_eq!(
            m.default_state_frozen(),
            discriminant == EXT_DEFAULT_ACCOUNT_STATE,
            "default_state_frozen fired for discriminant {discriminant}"
        );
        assert_eq!(
            m.transfer_fee_bps().is_some(),
            discriminant == EXT_TRANSFER_FEE_CONFIG,
            "transfer_fee_bps fired for discriminant {discriminant}"
        );

        // 3. Naming is honest: exactly the six live-verified discriminants are named,
        //    and an unknown one is reported as unknown rather than guessed at.
        assert_eq!(
            m.extensions[0].name().is_some(),
            KNOWN.contains(&discriminant),
            "name() disagreed about discriminant {discriminant}"
        );
    }

    assert_eq!(decoded_ok, 65_535, "every live discriminant should decode");
}

/// Zero is the padding sentinel, not a discriminant. Walking it separately keeps the
/// claim above exact rather than quietly excluding a value.
#[test]
fn discriminant_zero_terminates_the_walk_rather_than_becoming_an_extension() {
    let bytes = mint_with(0, &hot_payload());
    let m = decode_mint(&bytes, true).expect("zero-discriminant mint decodes");
    assert!(
        m.extensions.is_empty(),
        "a zero discriminant is padding and must not appear as an extension"
    );
    assert!(!m.permanent_delegate_active());
    assert!(!m.transfer_hook_program_active());
}

/// Every length a single TLV entry can declare, against a buffer that does not contain it.
/// The parse must reject rather than read past the end, for all 65,535 lengths.
#[test]
fn every_declared_tlv_length_that_overruns_is_refused() {
    let mut refused = 0u32;
    for len in 1..=u16::MAX {
        // Declare `len` bytes but supply none of them.
        let mut d = vec![0u8; LEGACY_MINT_LEN];
        d[0] = 1;
        d[45] = 1;
        d.resize(TLV_START, 0);
        d[ACCOUNT_TYPE_OFFSET] = 1;
        d.extend_from_slice(&EXT_PERMANENT_DELEGATE.to_le_bytes());
        d.extend_from_slice(&len.to_le_bytes());
        // No payload follows, so every non-zero declared length overruns.
        match decode_mint(&d, true) {
            Err(_) => refused += 1,
            Ok(m) => panic!("declared length {len} was accepted with no payload: {m:?}"),
        }
    }
    assert_eq!(refused, 65_535);
}
