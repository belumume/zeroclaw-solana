//! Durable-nonce ACCOUNT decoding: the 80-byte state a `getAccountInfo` on a
//! nonce account returns. Layout validated against a `bincode`-serialized
//! `solana_program::nonce::state::Versions` fixture (vecgen, 2026-07-20).
//!
//! Layout: version u32 LE (0 Legacy | 1 Current), state u32 LE (0 Uninitialized
//! | 1 Initialized), authority 32 bytes, durable nonce 32 bytes,
//! lamports_per_signature u64 LE.
//!
//! IMPORTANT semantic (proved by the fixture): the stored durable nonce is NOT
//! the raw blockhash it was created from — the runtime domain-hashes it
//! (`DurableNonce::from_blockhash`). Always USE THE STORED VALUE as the
//! transaction's recent_blockhash; never recompute it.

use crate::pubkey::Pubkey;

pub const NONCE_ACCOUNT_LEN: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    TooShort(usize),
    UnknownVersion(u32),
    /// The account exists but was never initialized as a nonce.
    Uninitialized,
    UnknownState(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceState {
    pub authority: Pubkey,
    /// Use this as `recent_blockhash` when compiling a durable transaction.
    pub durable_nonce: [u8; 32],
    pub lamports_per_signature: u64,
}

pub fn decode_nonce_account(data: &[u8]) -> Result<NonceState, NonceError> {
    if data.len() < NONCE_ACCOUNT_LEN {
        return Err(NonceError::TooShort(data.len()));
    }
    let version = u32::from_le_bytes(data[0..4].try_into().expect("bounds checked"));
    if version > 1 {
        return Err(NonceError::UnknownVersion(version));
    }
    let state = u32::from_le_bytes(data[4..8].try_into().expect("bounds checked"));
    match state {
        0 => Err(NonceError::Uninitialized),
        1 => Ok(NonceState {
            authority: Pubkey::new(data[8..40].try_into().expect("bounds checked")),
            durable_nonce: data[40..72].try_into().expect("bounds checked"),
            lamports_per_signature: u64::from_le_bytes(
                data[72..80].try_into().expect("bounds checked"),
            ),
        }),
        s => Err(NonceError::UnknownState(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Reference bytes from `bincode::serialize(&Versions::new(State::Initialized(
    /// Data::new([3;32], DurableNonce::from_blockhash([9;32]), 5000))))`.
    const NONCE_STATE: &str = "010000000100000003030303030303030303030303030303030303030303030303030303030303031d61423f9b450b3bac58d730f29a6297925ae3993c13b36b0868e64e5806cbde8813000000000000";

    #[test]
    fn reference_nonce_state_decodes() {
        let s = decode_nonce_account(&from_hex(NONCE_STATE)).unwrap();
        assert_eq!(s.authority, Pubkey::new([3u8; 32]));
        assert_eq!(s.lamports_per_signature, 5000);
        // The domain-hash fact: stored nonce differs from the source blockhash.
        assert_ne!(s.durable_nonce, [9u8; 32]);
        assert_eq!(
            s.durable_nonce.to_vec(),
            from_hex("1d61423f9b450b3bac58d730f29a6297925ae3993c13b36b0868e64e5806cbde"),
        );
    }

    #[test]
    fn uninitialized_fails_closed() {
        let mut data = from_hex(NONCE_STATE);
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(decode_nonce_account(&data), Err(NonceError::Uninitialized));
    }

    #[test]
    fn unknown_version_and_state_fail_closed() {
        let mut data = from_hex(NONCE_STATE);
        data[0..4].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            decode_nonce_account(&data),
            Err(NonceError::UnknownVersion(7))
        );
        let mut data2 = from_hex(NONCE_STATE);
        data2[4..8].copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(
            decode_nonce_account(&data2),
            Err(NonceError::UnknownState(9))
        );
    }

    #[test]
    fn short_data_fails_closed() {
        assert_eq!(
            decode_nonce_account(&[0u8; 40]),
            Err(NonceError::TooShort(40))
        );
    }
}
