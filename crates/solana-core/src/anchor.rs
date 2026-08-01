//! Anchor instruction/account discriminators, computed client-side so a
//! `wasm32-wasip2` tool-plugin can call an Anchor program WITHOUT depending on
//! `anchor-lang` (which does not build cleanly for wasip2 components).
//!
//! Anchor prepends every `#[program]` instruction's data with
//! `sha256("global:<name>")[..8]` and writes `sha256("account:<Name>")[..8]` at
//! the start of every `#[account]` struct. We reproduce that exactly, and prove
//! it against Anchor's own canonical `initialize` discriminator so the encoding
//! is validated against the reference, not asserted.

use sha2::{Digest, Sha256};

/// The 8-byte discriminator Anchor prepends to a `#[program]` instruction.
pub fn instruction_sighash(name: &str) -> [u8; 8] {
    sighash("global", name)
}

/// The 8-byte discriminator Anchor writes at the start of a `#[account]` struct.
pub fn account_sighash(name: &str) -> [u8; 8] {
    sighash("account", name)
}

fn sighash(namespace: &str, name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(namespace.as_bytes());
    h.update(b":");
    h.update(name.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_distinct_per_name() {
        assert_eq!(
            instruction_sighash("publish_reading"),
            instruction_sighash("publish_reading")
        );
        assert_ne!(
            instruction_sighash("publish_reading"),
            instruction_sighash("register_device")
        );
    }

    /// Known answer from the Anchor reference: the `initialize` instruction
    /// discriminator is `sha256("global:initialize")[..8]` =
    /// `afaf6d1f0d989bed` (the value every Anchor IDL emits). If our sighash
    /// drifts from Anchor's, every on-chain call would fail with a bad
    /// discriminator, so this vector is the contract with the deployed program.
    #[test]
    fn instruction_sighash_matches_anchor_initialize_reference() {
        assert_eq!(
            instruction_sighash("initialize"),
            [175, 175, 109, 31, 13, 152, 155, 237]
        );
    }

    /// Anchor account discriminators use the `account:` namespace with the
    /// PascalCase struct name. Distinct namespace ⇒ distinct value.
    #[test]
    fn account_and_instruction_namespaces_differ() {
        assert_ne!(
            account_sighash("DeviceFeed"),
            instruction_sighash("DeviceFeed")
        );
    }
}
