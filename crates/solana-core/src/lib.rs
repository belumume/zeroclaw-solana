//! `solana-core` — a wasm32-wasip2-friendly Solana core for ZeroClaw plugins.
//!
//! Pure Rust with no wasm dependency: this crate is host-testable with
//! `cargo test` and compiles cleanly to `wasm32-wasip2`. Plugins depend on it by
//! path and build the `cdylib` component themselves (pure-core / thin-shim).
//!
//! Modules land incrementally; each is host-tested before it ships:
//! - [`sanitize`] — untrusted on-chain output sanitization (the response-path
//!   indirect-injection defense).
//! - [`pubkey`] — base58 codec, on-curve test, PDA + ATA derivation (validated
//!   differentially against the solana-program reference impl).
//! - [`rpc`] — JSON-RPC transport seam, generic client, injectable mock.
//! - [`mint`] — SPL / Token-2022 mint decoding with bounds-checked TLV scan.
//! - [`shortvec`] — compact-u16 length codec (known-answer boundary vectors).
//! - [`instruction`] — instruction builders (transfer, memo, advance-nonce).
//! - [`message`] — legacy + v0 compile/serialize, byte-validated against
//!   `solana_program::message` reference fixtures.
//! - [`signing`] — deterministic ed25519 (RFC 8032 anchored); tx wire format.
//! - [`nonce`] — durable-nonce account decoding (reference bincode fixture).
//! - [`transport`] — the wasm-only `waki` transport (host builds never see it).
#![forbid(unsafe_code)]

pub mod anchor;
pub mod instruction;
pub mod message;
pub mod mint;
pub mod nonce;
pub mod pubkey;
pub mod rpc;
pub mod sanitize;
pub mod shortvec;
pub mod signing;
pub mod token;
pub mod tx_decode;
#[cfg(target_family = "wasm")]
pub mod transport;

pub use anchor::{account_sighash, instruction_sighash};
pub use instruction::{AccountMeta, Instruction};
pub use message::{compile, CompiledMessage, MessageError};
pub use mint::{decode_mint, DecodedMint, MintError, RawExtension};
pub use nonce::{decode_nonce_account, NonceError, NonceState};
pub use pubkey::{Pubkey, PubkeyError};
pub use rpc::{
    AccountInfo, Commitment, MockTransport, RpcError, RpcTransport, SignatureStatus, SolanaRpc,
};
pub use sanitize::{label_untrusted, sanitize_onchain, Sanitized, DEFAULT_LABEL_MAX};
pub use signing::{
    pubkey_from_seed, serialize_transaction, sign_message, verify_signature, SigningError,
};
pub use token::{find_payment, has_memo, FoundPayment, PaymentError};
pub use tx_decode::{decode_transaction, DecodeError, DecodedTransaction};
#[cfg(target_family = "wasm")]
pub use transport::WakiTransport;

/// Shorten a base58 identifier for display: `AAAA…ZZZZ`. Operates on CHARS, not
/// bytes, so an untrusted non-ASCII input (a Kamino `market` label read straight
/// from an HTTP response — NOT a validated pubkey) can never panic on a
/// non-char-boundary byte slice. The three plugins share this one copy.
pub fn short_pubkey(pk: &str) -> String {
    let n = pk.chars().count();
    if n <= 9 {
        pk.to_string()
    } else {
        let head: String = pk.chars().take(4).collect();
        let tail: String = pk.chars().skip(n - 4).collect();
        format!("{head}\u{2026}{tail}")
    }
}

#[cfg(test)]
mod short_pubkey_tests {
    use super::short_pubkey;

    #[test]
    fn shortens_a_long_base58() {
        assert_eq!(
            short_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"),
            "EPjF…Dt1v"
        );
    }

    #[test]
    fn short_input_passes_through() {
        assert_eq!(short_pubkey("short"), "short");
    }

    #[test]
    fn non_ascii_input_does_not_panic() {
        // A non-base58 `market` label of 12 multibyte chars (>9): the old
        // byte-slicing `&pk[..4]` panicked mid-codepoint here; char-based does not.
        let m = "\u{4e2d}".repeat(12);
        assert_eq!(
            short_pubkey(&m),
            "\u{4e2d}\u{4e2d}\u{4e2d}\u{4e2d}\u{2026}\u{4e2d}\u{4e2d}\u{4e2d}\u{4e2d}"
        );
    }
}
