//! Decode a fully or partially signed Solana transaction back into its
//! signatures and [`CompiledMessage`] — the inverse of [`crate::message`]'s
//! serialize path. Handles both the legacy wire format and the v0 format
//! (`0x80` version prefix + a trailing address-table-lookups shortvec).
//!
//! This exists for the *verifier* side: an untrusted party hands us a signed
//! transaction (e.g. an x402 `X-PAYMENT` payload) and we must introspect its
//! instructions before trusting or broadcasting it. Everything here is a
//! bounds-checked forward parse with no panics on adversarial input.

use crate::message::{CompiledInstruction, CompiledMessage};
use crate::pubkey::Pubkey;
use crate::shortvec::decode_len;

/// A decoded transaction: the signature slots (64 bytes each, all-zero when a
/// slot is left unsigned) and the message they cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTransaction {
    pub signatures: Vec<[u8; 64]>,
    pub message: CompiledMessage,
    /// `true` when the message carried the v0 (`0x80`) version prefix.
    pub is_v0: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Ran off the end of the buffer mid-field.
    Truncated,
    /// A shortvec length prefix was malformed (non-minimal or truncated).
    BadLength,
    /// v0 message declared address-table lookups; this decoder does not resolve
    /// them (a payment transaction must inline its accounts), so we refuse
    /// rather than misattribute account indexes.
    AddressTableLookupsUnsupported,
    /// Trailing bytes remained after a complete parse.
    TrailingBytes(usize),
    /// The three message-header bytes disagree with the rest of the message.
    ///
    /// Solana's own `Message::sanitize()` enforces these, and a decoder that does
    /// not is unsound for any caller asking "did this key sign?": the header is
    /// what defines the signer prefix of `account_keys`, so an unvalidated header
    /// lets crafted bytes claim signers whose signatures are not present.
    MalformedHeader(&'static str),
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let slice = self.data.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn array32(&mut self) -> Result<[u8; 32], DecodeError> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }

    fn array64(&mut self) -> Result<[u8; 64], DecodeError> {
        let mut a = [0u8; 64];
        a.copy_from_slice(self.take(64)?);
        Ok(a)
    }

    /// Read a shortvec length prefix and advance past it.
    fn len(&mut self) -> Result<usize, DecodeError> {
        let rest = self.data.get(self.pos..).ok_or(DecodeError::Truncated)?;
        let (n, consumed) = decode_len(rest).map_err(|_| DecodeError::BadLength)?;
        self.pos += consumed;
        Ok(n as usize)
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

/// Decode a serialized transaction. Rejects v0 messages that use address-table
/// lookups and rejects any input with trailing bytes.
pub fn decode_transaction(bytes: &[u8]) -> Result<DecodedTransaction, DecodeError> {
    let mut c = Cursor::new(bytes);

    let sig_count = c.len()?;
    // Cap: a legit transaction is bounded well under this; the guard stops a
    // huge length prefix from forcing a giant allocation before the take fails.
    if sig_count > u8::MAX as usize {
        return Err(DecodeError::BadLength);
    }
    let mut signatures = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        signatures.push(c.array64()?);
    }

    let is_v0 = matches!(c.data.get(c.pos), Some(&b) if b & 0x80 != 0);
    if is_v0 {
        let prefix = c.u8()?;
        // Only version 0 is defined; the low 7 bits must be zero.
        if prefix & 0x7f != 0 {
            return Err(DecodeError::BadLength);
        }
    }

    let num_required_signatures = c.u8()?;
    let num_readonly_signed = c.u8()?;
    let num_readonly_unsigned = c.u8()?;

    let key_count = c.len()?;
    if key_count > 256 {
        return Err(DecodeError::BadLength);
    }
    let mut account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        account_keys.push(Pubkey::new(c.array32()?));
    }

    let recent_blockhash = c.array32()?;

    let ix_count = c.len()?;
    let mut instructions = Vec::with_capacity(ix_count.min(64));
    for _ in 0..ix_count {
        let program_id_index = c.u8()?;
        let acct_len = c.len()?;
        let account_indexes = c.take(acct_len)?.to_vec();
        let data_len = c.len()?;
        let data = c.take(data_len)?.to_vec();
        instructions.push(CompiledInstruction {
            program_id_index,
            account_indexes,
            data,
        });
    }

    if is_v0 {
        // Address-table-lookups vector. A payment transaction must inline its
        // accounts so we can attribute them; a non-empty lookups vector means
        // some accounts are off-message and we refuse rather than guess.
        let lookup_count = c.len()?;
        if lookup_count != 0 {
            return Err(DecodeError::AddressTableLookupsUnsupported);
        }
    }

    if c.remaining() != 0 {
        return Err(DecodeError::TrailingBytes(c.remaining()));
    }

    // Header invariants, mirroring solana-sdk's `Message::sanitize()`. Until these hold, the
    // signer prefix of `account_keys` is not backed by the signature vector, so ANY signer
    // question answered from this message is answerable with attacker-chosen bytes. The
    // signer check in `token::find_payment` depends on this running first.
    let req = num_required_signatures as usize;
    if signatures.len() != req {
        return Err(DecodeError::MalformedHeader(
            "signature count does not equal num_required_signatures",
        ));
    }
    if req > account_keys.len() {
        return Err(DecodeError::MalformedHeader(
            "num_required_signatures exceeds the account-key count",
        ));
    }
    // No `num_required_signatures != 0` carve-out. Real Solana rejects a zero here outright,
    // because the fee payer is always a required signer, and the plain `>=` gives that for free:
    // 0 >= 0 refuses. An earlier draft added the exception defensively and it was a DEVIATION from
    // the parity this function claims, which review caught. Not exploitable either way -- with
    // zero required signatures `is_signer` slices `account_keys[..0]` and nothing can be reported
    // as a signer, so `find_payment` would refuse every transfer rather than be fooled -- but a
    // docstring claiming `Message::sanitize` parity should not have a silent exception in it.
    if num_readonly_signed >= num_required_signatures {
        return Err(DecodeError::MalformedHeader(
            "num_readonly_signed is not less than num_required_signatures, or no signer is required",
        ));
    }
    if req + num_readonly_unsigned as usize > account_keys.len() {
        return Err(DecodeError::MalformedHeader(
            "signed plus readonly-unsigned exceeds the account-key count",
        ));
    }

    Ok(DecodedTransaction {
        signatures,
        message: CompiledMessage {
            num_required_signatures,
            num_readonly_signed,
            num_readonly_unsigned,
            account_keys,
            recent_blockhash,
            instructions,
        },
        is_v0,
    })
}

impl DecodedTransaction {
    /// Resolve an instruction's program id via its `program_id_index`.
    pub fn program_id_of(&self, ix: &CompiledInstruction) -> Option<&Pubkey> {
        self.message.account_keys.get(ix.program_id_index as usize)
    }

    /// Resolve the Nth account of an instruction to a pubkey.
    pub fn account_of(&self, ix: &CompiledInstruction, n: usize) -> Option<&Pubkey> {
        let idx = *ix.account_indexes.get(n)? as usize;
        self.message.account_keys.get(idx)
    }

    /// Whether `key` is in the message's signer prefix.
    ///
    /// Solana puts every required signer first in `account_keys`, so membership in the
    /// first `num_required_signatures` entries IS the signer set. This is only sound
    /// because `decode_transaction` refuses a message whose header disagrees with its
    /// signature vector; without that check a crafted message could name any key as a
    /// signer while supplying no signature for it.
    ///
    /// Note this answers "the message DECLARES this key as a signer", and nothing more.
    /// The runtime does reject a transaction whose declared signature is absent or
    /// invalid, so the declaration is load-bearing for anything that happens AT
    /// SETTLEMENT. It is worth nothing BEFORE settlement: a caller that writes a
    /// ledger, meters a quota, or serves a paid resource on the strength of this alone
    /// is acting on bytes the sender chose, and the sender can name any key here for
    /// the price of 64 arbitrary bytes.
    ///
    /// Call [`verify_declared_signatures`] first if the answer will be acted on before
    /// the transaction reaches the network.
    pub fn is_signer(&self, key: &Pubkey) -> bool {
        let n = self.message.num_required_signatures as usize;
        self.message
            .account_keys
            .get(..n)
            .is_some_and(|signers| signers.contains(key))
    }
}

/// Why a declared signature could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureCheckError {
    /// `bytes` is not the buffer this transaction was decoded from, so the span the
    /// signatures cover cannot be located. Refused rather than guessed: verifying the
    /// wrong span would report a pass for a message nobody signed.
    MessageBytesUnrecoverable,
    /// Signature at `index` is absent, malformed, or does not verify against the
    /// message. The index is into the signer prefix of `account_keys`.
    Invalid { index: usize },
    /// The message declares no signers at all, so there is nothing to verify. Refused
    /// rather than passed, because an empty check and a passed check are the same `Ok`.
    NoDeclaredSigners,
}

/// Verify every signature the message declares, against the exact bytes they cover.
///
/// [`DecodedTransaction::is_signer`] answers what the message DECLARES. That is only a
/// useful question once something has established the declaration is backed by a real
/// signature, and until this runs nothing has: [`decode_transaction`]'s header check
/// proves the signature vector is the right LENGTH, never that any of it verifies. So a
/// verifier acting on `is_signer` before broadcast is acting on attacker-chosen bytes.
///
/// `bytes` must be the buffer `tx` was decoded from. The message span is recomputed from
/// that buffer rather than re-serialized from `tx`, because a re-serialization differing
/// by a single byte would happily verify a message nobody ever signed.
///
/// A partially signed transaction fails here, by design. An empty slot is 64 zero bytes,
/// which is not a valid signature over anything, and a caller that cannot itself add the
/// missing signature has nothing to gain from accepting one.
pub fn verify_declared_signatures(
    bytes: &[u8],
    tx: &DecodedTransaction,
) -> Result<(), SignatureCheckError> {
    let (count, consumed) =
        decode_len(bytes).map_err(|_| SignatureCheckError::MessageBytesUnrecoverable)?;
    if count as usize != tx.signatures.len() {
        return Err(SignatureCheckError::MessageBytesUnrecoverable);
    }
    let start = tx
        .signatures
        .len()
        .checked_mul(64)
        .and_then(|n| n.checked_add(consumed))
        .ok_or(SignatureCheckError::MessageBytesUnrecoverable)?;
    let message = bytes
        .get(start..)
        .ok_or(SignatureCheckError::MessageBytesUnrecoverable)?;

    // The signer prefix and the signature vector are index-aligned, and
    // `decode_transaction` has already refused a message where they disagree in length,
    // so the zip below cannot silently skip a declared signer.
    let n = tx.message.num_required_signatures as usize;
    let signers = tx
        .message
        .account_keys
        .get(..n)
        .ok_or(SignatureCheckError::MessageBytesUnrecoverable)?;
    if signers.len() != tx.signatures.len() {
        return Err(SignatureCheckError::MessageBytesUnrecoverable);
    }
    // A transaction declaring NO signers would satisfy the loop below vacuously, and an
    // empty loop returning Ok reads exactly like a verified transaction. `decode_transaction`
    // refuses that header already, so this is unreachable through the normal path and is
    // refused here anyway, because this function is public and a caller can build the struct.
    if signers.is_empty() {
        return Err(SignatureCheckError::NoDeclaredSigners);
    }
    for (index, (key, sig)) in signers.iter().zip(tx.signatures.iter()).enumerate() {
        // A key that is not a valid ed25519 point lands here too, as an invalid
        // signature rather than as a separate outcome: either way nobody signed.
        if crate::signing::verify_signature(key.as_bytes(), message, sig) != Ok(true) {
            return Err(SignatureCheckError::Invalid { index });
        }
    }
    Ok(())
}

#[cfg(test)]
mod signature_verification_tests {
    use super::*;
    use crate::instruction::system_transfer;
    use crate::message::compile;
    use crate::signing::{pubkey_from_seed, serialize_transaction, sign_message};

    /// A one-signer transfer, signed for real.
    fn signed_transfer() -> Vec<u8> {
        let seed = [1u8; 32];
        let payer = Pubkey::new(pubkey_from_seed(&seed));
        let dest = Pubkey::new(pubkey_from_seed(&[2u8; 32]));
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 5)], &[7u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        serialize_transaction(&[sign_message(&seed, &body)], &body)
    }

    /// The positive control. Without it, every case below passes just as happily
    /// against a checker that refuses everything.
    #[test]
    fn a_genuinely_signed_transaction_verifies() {
        let raw = signed_transfer();
        let tx = decode_transaction(&raw).unwrap();
        assert_eq!(verify_declared_signatures(&raw, &tx), Ok(()));
    }

    /// The defect this exists to close: 64 bytes of anything at all, in a message that
    /// declares a signer. `is_signer` says yes and the bytes say nothing.
    #[test]
    fn garbage_signature_bytes_are_refused_even_though_is_signer_says_yes() {
        let raw = signed_transfer();
        let tx = decode_transaction(&raw).unwrap();
        let signer = tx.message.account_keys[0];

        // Overwrite the signature in place, leaving the message untouched.
        let mut forged = raw.clone();
        let (_, consumed) = decode_len(&forged).unwrap();
        for b in &mut forged[consumed..consumed + 64] {
            *b = 0xAB;
        }
        let ftx = decode_transaction(&forged).unwrap();

        assert!(
            ftx.is_signer(&signer),
            "the declaration is unchanged; that is precisely the problem"
        );
        assert_eq!(
            verify_declared_signatures(&forged, &ftx),
            Err(SignatureCheckError::Invalid { index: 0 })
        );
    }

    /// An unsigned slot is all zeroes, which is the shape a partially signed
    /// transaction arrives in. It must not read as signed.
    #[test]
    fn an_all_zero_signature_slot_is_refused() {
        let raw = signed_transfer();
        let mut blank = raw.clone();
        let (_, consumed) = decode_len(&blank).unwrap();
        for b in &mut blank[consumed..consumed + 64] {
            *b = 0;
        }
        let tx = decode_transaction(&blank).unwrap();
        assert_eq!(
            verify_declared_signatures(&blank, &tx),
            Err(SignatureCheckError::Invalid { index: 0 })
        );
    }

    /// A real signature over a DIFFERENT message must not verify: the check has to be
    /// against the bytes, not merely against a well-formed signature.
    #[test]
    fn a_signature_over_another_message_is_refused() {
        let seed = [1u8; 32];
        let payer = Pubkey::new(pubkey_from_seed(&seed));
        let dest = Pubkey::new(pubkey_from_seed(&[2u8; 32]));
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 5)], &[7u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        let wrong = sign_message(&seed, b"some other message entirely");
        let raw = serialize_transaction(&[wrong], &body);
        let tx = decode_transaction(&raw).unwrap();
        assert_eq!(
            verify_declared_signatures(&raw, &tx),
            Err(SignatureCheckError::Invalid { index: 0 })
        );
    }

    /// Handed a buffer that is not the one decoded, the answer is a refusal rather than
    /// a verdict about a span it guessed at.
    #[test]
    fn a_foreign_buffer_is_refused_rather_than_verified_against_the_wrong_span() {
        let raw = signed_transfer();
        let tx = decode_transaction(&raw).unwrap();
        assert_eq!(
            verify_declared_signatures(&raw[..raw.len() - 1], &tx),
            Err(SignatureCheckError::Invalid { index: 0 }),
            "a truncated message is a different message, so the signature must not verify"
        );
        assert_eq!(
            verify_declared_signatures(&[], &tx),
            Err(SignatureCheckError::MessageBytesUnrecoverable)
        );
    }

    /// Nothing to verify is not the same as verified. A zero-signer message would run the
    /// verification loop zero times, and an empty loop returns the same `Ok(())` a genuinely
    /// checked transaction does.
    #[test]
    fn a_message_declaring_no_signers_is_refused_rather_than_passing_vacuously() {
        let raw = signed_transfer();
        let mut tx = decode_transaction(&raw).expect("the fixture decodes");
        // Built by hand, because `decode_transaction` refuses this header outright: the
        // point is that the struct is public and a caller can reach this state without it.
        tx.message.num_required_signatures = 0;
        tx.signatures.clear();
        assert_eq!(
            verify_declared_signatures(&raw, &tx),
            Err(SignatureCheckError::MessageBytesUnrecoverable),
            "the buffer still carries one signature, so the shapes disagree first"
        );

        // And with a buffer whose signature count genuinely is zero, the refusal is the
        // specific one rather than a pass.
        let body = raw[1 + 64..].to_vec();
        let empty = serialize_transaction(&[], &body);
        assert_eq!(
            verify_declared_signatures(&empty, &tx),
            Err(SignatureCheckError::NoDeclaredSigners)
        );
    }

    /// Two signers, both real. The loop must check every slot, not only the first.
    #[test]
    fn every_declared_signer_is_checked_not_only_the_first() {
        let (a_seed, b_seed) = ([3u8; 32], [4u8; 32]);
        let a = Pubkey::new(pubkey_from_seed(&a_seed));
        let b = Pubkey::new(pubkey_from_seed(&b_seed));
        // The transfer's source signs (system_transfer marks it), and the fee payer is a
        // different account, so the message declares two signers.
        let msg = compile(&a, &[system_transfer(&b, &a, 1)], &[7u8; 32]).unwrap();
        assert_eq!(msg.num_required_signatures, 2, "fixture needs two signers");
        let body = msg.serialize_legacy();
        let seed_of = |k: &Pubkey| if *k == a { a_seed } else { b_seed };
        let good: Vec<[u8; 64]> = msg.account_keys[..2]
            .iter()
            .map(|k| sign_message(&seed_of(k), &body))
            .collect();
        let raw = serialize_transaction(&good, &body);
        assert_eq!(
            verify_declared_signatures(&raw, &decode_transaction(&raw).unwrap()),
            Ok(())
        );

        // Now break only the SECOND slot. A checker that stopped at index 0 passes this
        // wrongly, which is the whole reason the case exists.
        let mut broken = good.clone();
        broken[1] = [0x11; 64];
        let raw = serialize_transaction(&broken, &body);
        assert_eq!(
            verify_declared_signatures(&raw, &decode_transaction(&raw).unwrap()),
            Err(SignatureCheckError::Invalid { index: 1 })
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::system_transfer;
    use crate::message::compile;
    use crate::pubkey::Pubkey;
    use crate::signing::{pubkey_from_seed, serialize_transaction, sign_message};

    fn kp(seed_byte: u8) -> ([u8; 32], Pubkey) {
        let seed = [seed_byte; 32];
        (seed, Pubkey::new(pubkey_from_seed(&seed)))
    }

    // Round-trips a compile()->serialize->sign->decode cycle: the decoded
    // message must equal the compiled one, byte for byte in every field.
    #[test]
    fn round_trip_legacy_single_instruction() {
        let (payer_seed, payer) = kp(1);
        let (_, dest) = kp(2);
        let bh = [7u8; 32];
        let ix = system_transfer(&payer, &dest, 12345);
        let msg = compile(&payer, &[ix], &bh).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(&payer_seed, &body);
        let tx = serialize_transaction(&[sig], &body);

        let decoded = decode_transaction(&tx).unwrap();
        assert!(!decoded.is_v0);
        assert_eq!(decoded.signatures.len(), 1);
        assert_eq!(decoded.signatures[0], sig);
        assert_eq!(decoded.message, msg);
    }

    #[test]
    fn round_trip_v0() {
        let (payer_seed, payer) = kp(3);
        let (_, dest) = kp(4);
        let bh = [9u8; 32];
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 1)], &bh).unwrap();
        let body = msg.serialize_v0_no_lookups();
        let sig = sign_message(&payer_seed, &body);
        let tx = serialize_transaction(&[sig], &body);

        let decoded = decode_transaction(&tx).unwrap();
        assert!(decoded.is_v0);
        assert_eq!(decoded.message, msg);
    }

    #[test]
    fn round_trip_multi_instruction_and_account_resolution() {
        let (payer_seed, payer) = kp(5);
        let (_, a) = kp(6);
        let (_, b) = kp(7);
        let bh = [3u8; 32];
        let ixs = vec![
            system_transfer(&payer, &a, 10),
            system_transfer(&payer, &b, 20),
        ];
        let msg = compile(&payer, &ixs, &bh).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(&payer_seed, &body);
        let tx = serialize_transaction(&[sig], &body);

        let decoded = decode_transaction(&tx).unwrap();
        assert_eq!(decoded.message.instructions.len(), 2);
        // system_transfer accounts are [from, to]; resolve the destination of ix 0.
        let ix0 = &decoded.message.instructions[0];
        assert_eq!(decoded.account_of(ix0, 1), Some(&a));
    }

    #[test]
    fn truncated_is_rejected_not_panicked() {
        let (payer_seed, payer) = kp(8);
        let (_, dest) = kp(9);
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 1)], &[0u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(&payer_seed, &body);
        let tx = serialize_transaction(&[sig], &body);
        // Every truncation point must error, never panic.
        for cut in 0..tx.len() {
            let _ = decode_transaction(&tx[..cut]);
        }
    }

    #[test]
    fn trailing_bytes_rejected() {
        let (payer_seed, payer) = kp(10);
        let (_, dest) = kp(11);
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 1)], &[0u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(&payer_seed, &body);
        let mut tx = serialize_transaction(&[sig], &body);
        tx.push(0xAB);
        assert!(matches!(
            decode_transaction(&tx),
            Err(DecodeError::TrailingBytes(1))
        ));
    }

    #[test]
    fn v0_with_lookups_refused() {
        let (payer_seed, payer) = kp(12);
        let (_, dest) = kp(13);
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 1)], &[0u8; 32]).unwrap();
        let mut body = msg.serialize_v0_no_lookups();
        // The serialize path wrote a zero lookups shortvec (last byte); flip it
        // to declare one lookup, which the decoder must refuse.
        *body.last_mut().unwrap() = 1;
        let sig = sign_message(&payer_seed, &body);
        let tx = serialize_transaction(&[sig], &body);
        assert_eq!(
            decode_transaction(&tx),
            Err(DecodeError::AddressTableLookupsUnsupported)
        );
    }

    #[test]
    fn empty_input_rejected() {
        assert!(decode_transaction(&[]).is_err());
    }

    // Adversarial: a huge signature-count prefix must not allocate/panic.
    #[test]
    fn oversized_signature_count_rejected() {
        // shortvec-encode 0xffff as the sig count, then nothing.
        let mut bytes = Vec::new();
        crate::shortvec::encode_len(0xffff, &mut bytes);
        assert!(matches!(
            decode_transaction(&bytes),
            Err(DecodeError::BadLength) | Err(DecodeError::Truncated)
        ));
    }

    /// Build a valid legacy tx, then hand-edit ONE header byte. The header sits at a fixed
    /// offset: 1 shortvec byte for the signature count, 64 signature bytes, then the three
    /// header bytes. Editing bytes rather than using `compile` is the point -- `compile`
    /// cannot produce these, and an attacker is not using `compile`.
    fn tx_with_header_byte(index: usize, value: u8) -> Vec<u8> {
        let (payer_seed, payer) = kp(11);
        let (_, dest) = kp(12);
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 1)], &[3u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(&payer_seed, &body);
        let mut tx = serialize_transaction(&[sig], &body);
        tx[1 + 64 + index] = value;
        tx
    }

    /// CONTROL. The untouched fixture must still decode, or the three must-fire cases below
    /// prove only that the builder is broken.
    #[test]
    fn well_formed_header_still_decodes() {
        let (payer_seed, payer) = kp(11);
        let (_, dest) = kp(12);
        let msg = compile(&payer, &[system_transfer(&payer, &dest, 1)], &[3u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(&payer_seed, &body);
        let tx = serialize_transaction(&[sig], &body);
        assert!(decode_transaction(&tx).is_ok());
    }

    /// Claiming more signers than there are signatures is how a crafted message names a
    /// victim as a signer without producing their signature. `is_signer` is unsound until
    /// this is refused, so this case guards the token authority check too.
    #[test]
    fn header_claiming_more_signers_than_signatures_is_refused() {
        // 5 required signatures, 1 supplied. Stay under 0x80 or the v0 sniff eats it first.
        let tx = tx_with_header_byte(0, 5);
        assert!(matches!(
            decode_transaction(&tx),
            Err(DecodeError::MalformedHeader(_))
        ));
    }

    /// num_readonly_signed must be strictly less than num_required_signatures; otherwise the
    /// writable-signer set is empty or negative-sized and the fee payer is not writable.
    #[test]
    fn header_readonly_signed_not_less_than_required_is_refused() {
        let tx = tx_with_header_byte(1, 9);
        assert!(matches!(
            decode_transaction(&tx),
            Err(DecodeError::MalformedHeader(_))
        ));
    }

    /// Signed plus readonly-unsigned must fit inside the account-key vector.
    #[test]
    fn header_readonly_unsigned_overrunning_keys_is_refused() {
        let tx = tx_with_header_byte(2, 120);
        assert!(matches!(
            decode_transaction(&tx),
            Err(DecodeError::MalformedHeader(_))
        ));
    }

    /// A header claiming ZERO required signatures is refused, matching Solana: the fee payer is
    /// always a required signer, so there is no valid transaction with none. Added because review
    /// found an explicit carve-out here that deviated from this decoder's stated parity claim.
    #[test]
    fn header_requiring_no_signatures_at_all_is_refused() {
        let tx = tx_with_header_byte(0, 0);
        assert!(matches!(
            decode_transaction(&tx),
            Err(DecodeError::MalformedHeader(_))
        ));
    }
}
