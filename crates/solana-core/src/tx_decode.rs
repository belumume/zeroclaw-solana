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
        self.message
            .account_keys
            .get(ix.program_id_index as usize)
    }

    /// Resolve the Nth account of an instruction to a pubkey.
    pub fn account_of(&self, ix: &CompiledInstruction, n: usize) -> Option<&Pubkey> {
        let idx = *ix.account_indexes.get(n)? as usize;
        self.message.account_keys.get(idx)
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
        let ixs = vec![system_transfer(&payer, &a, 10), system_transfer(&payer, &b, 20)];
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
}
