//! Legacy + v0 message compilation and serialization, byte-validated
//! DIFFERENTIALLY against `solana_program::message::Message::new_with_blockhash`
//! and `v0::Message::try_compile` fixtures (generated from the solana-program reference).
//!
//! Account ordering (verified against the reference, not assumed): keys are
//! deduped with flag-merging, then grouped as writable signers (fee payer
//! forced first), readonly signers, writable non-signers, readonly non-signers,
//! and SORTED BY PUBKEY BYTES within each group (the reference builds a
//! BTreeMap, so ordering is lexicographic, not first-appearance).
//!
//! v0 scope, stated honestly: this emits the v0 wire format with an EMPTY
//! address-table-lookups vector (byte-identical to the reference for that
//! case). Full ALT resolution (fetching tables + moving keys into lookups) is
//! a separate, harder feature and is NOT implemented here yet.

use crate::instruction::Instruction;
use crate::pubkey::Pubkey;
use crate::shortvec;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageError {
    /// More than 256 unique accounts cannot be indexed by u8.
    TooManyAccounts(usize),
    /// A message must carry at least one instruction.
    NoInstructions,
    /// Instruction data longer than the u16 shortvec length prefix (65535
    /// bytes): serializing would truncate the length via `as u16` and sign a
    /// message whose header disagrees with its payload. Fail closed instead.
    InstructionDataTooLarge(usize),
    /// More than 255 required signatures cannot be encoded in the u8 header
    /// (`num_required_signatures as u8` would wrap).
    TooManySignatures(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledInstruction {
    pub program_id_index: u8,
    pub account_indexes: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMessage {
    pub num_required_signatures: u8,
    pub num_readonly_signed: u8,
    pub num_readonly_unsigned: u8,
    pub account_keys: Vec<Pubkey>,
    pub recent_blockhash: [u8; 32],
    pub instructions: Vec<CompiledInstruction>,
}

#[derive(Default, Clone, Copy)]
struct Flags {
    signer: bool,
    writable: bool,
}

/// Compile instructions into a legacy message (also the body of a v0 message
/// when no address-table lookups are used).
pub fn compile(
    payer: &Pubkey,
    instructions: &[Instruction],
    recent_blockhash: &[u8; 32],
) -> Result<CompiledMessage, MessageError> {
    if instructions.is_empty() {
        return Err(MessageError::NoInstructions);
    }

    // Dedup + merge flags. BTreeMap gives the reference's lexicographic order.
    let mut map: BTreeMap<Pubkey, Flags> = BTreeMap::new();
    let payer_flags = map.entry(*payer).or_default();
    payer_flags.signer = true;
    payer_flags.writable = true;
    for ix in instructions {
        for m in &ix.accounts {
            let f = map.entry(m.pubkey).or_default();
            f.signer |= m.is_signer;
            f.writable |= m.is_writable;
        }
        map.entry(ix.program_id).or_default(); // programs: readonly non-signer
    }

    let group = |signer: bool, writable: bool| {
        map.iter()
            .filter(|(k, f)| f.signer == signer && f.writable == writable && *k != payer)
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
    };
    let mut account_keys = vec![*payer];
    account_keys.extend(group(true, true));
    let readonly_signed = group(true, false);
    let writable_unsigned = group(false, true);
    let readonly_unsigned = group(false, false);
    let num_required_signatures = account_keys.len() + readonly_signed.len();
    account_keys.extend(readonly_signed.iter().copied());
    account_keys.extend(writable_unsigned);
    account_keys.extend(readonly_unsigned.iter().copied());

    if account_keys.len() > 256 {
        return Err(MessageError::TooManyAccounts(account_keys.len()));
    }
    let index_of = |k: &Pubkey| -> u8 {
        account_keys
            .iter()
            .position(|a| a == k)
            .expect("key inserted above") as u8
    };

    // Fail closed on the length casts serialize_body performs, rather than
    // silently truncating and signing a malformed message. (account/index counts
    // are already bounded by the 256-account guard above; these two are not.)
    if num_required_signatures > u8::MAX as usize {
        return Err(MessageError::TooManySignatures(num_required_signatures));
    }
    for ix in instructions {
        if ix.data.len() > u16::MAX as usize {
            return Err(MessageError::InstructionDataTooLarge(ix.data.len()));
        }
    }

    let compiled = instructions
        .iter()
        .map(|ix| CompiledInstruction {
            program_id_index: index_of(&ix.program_id),
            account_indexes: ix.accounts.iter().map(|m| index_of(&m.pubkey)).collect(),
            data: ix.data.clone(),
        })
        .collect();

    Ok(CompiledMessage {
        num_required_signatures: num_required_signatures as u8,
        num_readonly_signed: readonly_signed.len() as u8,
        num_readonly_unsigned: readonly_unsigned.len() as u8,
        account_keys,
        recent_blockhash: *recent_blockhash,
        instructions: compiled,
    })
}

impl CompiledMessage {
    fn serialize_body(&self, out: &mut Vec<u8>) {
        out.push(self.num_required_signatures);
        out.push(self.num_readonly_signed);
        out.push(self.num_readonly_unsigned);
        shortvec::encode_len(self.account_keys.len() as u16, out);
        for k in &self.account_keys {
            out.extend_from_slice(&k.to_bytes());
        }
        out.extend_from_slice(&self.recent_blockhash);
        shortvec::encode_len(self.instructions.len() as u16, out);
        for ix in &self.instructions {
            out.push(ix.program_id_index);
            shortvec::encode_len(ix.account_indexes.len() as u16, out);
            out.extend_from_slice(&ix.account_indexes);
            shortvec::encode_len(ix.data.len() as u16, out);
            out.extend_from_slice(&ix.data);
        }
    }

    /// Legacy wire format — the byte string that gets signed.
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        self.serialize_body(&mut out);
        out
    }

    /// v0 wire format with an empty address-table-lookups vector.
    pub fn serialize_v0_no_lookups(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.push(0x80); // version prefix: 0x80 | 0
        self.serialize_body(&mut out);
        shortvec::encode_len(0, &mut out); // zero lookups
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{advance_nonce_account, memo, system_transfer};

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new([byte; 32])
    }
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Ground truth generated by `solana_program` itself (vecgen, 2026-07-20):
    // payer=[1;32], dest=[2;32], nonce_auth=[3;32], nonce_acct=[4;32], bh=[9;32],
    // memo text "zeroclaw-attest:test".
    const LEGACY_TRANSFER_MSG: &str = "01000103010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000000000000000000000000000000000000000000000000000000090909090909090909090909090909090909090909090909090909090909090901020200010c02000000e803000000000000";
    const LEGACY_TRANSFER_MEMO_MSG: &str = "01000204010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000000000000000000000000000000000000000000000000000000054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d090909090909090909090909090909090909090909090909090909090909090902020200010c02000000e803000000000000030100147a65726f636c61772d6174746573743a74657374";
    const NONCE_MEMO_MSG: &str = "01000305030303030303030303030303030303030303030303030303030303030303030304040404040404040404040404040404040404040404040404040404040404040000000000000000000000000000000000000000000000000000000000000000054a535a992921064d24e87160da387c7c35b5ddbc92bb81e41fa8404105448d06a7d517192c568ee08a845f73d29788cf035c3145b21ab344d8062ea940000009090909090909090909090909090909090909090909090909090909090909090202030104000404000000030100147a65726f636c61772d6174746573743a74657374";
    const V0_TRANSFER_MSG: &str = "8001000103010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000000000000000000000000000000000000000000000000000000090909090909090909090909090909090909090909090909090909090909090901020200010c02000000e80300000000000000";

    #[test]
    fn legacy_transfer_matches_reference_bytes() {
        let m = compile(&pk(1), &[system_transfer(&pk(1), &pk(2), 1000)], &[9u8; 32]).unwrap();
        assert_eq!(hex(&m.serialize_legacy()), LEGACY_TRANSFER_MSG);
    }

    #[test]
    fn transfer_plus_memo_matches_reference_bytes() {
        let ixs = [
            system_transfer(&pk(1), &pk(2), 1000),
            memo(&pk(1), b"zeroclaw-attest:test"),
        ];
        let m = compile(&pk(1), &ixs, &[9u8; 32]).unwrap();
        assert_eq!(hex(&m.serialize_legacy()), LEGACY_TRANSFER_MEMO_MSG);
    }

    #[test]
    fn durable_nonce_attestation_matches_reference_bytes() {
        // The depin-attest shape: AdvanceNonceAccount MUST be instruction 0.
        let ixs = [
            advance_nonce_account(&pk(4), &pk(3)),
            memo(&pk(3), b"zeroclaw-attest:test"),
        ];
        let m = compile(&pk(3), &ixs, &[9u8; 32]).unwrap();
        assert_eq!(hex(&m.serialize_legacy()), NONCE_MEMO_MSG);
    }

    // Ground truth from `solana_compute_budget_interface` via vecgen:
    // set_compute_unit_limit(150_000) + set_compute_unit_price(10_000) + transfer.
    const PRIORITY_TRANSFER_MSG: &str = "010002040101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020200000000000000000000000000000000000000000000000000000000000000000306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a4000000009090909090909090909090909090909090909090909090909090909090909090303000502f0490200030009031027000000000000020200010c02000000e803000000000000";

    #[test]
    fn priority_fee_transfer_matches_reference_bytes() {
        use crate::instruction::{set_compute_unit_limit, set_compute_unit_price};
        let ixs = [
            set_compute_unit_limit(150_000),
            set_compute_unit_price(10_000),
            system_transfer(&pk(1), &pk(2), 1000),
        ];
        let m = compile(&pk(1), &ixs, &[9u8; 32]).unwrap();
        assert_eq!(hex(&m.serialize_legacy()), PRIORITY_TRANSFER_MSG);
    }

    #[test]
    fn v0_no_lookups_matches_reference_bytes() {
        let m = compile(&pk(1), &[system_transfer(&pk(1), &pk(2), 1000)], &[9u8; 32]).unwrap();
        assert_eq!(hex(&m.serialize_v0_no_lookups()), V0_TRANSFER_MSG);
    }

    #[test]
    fn readonly_unsigned_group_is_sorted_by_pubkey_bytes() {
        // The nonce fixture already proves this (system < memo < sysvar), but
        // assert it explicitly so a refactor to first-appearance order fails loudly.
        let ixs = [
            advance_nonce_account(&pk(4), &pk(3)),
            memo(&pk(3), b"zeroclaw-attest:test"),
        ];
        let m = compile(&pk(3), &ixs, &[9u8; 32]).unwrap();
        let ro_unsigned =
            &m.account_keys[m.account_keys.len() - m.num_readonly_unsigned as usize..];
        let mut sorted = ro_unsigned.to_vec();
        sorted.sort();
        assert_eq!(ro_unsigned, &sorted[..]);
    }

    #[test]
    fn empty_instruction_list_fails_closed() {
        assert_eq!(
            compile(&pk(1), &[], &[9u8; 32]),
            Err(MessageError::NoInstructions)
        );
    }

    #[test]
    fn oversized_instruction_data_fails_closed() {
        // >65535 bytes would truncate the u16 shortvec length prefix and sign a
        // malformed message. compile() must reject it, not silently corrupt.
        let big = memo(&pk(1), &vec![b'a'; 65_536]);
        let e = compile(&pk(1), &[big], &[9u8; 32]).unwrap_err();
        assert!(
            matches!(e, MessageError::InstructionDataTooLarge(_)),
            "got {e:?}"
        );
    }
}
