//! Instructions and the builders the plugins need. Data layouts are the System
//! Program's bincode enum (u32 LE discriminant) and SPL Memo's raw bytes; all
//! byte-validated differentially against `solana-program` message fixtures
//! (see `message.rs` tests).

use crate::pubkey::{self, Pubkey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    pub fn writable(pubkey: Pubkey, is_signer: bool) -> Self {
        AccountMeta {
            pubkey,
            is_signer,
            is_writable: true,
        }
    }
    pub fn readonly(pubkey: Pubkey, is_signer: bool) -> Self {
        AccountMeta {
            pubkey,
            is_signer,
            is_writable: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// SystemProgram::Transfer (discriminant 2) — moves lamports.
pub fn system_transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: pubkey::system_program(),
        accounts: vec![
            AccountMeta::writable(*from, true),
            AccountMeta::writable(*to, false),
        ],
        data,
    }
}

/// SystemProgram::AdvanceNonceAccount (discriminant 4) — MUST be instruction 0
/// of a durable-nonce transaction.
pub fn advance_nonce_account(nonce_account: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: pubkey::system_program(),
        accounts: vec![
            AccountMeta::writable(*nonce_account, false),
            AccountMeta::readonly(pubkey::recent_blockhashes_sysvar(), false),
            AccountMeta::readonly(*authority, true),
        ],
        data: 4u32.to_le_bytes().to_vec(),
    }
}

/// SPL Memo v2 — publishes `text` on-chain, attributed to `signer`.
pub fn memo(signer: &Pubkey, text: &[u8]) -> Instruction {
    Instruction {
        program_id: pubkey::memo_program(),
        accounts: vec![AccountMeta::readonly(*signer, true)],
        data: text.to_vec(),
    }
}

/// ComputeBudget::SetComputeUnitLimit (u8 tag 2 + u32 LE units). No accounts.
pub fn set_compute_unit_limit(units: u32) -> Instruction {
    let mut data = Vec::with_capacity(5);
    data.push(2u8);
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: pubkey::compute_budget_program(),
        accounts: vec![],
        data,
    }
}

/// ComputeBudget::SetComputeUnitPrice (u8 tag 3 + u64 LE micro-lamports per
/// compute unit) — the priority fee. No accounts.
pub fn set_compute_unit_price(micro_lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(3u8);
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction {
        program_id: pubkey::compute_budget_program(),
        accounts: vec![],
        data,
    }
}
