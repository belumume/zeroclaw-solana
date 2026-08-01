//! SPL-Token / Token-2022 instruction introspection for the *verifier* side.
//!
//! When an untrusted party hands us a signed transaction claiming to pay us
//! (x402 `exact` scheme), we must confirm — from the bytes, before trusting or
//! broadcasting — that it contains a `TransferChecked` moving at least the
//! quoted amount of the quoted mint into *our* associated token account. This
//! module finds and validates that instruction without any SDK dependency.
//!
//! `TransferChecked` (SPL-Token instruction tag `12`) data layout:
//!   [0]      = 12                (u8 discriminator)
//!   [1..9]   = amount            (u64 little-endian, in base units)
//!   [9]      = decimals          (u8)
//! Accounts (index order):
//!   0 = source ATA, 1 = mint, 2 = destination ATA, 3 = owner/authority, ...

use crate::message::CompiledInstruction;
use crate::pubkey::{token_2022_program, token_program, Pubkey};
use crate::tx_decode::DecodedTransaction;

/// The SPL-Token `TransferChecked` instruction discriminator.
pub const TRANSFER_CHECKED_TAG: u8 = 12;

/// A validated payment found inside a decoded transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundPayment {
    /// The mint being transferred.
    pub mint: Pubkey,
    /// Destination associated token account.
    pub destination: Pubkey,
    /// Amount in base units.
    pub amount: u64,
    /// Declared decimals from the instruction.
    pub decimals: u8,
    /// Index of the matching instruction within the message.
    pub instruction_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentError {
    /// No `TransferChecked` to the expected destination for the expected mint
    /// was found.
    NoMatchingTransfer,
    /// A matching transfer was found but its amount is below the quote.
    Underpaid { found: u64, required: u64 },
}

/// Parse a single instruction as a `TransferChecked` if it is one, returning
/// `(amount, decimals)` from the data. Returns `None` when the instruction is
/// not a well-formed TransferChecked (wrong program, wrong tag, short data).
pub fn parse_transfer_checked(
    tx: &DecodedTransaction,
    ix: &CompiledInstruction,
) -> Option<(u64, u8)> {
    let program = tx.program_id_of(ix)?;
    if *program != token_program() && *program != token_2022_program() {
        return None;
    }
    if ix.data.first().copied() != Some(TRANSFER_CHECKED_TAG) {
        return None;
    }
    // 1 tag + 8 amount + 1 decimals
    if ix.data.len() < 10 {
        return None;
    }
    let mut amount_bytes = [0u8; 8];
    amount_bytes.copy_from_slice(&ix.data[1..9]);
    let amount = u64::from_le_bytes(amount_bytes);
    let decimals = ix.data[9];
    Some((amount, decimals))
}

/// Find a `TransferChecked` in `tx` that pays at least `min_amount` of `mint`
/// into `expected_destination`. Returns the first such instruction.
///
/// The caller is responsible for having already verified (a) the transaction's
/// signatures cover the message, and (b) the fee payer / other instructions are
/// acceptable. This function makes exactly one claim: "a valid payment of the
/// right mint, to the right account, of at least the right amount, is present."
pub fn find_payment(
    tx: &DecodedTransaction,
    mint: &Pubkey,
    expected_destination: &Pubkey,
    min_amount: u64,
) -> Result<FoundPayment, PaymentError> {
    let mut best_underpaid: Option<u64> = None;

    for (i, ix) in tx.message.instructions.iter().enumerate() {
        let Some((amount, decimals)) = parse_transfer_checked(tx, ix) else {
            continue;
        };
        // account[1] = mint, account[2] = destination
        let ix_mint = tx.account_of(ix, 1);
        let ix_dest = tx.account_of(ix, 2);
        if ix_mint != Some(mint) || ix_dest != Some(expected_destination) {
            continue;
        }
        if amount >= min_amount {
            return Ok(FoundPayment {
                mint: *mint,
                destination: *expected_destination,
                amount,
                decimals,
                instruction_index: i,
            });
        }
        // Track the closest underpayment so the error is informative.
        best_underpaid = Some(best_underpaid.map_or(amount, |b| b.max(amount)));
    }

    match best_underpaid {
        Some(found) => Err(PaymentError::Underpaid {
            found,
            required: min_amount,
        }),
        None => Err(PaymentError::NoMatchingTransfer),
    }
}

/// Whether `tx` contains a Memo-program instruction whose UTF-8 data equals
/// `expected` exactly. Used to bind an x402 payment to the specific 402
/// challenge nonce we issued, defeating replay of a payment against a different
/// request. The Memo program id is passed in so the caller controls it.
pub fn has_memo(tx: &DecodedTransaction, memo_program: &Pubkey, expected: &[u8]) -> bool {
    tx.message
        .instructions
        .iter()
        .any(|ix| tx.program_id_of(ix) == Some(memo_program) && ix.data.as_slice() == expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{AccountMeta, Instruction};
    use crate::message::compile;
    use crate::pubkey::token_program;
    use crate::signing::{pubkey_from_seed, serialize_transaction, sign_message};
    use crate::tx_decode::decode_transaction;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new(pubkey_from_seed(&[b; 32]))
    }

    /// Build a real TransferChecked instruction (source, mint, dest, owner).
    fn transfer_checked(
        source: &Pubkey,
        mint: &Pubkey,
        dest: &Pubkey,
        owner: &Pubkey,
        amount: u64,
        decimals: u8,
    ) -> Instruction {
        let mut data = vec![TRANSFER_CHECKED_TAG];
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(decimals);
        Instruction {
            program_id: token_program(),
            accounts: vec![
                AccountMeta::writable(*source, false),
                AccountMeta::readonly(*mint, false),
                AccountMeta::writable(*dest, false),
                AccountMeta::readonly(*owner, true),
            ],
            data,
        }
    }

    fn build_tx(ixs: &[Instruction], payer_seed: &[u8; 32], payer: &Pubkey) -> Vec<u8> {
        let msg = compile(payer, ixs, &[1u8; 32]).unwrap();
        let body = msg.serialize_legacy();
        let sig = sign_message(payer_seed, &body);
        serialize_transaction(&[sig], &body)
    }

    #[test]
    fn finds_exact_payment() {
        let payer_seed = [1u8; 32];
        let payer = pk(1);
        let mint = pk(2);
        let dest = pk(3);
        let src = pk(4);
        let ix = transfer_checked(&src, &mint, &dest, &payer, 5_000_000, 6);
        let tx = build_tx(&[ix], &payer_seed, &payer);
        let decoded = decode_transaction(&tx).unwrap();

        let found = find_payment(&decoded, &mint, &dest, 5_000_000).unwrap();
        assert_eq!(found.amount, 5_000_000);
        assert_eq!(found.mint, mint);
        assert_eq!(found.destination, dest);
    }

    #[test]
    fn overpayment_accepted() {
        let payer_seed = [1u8; 32];
        let payer = pk(1);
        let (mint, dest, src) = (pk(2), pk(3), pk(4));
        let ix = transfer_checked(&src, &mint, &dest, &payer, 9_000_000, 6);
        let tx = build_tx(&[ix], &payer_seed, &payer);
        let decoded = decode_transaction(&tx).unwrap();
        // Quote was 5 USDC; 9 paid — accepted.
        assert!(find_payment(&decoded, &mint, &dest, 5_000_000).is_ok());
    }

    #[test]
    fn underpayment_rejected_with_detail() {
        let payer_seed = [1u8; 32];
        let payer = pk(1);
        let (mint, dest, src) = (pk(2), pk(3), pk(4));
        let ix = transfer_checked(&src, &mint, &dest, &payer, 3_000_000, 6);
        let tx = build_tx(&[ix], &payer_seed, &payer);
        let decoded = decode_transaction(&tx).unwrap();
        assert_eq!(
            find_payment(&decoded, &mint, &dest, 5_000_000),
            Err(PaymentError::Underpaid {
                found: 3_000_000,
                required: 5_000_000
            })
        );
    }

    #[test]
    fn wrong_destination_rejected() {
        let payer_seed = [1u8; 32];
        let payer = pk(1);
        let (mint, dest, src, attacker) = (pk(2), pk(3), pk(4), pk(9));
        // Pays the attacker, not us.
        let ix = transfer_checked(&src, &mint, &attacker, &payer, 5_000_000, 6);
        let tx = build_tx(&[ix], &payer_seed, &payer);
        let decoded = decode_transaction(&tx).unwrap();
        assert_eq!(
            find_payment(&decoded, &mint, &dest, 5_000_000),
            Err(PaymentError::NoMatchingTransfer)
        );
    }

    #[test]
    fn wrong_mint_rejected() {
        let payer_seed = [1u8; 32];
        let payer = pk(1);
        let (mint, other_mint, dest, src) = (pk(2), pk(8), pk(3), pk(4));
        let ix = transfer_checked(&src, &other_mint, &dest, &payer, 5_000_000, 6);
        let tx = build_tx(&[ix], &payer_seed, &payer);
        let decoded = decode_transaction(&tx).unwrap();
        assert_eq!(
            find_payment(&decoded, &mint, &dest, 5_000_000),
            Err(PaymentError::NoMatchingTransfer)
        );
    }

    #[test]
    fn plain_transfer_not_mistaken_for_checked() {
        // A legacy Transfer (tag 3) to our dest must NOT satisfy find_payment,
        // which only trusts TransferChecked (tag 12, carries mint + decimals).
        let payer_seed = [1u8; 32];
        let payer = pk(1);
        let (mint, dest, src) = (pk(2), pk(3), pk(4));
        let mut data = vec![3u8]; // Transfer, not TransferChecked
        data.extend_from_slice(&5_000_000u64.to_le_bytes());
        let ix = Instruction {
            program_id: token_program(),
            accounts: vec![
                AccountMeta::writable(src, false),
                AccountMeta::writable(dest, false),
                AccountMeta::readonly(payer, true),
            ],
            data,
        };
        let tx = build_tx(&[ix], &payer_seed, &payer);
        let decoded = decode_transaction(&tx).unwrap();
        assert_eq!(
            find_payment(&decoded, &mint, &dest, 5_000_000),
            Err(PaymentError::NoMatchingTransfer)
        );
    }

    #[test]
    fn memo_binding_matches_and_mismatches() {
        let payer_seed = [1u8; 32];
        let payer = pk(1);
        let memo_prog = pk(20);
        let nonce = b"x402-nonce-abc123";
        let memo_ix = Instruction {
            program_id: memo_prog,
            accounts: vec![AccountMeta::readonly(payer, true)],
            data: nonce.to_vec(),
        };
        let tx = build_tx(&[memo_ix], &payer_seed, &payer);
        let decoded = decode_transaction(&tx).unwrap();
        assert!(has_memo(&decoded, &memo_prog, nonce));
        assert!(!has_memo(&decoded, &memo_prog, b"different-nonce"));
        assert!(!has_memo(&decoded, &pk(21), nonce)); // wrong memo program
    }
}
