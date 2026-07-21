//! Solana public keys: base58 codec, ed25519 on-curve test, and off-curve
//! program-derived-address (PDA) + associated-token-account (ATA) derivation.
//!
//! Hand-rolled and `wasm32-wasip2`-friendly: `curve25519-dalek` (portable
//! backend on wasm, no asm), `sha2`, and `bs58` only — no `solana-sdk`/
//! `solana-client`, which do not compile for wasip2 components.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// A 32-byte Solana public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pubkey([u8; 32]);

/// The PDA marker Solana appends before hashing (`create_program_address`).
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";
const MAX_SEEDS: usize = 16;
const MAX_SEED_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubkeyError {
    /// base58 decoded to a length other than 32 bytes.
    WrongLength(usize),
    /// Input was not valid base58.
    BadBase58,
    /// Too many seeds (>16) or a seed longer than 32 bytes.
    InvalidSeeds,
    /// The derived address landed on the ed25519 curve (not a valid PDA).
    OnCurve,
}

impl Pubkey {
    pub const LEN: usize = 32;

    #[inline]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Pubkey(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[inline]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Decode a base58 address. Rejects anything that is not exactly 32 bytes.
    pub fn from_base58(s: &str) -> Result<Self, PubkeyError> {
        let v = bs58::decode(s)
            .into_vec()
            .map_err(|_| PubkeyError::BadBase58)?;
        let arr: [u8; 32] = v
            .as_slice()
            .try_into()
            .map_err(|_| PubkeyError::WrongLength(v.len()))?;
        Ok(Pubkey(arr))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.0).into_string()
    }

    /// True if this key is a point on the ed25519 curve (i.e. could be a wallet
    /// with a private key). PDAs are deliberately OFF the curve.
    pub fn is_on_curve(&self) -> bool {
        CompressedEdwardsY::from_slice(&self.0)
            .ok()
            .and_then(|c| c.decompress())
            .is_some()
    }

    /// Derive an address from seeds + program id in a single attempt. Errors if
    /// the result is on-curve (Solana rejects such addresses as PDAs) or if the
    /// seeds violate the length/count limits.
    pub fn create_program_address(
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<Pubkey, PubkeyError> {
        if seeds.len() > MAX_SEEDS || seeds.iter().any(|s| s.len() > MAX_SEED_LEN) {
            return Err(PubkeyError::InvalidSeeds);
        }
        let mut h = Sha256::new();
        for s in seeds {
            h.update(s);
        }
        h.update(program_id.as_bytes());
        h.update(PDA_MARKER);
        let candidate = Pubkey(h.finalize().into());
        if candidate.is_on_curve() {
            Err(PubkeyError::OnCurve)
        } else {
            Ok(candidate)
        }
    }

    /// Find the canonical off-curve PDA and its bump seed, scanning bump 255→0.
    pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
        let mut bump = 255u8;
        loop {
            // Bump is passed as an extra 1-byte seed (fresh each iteration).
            let bump_seed = [bump];
            let mut with_bump: Vec<&[u8]> = Vec::with_capacity(seeds.len() + 1);
            with_bump.extend_from_slice(seeds);
            with_bump.push(&bump_seed);
            if let Ok(pk) = Pubkey::create_program_address(&with_bump, program_id) {
                return Some((pk, bump));
            }
            if bump == 0 {
                return None;
            }
            bump -= 1;
        }
    }

    /// Derive the associated token account for `(wallet, mint)` under a token
    /// program (classic SPL Token or Token-2022).
    pub fn associated_token_address(
        wallet: &Pubkey,
        mint: &Pubkey,
        token_program: &Pubkey,
    ) -> Pubkey {
        // ATA seeds: [wallet, token_program, mint] under the ATA program.
        Pubkey::find_program_address(
            &[wallet.as_bytes(), token_program.as_bytes(), mint.as_bytes()],
            &associated_token_program(),
        )
        .expect("ATA derivation always yields a valid bump")
        .0
    }
}

impl core::fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl core::fmt::Display for Pubkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

// --- Well-known program ids (decoded from their canonical base58) -----------

fn from_known(b58: &str) -> Pubkey {
    Pubkey::from_base58(b58).expect("hard-coded program id must be valid base58/32 bytes")
}

/// System Program (`1111…`, the all-zero address).
pub fn system_program() -> Pubkey {
    Pubkey::new([0u8; 32])
}
/// Classic SPL Token program (`Tokenkeg…`).
pub fn token_program() -> Pubkey {
    from_known("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}
/// SPL Token-2022 program (`TokenzQd…`).
pub fn token_2022_program() -> Pubkey {
    from_known("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
}
/// Associated Token Account program (`ATokenGP…`).
pub fn associated_token_program() -> Pubkey {
    from_known("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
}
/// SPL Memo program (`MemoSq4g…`).
pub fn memo_program() -> Pubkey {
    from_known("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
}
/// RecentBlockhashes sysvar (required by `AdvanceNonceAccount`).
/// Verified against `solana_program::sysvar::recent_blockhashes::id()` (vecgen).
pub fn recent_blockhashes_sysvar() -> Pubkey {
    from_known("SysvarRecentB1ockHashes11111111111111111111")
}
/// Compute Budget program (`ComputeBudget…`).
/// Verified against `solana_compute_budget_interface::id()` (vecgen).
pub fn compute_budget_program() -> Pubkey {
    from_known("ComputeBudget111111111111111111111111111111")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base58_round_trips() {
        let pk = token_program();
        let s = pk.to_base58();
        assert_eq!(s, "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
        assert_eq!(Pubkey::from_base58(&s).unwrap(), pk);
    }

    #[test]
    fn known_program_ids_decode_to_32_bytes() {
        // Every accessor must decode without panicking (32-byte base58).
        let _ = system_program();
        let _ = token_program();
        let _ = token_2022_program();
        let _ = associated_token_program();
        let _ = memo_program();
    }

    #[test]
    fn from_base58_rejects_wrong_length() {
        assert!(matches!(
            Pubkey::from_base58("abc"),
            Err(PubkeyError::WrongLength(_))
        ));
        assert!(matches!(
            Pubkey::from_base58("0OIl"), // contains base58-invalid chars
            Err(PubkeyError::BadBase58)
        ));
    }

    #[test]
    fn pda_is_off_curve_and_deterministic() {
        let program = token_program();
        let (pda, bump) =
            Pubkey::find_program_address(&[b"seed", program.as_bytes()], &program).unwrap();
        // A valid PDA is never on the ed25519 curve.
        assert!(!pda.is_on_curve());
        // Deterministic.
        let (pda2, bump2) =
            Pubkey::find_program_address(&[b"seed", program.as_bytes()], &program).unwrap();
        assert_eq!(pda, pda2);
        assert_eq!(bump, bump2);
    }

    #[test]
    fn find_matches_create_with_the_found_bump() {
        let program = token_program();
        let (pda, bump) = Pubkey::find_program_address(&[b"x"], &program).unwrap();
        let direct = Pubkey::create_program_address(&[b"x", &[bump]], &program).unwrap();
        assert_eq!(pda, direct);
    }

    #[test]
    fn seed_limits_enforced() {
        let program = token_program();
        let too_long = [0u8; 33];
        assert_eq!(
            Pubkey::create_program_address(&[&too_long], &program),
            Err(PubkeyError::InvalidSeeds)
        );
        let seeds17: Vec<&[u8]> = (0..17).map(|_| b"a".as_slice()).collect();
        assert_eq!(
            Pubkey::create_program_address(&seeds17, &program),
            Err(PubkeyError::InvalidSeeds)
        );
    }

    // --- Known-answer vectors, generated from the canonical solana-program /
    // spl-associated-token-account reference impl (differential validation). ---

    #[test]
    fn known_answer_base58_matches_reference() {
        assert_eq!(
            Pubkey::new([7u8; 32]).to_base58(),
            "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx"
        );
        assert_eq!(
            Pubkey::new([9u8; 32]).to_base58(),
            "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN"
        );
    }

    #[test]
    fn known_answer_pda_matches_reference() {
        // solana_program::Pubkey::find_program_address([b"seed", wallet], Tokenkeg)
        let wallet = Pubkey::new([7u8; 32]);
        let (pda, bump) =
            Pubkey::find_program_address(&[b"seed", wallet.as_bytes()], &token_program()).unwrap();
        assert_eq!(
            pda.to_base58(),
            "4LSSVqFVwPMgYugMThJZa6tP2xHyFLKNU7q9JXMfXu4N"
        );
        assert_eq!(bump, 254);
    }

    #[test]
    fn known_answer_ata_matches_reference() {
        // spl_associated_token_account::get_associated_token_address(wallet, mint)
        let wallet = Pubkey::new([7u8; 32]);
        let mint = Pubkey::new([9u8; 32]);
        let ata = Pubkey::associated_token_address(&wallet, &mint, &token_program());
        assert_eq!(
            ata.to_base58(),
            "BjmJ1yi1Sc4s9xQaiv4DbRuUhgfjUSc8cYSuwsFqoS9"
        );
    }
}
