//! Token mint decoding: SPL Token legacy (82-byte) and Token-2022 with TLV
//! extensions. SPL uses C-`Pack` fixed offsets (not borsh), so this is a
//! hand-rolled, bounds-checked reader that fails closed on anything malformed.
//!
//! Layout facts (verified against the SPL Token-2022 account layout):
//! legacy `Mint` is 82 bytes; Token-2022 pads to 165, puts the account-type
//! byte at offset 165 (`1` = Mint), and packs TLV entries from offset 166 as
//! `[type u16 LE][len u16 LE][data]`. Extension discriminants confirmed live:
//! #1 TransferFeeConfig, #3 MintCloseAuthority, #6 DefaultAccountState,
//! #12 PermanentDelegate, #14 TransferHook, #26 Pausable. Never hardcode a
//! maximum discriminant: upstream keeps adding extensions (#28 exists), so
//! unknown discriminants are preserved raw and surfaced, not rejected.

/// Size of a legacy SPL Token `Mint` account.
pub const LEGACY_MINT_LEN: usize = 82;
/// Offset of the Token-2022 account-type byte.
pub const ACCOUNT_TYPE_OFFSET: usize = 165;
/// First byte of the Token-2022 TLV region.
pub const TLV_START: usize = 166;
/// Token-2022 `AccountType::Mint`.
const ACCOUNT_TYPE_MINT: u8 = 1;

pub const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
pub const EXT_MINT_CLOSE_AUTHORITY: u16 = 3;
pub const EXT_DEFAULT_ACCOUNT_STATE: u16 = 6;
pub const EXT_PERMANENT_DELEGATE: u16 = 12;
pub const EXT_TRANSFER_HOOK: u16 = 14;
pub const EXT_PAUSABLE: u16 = 26;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintError {
    /// Account data shorter than a legacy mint (or than the TLV header).
    TooShort(usize),
    /// The Token-2022 account-type byte is not `Mint`.
    NotAMint(u8),
    /// A TLV entry's declared length overruns the account data (byte offset).
    MalformedTlv(usize),
    /// A `COption` tag was neither 0 nor 1.
    BadCOption(u32),
}

/// One TLV extension entry, kept raw so unknown discriminants survive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExtension {
    pub discriminant: u16,
    pub data: Vec<u8>,
}

impl RawExtension {
    /// Human name for the live-verified discriminants; `None` for the rest.
    pub fn name(&self) -> Option<&'static str> {
        match self.discriminant {
            EXT_TRANSFER_FEE_CONFIG => Some("TransferFeeConfig"),
            EXT_MINT_CLOSE_AUTHORITY => Some("MintCloseAuthority"),
            EXT_DEFAULT_ACCOUNT_STATE => Some("DefaultAccountState"),
            EXT_PERMANENT_DELEGATE => Some("PermanentDelegate"),
            EXT_TRANSFER_HOOK => Some("TransferHook"),
            EXT_PAUSABLE => Some("Pausable"),
            _ => None,
        }
    }
}

/// A decoded mint: the legacy fields plus any Token-2022 extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedMint {
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
    pub has_mint_authority: bool,
    pub has_freeze_authority: bool,
    pub token_2022: bool,
    pub extensions: Vec<RawExtension>,
}

impl DecodedMint {
    /// First match wins, which is what the Token-2022 program itself does.
    ///
    /// Worth stating because the alternative reading is a vulnerability: if a mint could
    /// carry two entries of one type, an attacker could place a benign PermanentDelegate
    /// first and a live one second, and a first-match lookup would report the token safe.
    /// Checked against the program rather than assumed. `get_extension_indices` in
    /// token-2022's `interface/src/extension/mod.rs` returns on the first type match
    /// ("found an instance of the extension that we're initializing, return!"), and `alloc`
    /// refuses to write over an existing entry with `TokenError::ExtensionAlreadyInitialized`
    /// unless an explicit overwrite is requested, which replaces that entry in place rather
    /// than appending a second. So duplicates are not constructible through the program, and
    /// where they cannot occur, first-match is the same answer the chain would give.
    pub fn extension(&self, discriminant: u16) -> Option<&RawExtension> {
        self.extensions
            .iter()
            .find(|e| e.discriminant == discriminant)
    }

    /// PermanentDelegate carries one `OptionalNonZeroPubkey` (32 bytes,
    /// all-zero = none). Active delegate = any nonzero byte.
    pub fn permanent_delegate_active(&self) -> bool {
        self.extension(EXT_PERMANENT_DELEGATE)
            .map(|e| e.data.iter().take(32).any(|&b| b != 0))
            .unwrap_or(false)
    }

    /// TransferHook is `{ authority: OptionalNonZeroPubkey, program_id:
    /// OptionalNonZeroPubkey }`; the hook bites only if `program_id` is set.
    pub fn transfer_hook_program_active(&self) -> bool {
        self.extension(EXT_TRANSFER_HOOK)
            .and_then(|e| e.data.get(32..64))
            .map(|pk| pk.iter().any(|&b| b != 0))
            .unwrap_or(false)
    }

    /// DefaultAccountState is one byte; `2` = Frozen (new accounts unusable
    /// until thawed by the freeze authority).
    pub fn default_state_frozen(&self) -> bool {
        self.extension(EXT_DEFAULT_ACCOUNT_STATE)
            .and_then(|e| e.data.first())
            .map(|&s| s == 2)
            .unwrap_or(false)
    }

    /// TransferFeeConfig is `{ config_authority: ONZPubkey(32),
    /// withdraw_withheld_authority: ONZPubkey(32), withheld_amount: u64(8),
    /// older: TransferFee(18), newer: TransferFee(18) }` = 108 bytes, where
    /// `TransferFee = { epoch: u64, maximum_fee: u64, basis_points: u16 }`.
    /// Returns the NEWER fee's basis points. (Offsets flagged in open-unknowns
    /// for one live-mint validation before ship: Pod layout has no padding, but
    /// verify against a real transfer-fee mint.)
    pub fn transfer_fee_bps(&self) -> Option<u16> {
        let e = self.extension(EXT_TRANSFER_FEE_CONFIG)?;
        let b = e.data.get(106..108)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
}

fn coption_present(data: &[u8], at: usize) -> Result<bool, MintError> {
    let tag_bytes: [u8; 4] = data[at..at + 4].try_into().expect("caller bounds-checked");
    match u32::from_le_bytes(tag_bytes) {
        0 => Ok(false),
        1 => Ok(true),
        t => Err(MintError::BadCOption(t)),
    }
}

/// Decode a mint account's raw data. `token_2022` = the account's owner is the
/// Token-2022 program (the caller checks the owner; this function trusts it
/// only to decide whether a TLV region may follow the legacy fields).
pub fn decode_mint(data: &[u8], token_2022: bool) -> Result<DecodedMint, MintError> {
    if data.len() < LEGACY_MINT_LEN {
        return Err(MintError::TooShort(data.len()));
    }
    let has_mint_authority = coption_present(data, 0)?;
    let supply = u64::from_le_bytes(data[36..44].try_into().expect("bounds checked"));
    let decimals = data[44];
    let is_initialized = data[45] != 0;
    let has_freeze_authority = coption_present(data, 46)?;

    let mut extensions = Vec::new();
    if token_2022 && data.len() > LEGACY_MINT_LEN {
        if data.len() < TLV_START {
            return Err(MintError::TooShort(data.len()));
        }
        let account_type = data[ACCOUNT_TYPE_OFFSET];
        if account_type != ACCOUNT_TYPE_MINT {
            return Err(MintError::NotAMint(account_type));
        }
        let mut i = TLV_START;
        // Bound the number of TLV extensions parsed: a hostile ~10 MiB mint
        // account could otherwise carry millions of tiny entries, forcing
        // millions of heap allocations before any caller can cap them. A real
        // Token-2022 mint has a handful; 64 is comfortably above any legitimate
        // count and keeps per-call memory bounded regardless of account size.
        const MAX_EXTENSIONS: usize = 64;
        while i + 4 <= data.len() && extensions.len() < MAX_EXTENSIONS {
            let discriminant = u16::from_le_bytes([data[i], data[i + 1]]);
            if discriminant == 0 {
                // Uninitialized entry: padding from here on. This matches the program,
                // not just our own convention: token-2022's `get_extension_indices`
                // stops the moment it sees `ExtensionType::Uninitialized` rather than
                // scanning past it, so an entry hidden behind a zero would be invisible
                // to the chain as well and must be invisible here.
                break;
            }
            let len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
            let end = i + 4 + len;
            if end > data.len() {
                return Err(MintError::MalformedTlv(i));
            }
            extensions.push(RawExtension {
                discriminant,
                data: data[i + 4..end].to_vec(),
            });
            i = end;
        }
    }

    Ok(DecodedMint {
        supply,
        decimals,
        is_initialized,
        has_mint_authority,
        has_freeze_authority,
        token_2022,
        extensions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A legacy 82-byte mint: authority present, supply 1e6, 6 decimals,
    /// initialized, no freeze authority.
    fn legacy_mint() -> Vec<u8> {
        let mut d = vec![0u8; LEGACY_MINT_LEN];
        d[0] = 1; // COption tag = Some (mint authority)
        d[36..44].copy_from_slice(&1_000_000u64.to_le_bytes());
        d[44] = 6;
        d[45] = 1;
        // freeze tag at 46 stays 0 = None
        d
    }

    /// A Token-2022 mint buffer carrying the given TLV entries.
    fn t22_mint(exts: &[(u16, &[u8])]) -> Vec<u8> {
        let mut d = legacy_mint();
        d.resize(TLV_START, 0);
        d[ACCOUNT_TYPE_OFFSET] = ACCOUNT_TYPE_MINT;
        for (t, data) in exts {
            d.extend_from_slice(&t.to_le_bytes());
            d.extend_from_slice(&(data.len() as u16).to_le_bytes());
            d.extend_from_slice(data);
        }
        d
    }

    #[test]
    fn legacy_mint_decodes() {
        let m = decode_mint(&legacy_mint(), false).unwrap();
        assert_eq!(m.supply, 1_000_000);
        assert_eq!(m.decimals, 6);
        assert!(m.is_initialized && m.has_mint_authority && !m.has_freeze_authority);
        assert!(!m.token_2022 && m.extensions.is_empty());
    }

    #[test]
    fn permanent_delegate_detected() {
        let delegate = [7u8; 32];
        let m = decode_mint(&t22_mint(&[(EXT_PERMANENT_DELEGATE, &delegate)]), true).unwrap();
        assert!(m.permanent_delegate_active());
        assert_eq!(m.extensions[0].name(), Some("PermanentDelegate"));
    }

    #[test]
    fn all_zero_permanent_delegate_is_inactive() {
        let m = decode_mint(&t22_mint(&[(EXT_PERMANENT_DELEGATE, &[0u8; 32])]), true).unwrap();
        assert!(!m.permanent_delegate_active());
    }

    #[test]
    fn transfer_hook_program_detected() {
        let mut ext = vec![0u8; 64];
        ext[32..64].copy_from_slice(&[9u8; 32]); // program_id set, authority none
        let m = decode_mint(&t22_mint(&[(EXT_TRANSFER_HOOK, &ext)]), true).unwrap();
        assert!(m.transfer_hook_program_active());
    }

    #[test]
    fn transfer_fee_bps_parsed() {
        let mut ext = vec![0u8; 108];
        ext[106..108].copy_from_slice(&300u16.to_le_bytes()); // newer fee = 300 bps
        let m = decode_mint(&t22_mint(&[(EXT_TRANSFER_FEE_CONFIG, &ext)]), true).unwrap();
        assert_eq!(m.transfer_fee_bps(), Some(300));
    }

    #[test]
    fn default_state_frozen_detected() {
        let m = decode_mint(&t22_mint(&[(EXT_DEFAULT_ACCOUNT_STATE, &[2u8])]), true).unwrap();
        assert!(m.default_state_frozen());
    }

    #[test]
    fn truncated_tlv_fails_closed() {
        let mut d = t22_mint(&[]);
        // Entry claims 64 bytes of data but the buffer ends after 4.
        d.extend_from_slice(&EXT_PERMANENT_DELEGATE.to_le_bytes());
        d.extend_from_slice(&64u16.to_le_bytes());
        d.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(
            decode_mint(&d, true),
            Err(MintError::MalformedTlv(_))
        ));
    }

    #[test]
    fn wrong_account_type_rejected() {
        let mut d = t22_mint(&[]);
        d[ACCOUNT_TYPE_OFFSET] = 2; // AccountType::Account, not Mint
        assert!(matches!(decode_mint(&d, true), Err(MintError::NotAMint(2))));
    }

    #[test]
    fn bad_coption_tag_rejected() {
        let mut d = legacy_mint();
        d[0] = 7;
        assert!(matches!(
            decode_mint(&d, false),
            Err(MintError::BadCOption(7))
        ));
    }

    #[test]
    fn unknown_discriminant_preserved_not_rejected() {
        let m = decode_mint(&t22_mint(&[(999, &[1, 2, 3])]), true).unwrap();
        assert_eq!(m.extensions[0].discriminant, 999);
        assert_eq!(m.extensions[0].name(), None);
    }

    #[test]
    fn zero_discriminant_stops_scan() {
        let mut d = t22_mint(&[(EXT_PAUSABLE, &[1])]);
        d.extend_from_slice(&[0u8; 8]); // trailing padding after real entries
        let m = decode_mint(&d, true).unwrap();
        assert_eq!(m.extensions.len(), 1);
    }

    #[test]
    fn too_short_fails_closed() {
        assert!(matches!(
            decode_mint(&[0u8; 40], false),
            Err(MintError::TooShort(40))
        ));
    }

    // -- Real mainnet fixtures (fetched live 2026-07-19 via getAccountInfo,
    // -- base64 baked so tests stay offline). Expected values come from an
    // -- INDEPENDENT python decode of the same bytes: two implementations
    // -- agreeing on real data validates the offsets, not just self-consistency.

    /// USDC (EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v), legacy SPL mint.
    const USDC_MINT_B64: &str = "AQAAAJj+huiNm+Lqi8HMpIeLKYjCQPUrhCS/tA7Rot3LXhmbHO7GeqM1HAAGAQEAAABicKqKWcWUBbRShshncubNEm6bil06OFNtN/e0FOi2Zw==";

    /// PYUSD (2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo), Token-2022 with a
    /// real TLV region: MintCloseAuthority(#3), PermanentDelegate(#12),
    /// TransferFeeConfig(#1, 108 bytes, 0 bps), ConfidentialTransfer(#4),
    /// ConfidentialTransferFee(#16), TransferHook(#14, authority set but NO
    /// program), MetadataPointer(#18), TokenMetadata(#19).
    const PYUSD_MINT_B64: &str = "AQAAAGyRqkllkBL4q+lh7CS2EHSSZUdTL/CU7VtpOYLbmHMTNKdcjFBqAgAGAQEAAAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMAIAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwwAIAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKwEAbAAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKxeFMmHvarhTKmfwU4ZarTEpP88HzxIKtbmhVwZUjcArAAAAAAAAAABdAgAAAAAAAAAAAAAAAAAAAABdAgAAAAAAAAAAAAAAAAAAAAAEAEEAF4UyYe9quFMqZ/BThlqtMSk/zwfPEgq1uaFXBlSNwCsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAIEAF4UyYe9quFMqZ/BThlqtMSk/zwfPEgq1uaFXBlSNwCscN+ZDO3ME3YJzeuQNm4vzxJ9bDmxJqNUzKLPlBpAcVwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgBAABeFMmHvarhTKmfwU4ZarTEpP88HzxIKtbmhVwZUjcArAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAEAAF4UyYe9quFMqZ/BThlqtMSk/zwfPEgq1uaFXBlSNwCsXkkg7bIoqh7dHHYFPlZH5OVyECpzj2fTVun06S4p0nhMArgAXhTJh72q4Uypn8FOGWq0xKT/PB88SCrW5oVcGVI3AKxeSSDtsiiqHt0cdgU+Vkfk5XIQKnOPZ9NW6fTpLinSeCgAAAFBheVBhbCBVU0QFAAAAUFlVU0RPAAAAaHR0cHM6Ly90b2tlbi1tZXRhZGF0YS5wYXhvcy5jb20vcHl1c2RfbWV0YWRhdGEvcHJvZC9zb2xhbmEvcHl1c2RfbWV0YWRhdGEuanNvbgAAAAA=";

    fn from_b64(s: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    #[test]
    fn real_usdc_legacy_mint_decodes() {
        let m = decode_mint(&from_b64(USDC_MINT_B64), false).unwrap();
        assert_eq!(m.supply, 7_940_275_603_697_180); // snapshot 2026-07-19
        assert_eq!(m.decimals, 6);
        assert!(m.is_initialized && m.has_mint_authority && m.has_freeze_authority);
        assert!(!m.token_2022 && m.extensions.is_empty());
    }

    #[test]
    fn real_pyusd_token_2022_tlv_walk_matches_independent_decode() {
        let m = decode_mint(&from_b64(PYUSD_MINT_B64), true).unwrap();
        assert_eq!(m.supply, 679_844_138_231_604); // snapshot 2026-07-19
        assert_eq!(m.decimals, 6);
        assert!(m.has_mint_authority && m.has_freeze_authority);
        let discs: Vec<u16> = m.extensions.iter().map(|e| e.discriminant).collect();
        assert_eq!(discs, vec![3, 12, 1, 4, 16, 14, 18, 19]);
        // PYUSD's real risk surface, correctly read:
        assert!(
            m.permanent_delegate_active(),
            "Paxos permanent delegate is set"
        );
        assert_eq!(
            m.transfer_fee_bps(),
            Some(0),
            "fee config present, zero fee"
        );
        assert!(
            !m.transfer_hook_program_active(),
            "hook AUTHORITY is set but no hook PROGRAM — must not read as active"
        );
        assert!(!m.default_state_frozen());
    }
}
