//! The one chain fact this plugin needs: the mint's decimals.
//!
//! x402 prices in ATOMIC base units and `allowance-spend-build` takes UI units, so converting
//! between them needs `decimals`. It is read from the chain rather than taken from config or from
//! the challenge, and the reason is different for each of those two:
//!
//! FROM THE CHALLENGE would be self-certification by the party being paid. A seller who declares
//! nine decimals for a six-decimal mint turns a 0.4 charge into 400, and every downstream check
//! still passes because the arithmetic is internally consistent.
//!
//! FROM CONFIG would be an operator asserting a property of someone else's account. It is right
//! until the operator points the config at a different mint and forgets, and then it is silently
//! wrong in the same direction.
//!
//! The mint account is the authority on its own decimals, so that is what is read. Transport-
//! generic so it is host-testable with `MockTransport`: no network in this function.

use solana_core::{decode_mint, pubkey, Pubkey, RpcTransport, SolanaRpc};

use crate::pay::sanitize_rpc_error;

/// A mint reporting more decimals than this is refused rather than trusted. Mirrors the ceiling
/// `allowance-spend-build` applies for the same reason: an attacker-controlled RPC can say
/// anything, and an absurd exponent is how that becomes an absurd amount.
pub const MAX_MINT_DECIMALS: u8 = 18;

/// Read `decimals` from the mint account, refusing anything that is not an SPL mint.
pub fn mint_decimals<T: RpcTransport>(rpc: &SolanaRpc<T>, mint: &Pubkey) -> Result<u8, String> {
    let acct = match rpc.get_account_info(mint) {
        Ok(Some(a)) => a,
        // NOT ECHO-BOUNDED, deliberately: `mint` is a `Pubkey`, so this is `bs58` of exactly 32
        // bytes. MEASURED against `Pubkey::from_base58`, which requires exactly 32 decoded bytes
        // and therefore admits nothing longer than 44 characters: a round-tripped address is 44
        // ASCII bytes and there is no input that makes it longer.
        Ok(None) => {
            return Err(format!(
                "the configured mint {} was not found on chain",
                mint.to_base58()
            ))
        }
        // BOUNDED. This is the most REMOTE string this crate renders: `RpcError::Rpc.message` is
        // the endpoint's own error text, and `RpcError::Transport` carries a 200-CHARACTER snippet
        // of a non-2xx body that `solana-core`'s transport does not sanitize at all. Both are
        // capped on characters upstream and neither is capped in BYTES, so an endpoint answering in
        // astral-plane codepoints reaches this line at four times the figure the cap suggests.
        Err(e) => return Err(sanitize_rpc_error("rpc error fetching the mint", &e)),
    };

    // The OWNER selects the layout, so it is checked before the data is decoded rather than
    // after. A non-token account decoded as a mint yields a plausible byte at the decimals
    // offset, which is a wrong exponent that looks like a right one.
    let token_2022 = acct.owner == pubkey::token_2022_program();
    // NOT ECHO-BOUNDED, deliberately: `acct.owner` is a `Pubkey` decoded from the response, so it
    // is 32 bytes re-encoded, 44 ASCII characters at most, whatever the node sent.
    if !token_2022 && acct.owner != pubkey::token_program() {
        return Err(format!(
            "the configured mint is owned by {}, which is not an SPL token program; it is not a \
             mint and its bytes must not be read as one",
            acct.owner.to_base58()
        ));
    }

    // NOT ECHO-BOUNDED, deliberately: every `MintError` variant carries a NUMBER and no string --
    // `TooShort(usize)`, `NotAMint(u8)`, `MalformedTlv(usize)`, `BadCOption(u32)`. None of the
    // account's bytes reach this message.
    let decoded = decode_mint(&acct.data, token_2022)
        .map_err(|e| format!("the mint account did not decode: {e:?}"))?;
    // NOT ECHO-BOUNDED, deliberately: `decimals` is a `u8`.
    if decoded.decimals > MAX_MINT_DECIMALS {
        return Err(format!(
            "the mint reports {} decimals, over the {MAX_MINT_DECIMALS} ceiling; refusing to \
             convert an amount against an implausible exponent",
            decoded.decimals
        ));
    }
    Ok(decoded.decimals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_core::MockTransport;

    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const TOKEN22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

    fn pk(s: &str) -> Pubkey {
        Pubkey::from_base58(s).expect("address parses")
    }

    /// A legacy SPL mint account: 82 bytes, `decimals` at offset 44.
    fn mint_account(owner: &str, decimals: u8) -> String {
        let mut data = vec![0u8; 82];
        data[44] = decimals;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"context":{{"slot":1}},"value":{{"data":["{b64}","base64"],"executable":false,"lamports":1,"owner":"{owner}","rentEpoch":0}}}}}}"#
        )
    }

    #[test]
    fn usdc_reports_six_decimals() {
        let rpc = SolanaRpc::new(MockTransport::single(mint_account(TOKEN, 6)));
        assert_eq!(mint_decimals(&rpc, &pk(USDC)).unwrap(), 6);
    }

    #[test]
    fn a_token_2022_mint_is_read_too() {
        let rpc = SolanaRpc::new(MockTransport::single(mint_account(TOKEN22, 9)));
        assert_eq!(mint_decimals(&rpc, &pk(USDC)).unwrap(), 9);
    }

    #[test]
    fn an_account_owned_by_something_else_is_refused_rather_than_decoded() {
        // The bytes would decode: offset 44 holds a plausible decimals value. Checking the owner
        // FIRST is what stops a wrong exponent that looks like a right one.
        let rpc = SolanaRpc::new(MockTransport::single(mint_account(
            "11111111111111111111111111111111",
            6,
        )));
        let e = mint_decimals(&rpc, &pk(USDC)).unwrap_err();
        assert!(e.contains("not an SPL token program"), "{e}");
    }

    #[test]
    fn an_implausible_decimals_is_refused() {
        let rpc = SolanaRpc::new(MockTransport::single(mint_account(TOKEN, 200)));
        let e = mint_decimals(&rpc, &pk(USDC)).unwrap_err();
        assert!(e.contains("ceiling"), "{e}");
    }

    #[test]
    fn a_missing_mint_is_refused_rather_than_defaulted() {
        let rpc = SolanaRpc::new(MockTransport::single(
            r#"{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":null}}"#,
        ));
        assert!(mint_decimals(&rpc, &pk(USDC))
            .unwrap_err()
            .contains("not found on chain"));
    }

    #[test]
    fn an_rpc_error_is_refused_rather_than_defaulted() {
        // A default of 6 here would be right for USDC and wrong for everything else, and it would
        // be wrong in the direction that overpays on a nine-decimal mint.
        let rpc = SolanaRpc::new(MockTransport::single("not json at all"));
        assert!(mint_decimals(&rpc, &pk(USDC))
            .unwrap_err()
            .contains("rpc error"));
    }
}
