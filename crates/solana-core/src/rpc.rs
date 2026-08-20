//! JSON-RPC spine: a one-method [`RpcTransport`] seam, a generic [`SolanaRpc`]
//! client over it, and an injectable [`MockTransport`] so every plugin is
//! host-testable with no live network.
//!
//! In a wasm plugin the transport is implemented with `waki` (blocking
//! `wasi:http`); in tests it is `MockTransport`. The core never depends on wasm.

use crate::pubkey::{Pubkey, PubkeyError};
use base64::Engine;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// The transport (HTTP) layer failed.
    Transport(String),
    /// The node returned a JSON-RPC `error` object.
    Rpc { code: i64, message: String },
    /// The response could not be parsed into the expected shape.
    Parse(String),
}

impl From<PubkeyError> for RpcError {
    fn from(e: PubkeyError) -> Self {
        RpcError::Parse(format!("pubkey: {e:?}"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commitment {
    Processed,
    Confirmed,
    Finalized,
}

impl Commitment {
    pub fn as_str(self) -> &'static str {
        match self {
            Commitment::Processed => "processed",
            Commitment::Confirmed => "confirmed",
            Commitment::Finalized => "finalized",
        }
    }
}

/// The single seam between the client and the outside world. Implement this
/// with `waki` inside a wasm plugin; inject [`MockTransport`] in host tests.
pub trait RpcTransport {
    /// POST a JSON-RPC request body and return the raw response body.
    fn post_json(&self, body: &str) -> Result<String, RpcError>;
}

/// A canned transport for host tests. Returns queued responses in order, then
/// repeats the last one; records every request body for assertions.
pub struct MockTransport {
    queue: RefCell<VecDeque<String>>,
    last: RefCell<Option<String>>,
    pub requests: RefCell<Vec<String>>,
}

impl MockTransport {
    pub fn new(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        MockTransport {
            queue: RefCell::new(responses.into_iter().map(Into::into).collect()),
            last: RefCell::new(None),
            requests: RefCell::new(Vec::new()),
        }
    }

    pub fn single(response: impl Into<String>) -> Self {
        MockTransport::new([response.into()])
    }
}

impl RpcTransport for MockTransport {
    fn post_json(&self, body: &str) -> Result<String, RpcError> {
        self.requests.borrow_mut().push(body.to_string());
        if let Some(r) = self.queue.borrow_mut().pop_front() {
            *self.last.borrow_mut() = Some(r.clone());
            Ok(r)
        } else if let Some(r) = self.last.borrow().clone() {
            Ok(r)
        } else {
            Err(RpcError::Transport("mock: no response queued".into()))
        }
    }
}

/// An account as returned by `getAccountInfo` (base64 data decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountInfo {
    pub lamports: u64,
    pub owner: Pubkey,
    pub data: Vec<u8>,
    pub executable: bool,
    pub rent_epoch: u64,
}

/// A recent blockhash plus the last block height at which it stays valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatestBlockhash {
    pub blockhash: [u8; 32],
    pub last_valid_block_height: u64,
}

/// Generic Solana JSON-RPC client over any [`RpcTransport`].
pub struct SolanaRpc<T: RpcTransport> {
    transport: T,
    commitment: Commitment,
    id: Cell<u64>,
}

impl<T: RpcTransport> SolanaRpc<T> {
    pub fn new(transport: T) -> Self {
        SolanaRpc {
            transport,
            commitment: Commitment::Confirmed,
            id: Cell::new(1),
        }
    }

    pub fn with_commitment(mut self, c: Commitment) -> Self {
        self.commitment = c;
        self
    }

    /// Borrow the underlying transport.
    ///
    /// For host tests holding a [`MockTransport`], whose `requests` log answers a question
    /// no return value can: whether a call reached the network AT ALL. A test asserting
    /// that an unacceptable payment is refused BEFORE broadcast has to read this, because
    /// "refused" and "refused only after we sent it" produce the same status code.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn next_id(&self) -> u64 {
        let n = self.id.get();
        self.id.set(n + 1);
        n
    }

    /// Issue a JSON-RPC call and return its `result` value (or a mapped error).
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.next_id(),
            "method": method,
            "params": params,
        })
        .to_string();
        let resp = self.transport.post_json(&body)?;
        let v: serde_json::Value =
            serde_json::from_str(&resp).map_err(|e| RpcError::Parse(e.to_string()))?;
        if let Some(err) = v.get("error") {
            return Err(RpcError::Rpc {
                code: err
                    .get("code")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0),
                // The endpoint's own error text is untrusted response-path data
                // (a compromised/hostile RPC can inject unbounded or hidden-framing
                // text here). Strip control/zero-width/bidi and cap it, matching the
                // discipline sanitize_onchain applies to on-chain metadata.
                message: crate::sanitize::sanitize_onchain(
                    err.get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                    200,
                )
                .text,
            });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::Parse("missing `result`".into()))
    }

    pub fn get_account_info(&self, pubkey: &Pubkey) -> Result<Option<AccountInfo>, RpcError> {
        let params = serde_json::json!([
            pubkey.to_base58(),
            { "encoding": "base64", "commitment": self.commitment.as_str() },
        ]);
        let result = self.call("getAccountInfo", params)?;
        let value = result
            .get("value")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if value.is_null() {
            return Ok(None);
        }
        parse_account(&value).map(Some)
    }

    pub fn get_balance(&self, pubkey: &Pubkey) -> Result<u64, RpcError> {
        let params = serde_json::json!([
            pubkey.to_base58(),
            { "commitment": self.commitment.as_str() },
        ]);
        let result = self.call("getBalance", params)?;
        result
            .get("value")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| RpcError::Parse("getBalance: bad value".into()))
    }

    /// Broadcast a signed transaction (wire bytes) and return its signature
    /// string. `skip_preflight=false` keeps the node's simulation gate on.
    pub fn send_transaction(&self, tx_bytes: &[u8]) -> Result<String, RpcError> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(tx_bytes);
        let params = serde_json::json!([
            encoded,
            { "encoding": "base64", "preflightCommitment": self.commitment.as_str() },
        ]);
        let result = self.call("sendTransaction", params)?;
        let sig = result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Parse("sendTransaction: non-string result".into()))?;
        // A real signature is base58 of 64 bytes (<=88 chars). Reject a
        // maliciously oversized "signature" from a compromised RPC before it
        // reaches the caller and, via the plugin, the agent's context.
        if sig.len() > 96 {
            return Err(RpcError::Parse(
                "sendTransaction: oversized signature".into(),
            ));
        }
        Ok(sig)
    }

    pub fn get_latest_blockhash(&self) -> Result<LatestBlockhash, RpcError> {
        let params = serde_json::json!([{ "commitment": self.commitment.as_str() }]);
        let result = self.call("getLatestBlockhash", params)?;
        let value = result
            .get("value")
            .ok_or_else(|| RpcError::Parse("getLatestBlockhash: no value".into()))?;
        let bh = value
            .get("blockhash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| RpcError::Parse("getLatestBlockhash: no blockhash".into()))?;
        Ok(LatestBlockhash {
            blockhash: Pubkey::from_base58(bh)?.to_bytes(),
            last_valid_block_height: value
                .get("lastValidBlockHeight")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        })
    }

    /// Simulate a transaction without broadcasting. Returns `Ok(None)` when the
    /// simulation succeeded (no `err`), or `Ok(Some(err_string))` when the
    /// runtime rejected it. Transport/parse failures surface as `Err`.
    ///
    /// The verifier runs this before `send_transaction` so a payment that would
    /// fail on-chain is rejected up front rather than broadcast and lost.
    pub fn simulate_transaction(&self, tx_bytes: &[u8]) -> Result<Option<String>, RpcError> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(tx_bytes);
        let params = serde_json::json!([
            encoded,
            {
                "encoding": "base64",
                "commitment": self.commitment.as_str(),
                "replaceRecentBlockhash": false,
                "sigVerify": true,
            },
        ]);
        let result = self.call("simulateTransaction", params)?;
        let value = result
            .get("value")
            .ok_or_else(|| RpcError::Parse("simulateTransaction: no value".into()))?;
        match value.get("err") {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(err) => Ok(Some(err.to_string())),
        }
    }

    /// Fetch the confirmation status of one signature. Returns `Ok(None)` when
    /// the signature is not yet known to the cluster, or `Ok(Some(status))`
    /// with the confirmation level (`processed` / `confirmed` / `finalized`)
    /// and any execution error.
    pub fn get_signature_status(
        &self,
        signature: &str,
    ) -> Result<Option<SignatureStatus>, RpcError> {
        if signature.len() > 96 {
            return Err(RpcError::Parse(
                "get_signature_status: oversized signature".into(),
            ));
        }
        let params = serde_json::json!([[signature], { "searchTransactionHistory": true }]);
        let result = self.call("getSignatureStatuses", params)?;
        let first = result
            .get("value")
            .and_then(|v| v.get(0))
            .ok_or_else(|| RpcError::Parse("getSignatureStatuses: no value[0]".into()))?;
        if first.is_null() {
            return Ok(None);
        }
        let confirmation = first
            .get("confirmationStatus")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("processed")
            .to_string();
        let err = first.get("err").and_then(|e| {
            if e.is_null() {
                None
            } else {
                Some(e.to_string())
            }
        });
        Ok(Some(SignatureStatus { confirmation, err }))
    }
}

/// Confirmation status of a transaction signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureStatus {
    /// `processed` | `confirmed` | `finalized`.
    pub confirmation: String,
    /// Execution error string when the transaction failed, else `None`.
    pub err: Option<String>,
}

impl SignatureStatus {
    /// Whether the signature has reached at least `confirmed` (i.e. not merely
    /// `processed`) and carried no execution error.
    pub fn is_settled(&self) -> bool {
        self.err.is_none() && matches!(self.confirmation.as_str(), "confirmed" | "finalized")
    }
}

fn parse_account(value: &serde_json::Value) -> Result<AccountInfo, RpcError> {
    let lamports = value
        .get("lamports")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| RpcError::Parse("account: lamports".into()))?;
    let owner_s = value
        .get("owner")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RpcError::Parse("account: owner".into()))?;
    Ok(AccountInfo {
        lamports,
        owner: Pubkey::from_base58(owner_s)?,
        data: decode_base64_data(value.get("data"))?,
        executable: value
            .get("executable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        rent_epoch: value
            .get("rentEpoch")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
    })
}

/// `getAccountInfo` returns `data: ["<base64>", "base64"]`. Any other shape
/// (jsonParsed, or absent) yields empty bytes.
fn decode_base64_data(d: Option<&serde_json::Value>) -> Result<Vec<u8>, RpcError> {
    match d
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|s| s.as_str())
    {
        Some(b64) => base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| RpcError::Parse(format!("account data base64: {e}"))),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pubkey::token_program;

    #[test]
    fn get_account_info_parses_base64_data() {
        // owner = Tokenkeg, data = base64("AQID") = [1,2,3].
        let resp = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"lamports":1000000,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","data":["AQID","base64"],"executable":false,"rentEpoch":18446744073709551615,"space":3}},"id":1}"#;
        let rpc = SolanaRpc::new(MockTransport::single(resp));
        let acct = rpc.get_account_info(&token_program()).unwrap().unwrap();
        assert_eq!(acct.lamports, 1_000_000);
        assert_eq!(acct.owner, token_program());
        assert_eq!(acct.data, vec![1, 2, 3]);
        assert!(!acct.executable);
    }

    #[test]
    fn get_account_info_null_is_none() {
        let resp = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":null},"id":1}"#;
        let rpc = SolanaRpc::new(MockTransport::single(resp));
        assert_eq!(rpc.get_account_info(&token_program()).unwrap(), None);
    }

    #[test]
    fn get_balance_reads_value() {
        let resp = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":12345},"id":1}"#;
        let rpc = SolanaRpc::new(MockTransport::single(resp));
        assert_eq!(rpc.get_balance(&token_program()).unwrap(), 12345);
    }

    #[test]
    fn get_latest_blockhash_decodes_32_bytes() {
        // Fixture blockhash is a valid 32-byte base58 (Tokenkeg reused as bytes).
        let resp = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"blockhash":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","lastValidBlockHeight":3090}},"id":1}"#;
        let rpc = SolanaRpc::new(MockTransport::single(resp));
        let bh = rpc.get_latest_blockhash().unwrap();
        assert_eq!(bh.blockhash, token_program().to_bytes());
        assert_eq!(bh.last_valid_block_height, 3090);
    }

    #[test]
    fn send_transaction_encodes_base64_and_returns_signature() {
        let resp = r#"{"jsonrpc":"2.0","result":"5j7s6NiJS3JAkvgkoc18WVAsiSaci2pxB2A6ueCJP4tprA2TFg9wSyTLeYouxPBJEMzJinENTkpA52YStRW5Dia7","id":1}"#;
        let rpc = SolanaRpc::new(MockTransport::single(resp));
        let sig = rpc.send_transaction(&[1, 2, 3]).unwrap();
        assert!(sig.starts_with("5j7s6NiJS3"));
        let body = rpc.transport.requests.borrow()[0].clone();
        // base64([1,2,3]) = "AQID"; preflight commitment travels with the call.
        assert!(body.contains("sendTransaction") && body.contains("AQID"));
        assert!(body.contains("preflightCommitment"));
    }

    #[test]
    fn rpc_error_object_maps_to_error() {
        let resp = r#"{"jsonrpc":"2.0","error":{"code":-32002,"message":"Transaction simulation failed"},"id":1}"#;
        let rpc = SolanaRpc::new(MockTransport::single(resp));
        match rpc.get_balance(&token_program()) {
            Err(RpcError::Rpc { code, message }) => {
                assert_eq!(code, -32002);
                assert!(message.contains("simulation failed"));
            }
            other => panic!("expected Rpc error, got {other:?}"),
        }
    }

    #[test]
    fn request_bodies_carry_method_and_incrementing_id() {
        let rpc = SolanaRpc::new(MockTransport::new([
            r#"{"jsonrpc":"2.0","result":{"value":5},"id":1}"#,
            r#"{"jsonrpc":"2.0","result":{"value":{"lamports":1,"owner":"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA","data":["","base64"],"executable":false,"rentEpoch":0}},"id":2}"#,
        ]));
        let _ = rpc.get_balance(&token_program()).unwrap();
        let _ = rpc.get_account_info(&token_program()).unwrap();
        let bodies = rpc.transport.requests.borrow();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains("getBalance") && bodies[0].contains("\"id\":1"));
        assert!(bodies[1].contains("getAccountInfo") && bodies[1].contains("\"id\":2"));
    }
}
