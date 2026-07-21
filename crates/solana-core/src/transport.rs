//! The wasm-side [`RpcTransport`]: blocking `wasi:http` via `waki`. Compiled
//! only for wasm targets, so host builds and tests stay free of any wasm
//! dependency (they inject [`crate::MockTransport`] instead).
//!
//! Rigor bar (matches the strongest transport in the field, not the loosest):
//! explicit Content-Type/Accept headers, a connect timeout, a 2xx status gate,
//! and error bodies truncated to a short snippet so an RPC's own error text
//! reaches the operator without flooding agent context.

use crate::rpc::{RpcError, RpcTransport};
use std::time::Duration;

pub struct WakiTransport {
    url: String,
    connect_timeout: Duration,
}

impl WakiTransport {
    pub fn new(url: impl Into<String>) -> Self {
        WakiTransport {
            url: url.into(),
            connect_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_connect_timeout_secs(mut self, secs: u64) -> Self {
        self.connect_timeout = Duration::from_secs(secs);
        self
    }
}

impl RpcTransport for WakiTransport {
    fn post_json(&self, body: &str) -> Result<String, RpcError> {
        let resp = waki::Client::new()
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(body.as_bytes().to_vec())
            .connect_timeout(self.connect_timeout)
            .send()
            .map_err(|e| RpcError::Transport(format!("request failed: {e}")))?;

        let status = resp.status_code();
        let bytes = resp
            .body()
            .map_err(|e| RpcError::Transport(format!("reading body failed: {e}")))?;
        let text = String::from_utf8(bytes)
            .map_err(|e| RpcError::Transport(format!("non-utf8 body: {e}")))?;

        if !(200..300).contains(&status) {
            let snippet: String = text.chars().take(200).collect();
            return Err(RpcError::Transport(format!("HTTP {status}: {snippet}")));
        }
        Ok(text)
    }
}
