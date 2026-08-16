//! `x402-pay-build` -- turn an x402 402-Payment-Required challenge into an UNSIGNED transaction
//! that pays it under a Solana Foundation Subscriptions & Allowances delegation.
//!
//! Custody tier T1. Secrets held: none. The plugin holds no wallet and touches no private key; it
//! returns a base64 UNSIGNED transaction with every signature slot empty plus a human-readable
//! summary, so its output alone can never be submitted. The spend is bounded a second time by the
//! audited on-chain program (`De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44`), which returns
//! `0x12c` over cap. The agent proposes; an audited on-chain allowance disposes.
//!
//! WHAT THIS PLUGIN EXISTS TO GET RIGHT, and it is not the amount. The delegation's cap bounds
//! AMOUNT and not PAYEE, and a 402 challenge is content written by the party being paid. So the
//! payee, the mint, the network and the funding delegation come from the jailed operator config
//! and are cross-checked against the challenge; a mismatch fails closed. See [`pay`].
//!
//! STATE, stated rather than implied: [`pay`] is complete and host-tested, and the transaction
//! BUILDER and the wasm component are not written yet. The crate is compiled and tested in CI as a
//! library so it cannot rot unbuilt, and it joins the plugin matrix when the component lands.
//!
//! The host-side control that runs before any signature is `scripts/pay_x402_certified.py`, which
//! re-derives intent from the serialized bytes rather than trusting this crate, the model, or the
//! wire.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod pay;

pub use pay::{authorise, AuthorisedPayment, Challenge, PayConfig, PriceExtra, PriceOption};
