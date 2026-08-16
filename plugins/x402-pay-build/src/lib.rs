//! `x402-pay-build` -- decide whether an x402 402-Payment-Required challenge describes a payment
//! the operator authorised, and if so hand it to the plugin that builds delegated spends.
//!
//! Custody tier T1. Secrets held: none. It holds no wallet, touches no private key, and BUILDS NO
//! TRANSACTION: its output is the argument object for `allowance-spend-build`, which already reads
//! the delegation, fails closed unless the agent is the delegatee, derives the token accounts, and
//! emits the unsigned transaction. Two components each doing one job. The spend is bounded again by
//! the audited on-chain program (`De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44`), which returns
//! `0x12c` over cap. The agent proposes; an audited on-chain allowance disposes.
//!
//! WHAT THIS PLUGIN EXISTS TO GET RIGHT, and it is not the amount. The delegation's cap bounds
//! AMOUNT and not PAYEE, and a 402 challenge is content written by the party being paid. So the
//! payee, the mint, the network and the funding delegation come from the jailed operator config
//! and are cross-checked against the challenge; a mismatch fails closed. See [`pay`], and
//! [`compose`] for why the transaction belongs to the other plugin.
//!
//! STATE, stated rather than implied: [`pay`] and [`compose`] are complete and host-tested; the
//! wasm component shim is not written yet. The crate is compiled and tested in CI as a library so
//! it cannot rot unbuilt, and it joins the plugin matrix when the component lands.
//!
//! The host-side control that runs before any signature is `scripts/pay_x402_certified.py`, which
//! re-derives intent from the serialized bytes rather than trusting this crate, the model, or the
//! wire.
//!
//! Build:  rustup target add wasm32-wasip2
//!         cargo build --target wasm32-wasip2 --release
#![deny(unsafe_code)]

pub mod compose;
pub mod pay;

pub use compose::{atomic_to_ui, compose, SpendArgs};
pub use pay::{authorise, AuthorisedPayment, Challenge, PayConfig, PriceExtra, PriceOption};
