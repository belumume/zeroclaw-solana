//! zeroclaw_oracle: a device-oracle feed for self-hosted ZeroClaw agents.
//!
//! A physical DePIN device (temperature, energy, CO2, motion, ...) publishes a
//! DEVICE-SIGNED reading into a typed, program-owned `DeviceFeed` PDA that a
//! downstream program can CPI-read like a Pyth/Switchboard feed. This is the
//! consumable counterpart to depin-attest (which writes a bare memo): here the
//! reading has on-chain, verifiable provenance and freshness.
//!
//! # Two independent replay proofs
//! 1. The publishing transaction is fronted by a durable nonce, so a replayed
//!    TRANSACTION is rejected by the chain (consensus-level).
//! 2. `publish_reading` requires `sequence` to strictly increase, so a stale or
//!    re-submitted reading is rejected by THIS PROGRAM even under a fresh nonce.
//!
//! # Provenance
//! Only the registered device key may write to its feed: the device must sign
//! (`Signer`) and must equal the `device` recorded at registration. The agent's
//! capped session key (the fee payer) can pay for the transaction but can never
//! forge the reading — it is not the device.

use anchor_lang::prelude::*;

// Machine-readable security contact, embedded in the deployed binary and shown
// on explorers (neodyme security.txt standard). Gated on no-entrypoint so a CPI
// consumer linking this crate does not get a duplicate symbol.
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "ZeroClaw Device Oracle",
    project_url: "https://github.com/zeroclaw-labs/zeroclaw-plugins",
    contacts: "link:https://github.com/belumume",
    policy: "Report vulnerabilities privately via the contact link; do not exploit deployments. Best-effort response.",
    preferred_languages: "en",
    source_code: "https://github.com/zeroclaw-labs/zeroclaw-plugins"
}

declare_id!("EFCRmE5wFLoo5zJ4cu4J6rbQjmkiok8FmDekTGGXrCKn");

#[program]
pub mod zeroclaw_oracle {
    use super::*;

    /// One-time: bind a device key to its feed PDA. Admin-only (the `authority`
    /// signs and pays). The device does not sign registration; only its key
    /// seeds the PDA and is recorded as the sole future publisher.
    pub fn register_device(ctx: Context<RegisterDevice>, feed_kind: u8) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        feed.authority = ctx.accounts.authority.key();
        feed.device = ctx.accounts.device.key();
        feed.feed_kind = feed_kind;
        feed.value = 0;
        feed.scale = 0;
        feed.unit = [0u8; 12];
        feed.sequence = 0;
        feed.observed_at = 0;
        feed.published_at = 0;
        feed.bump = ctx.bumps.feed;
        Ok(())
    }

    /// Publish a device-signed reading. Enforced on-chain:
    /// - the `device` account must sign (`Signer`) and equal `feed.device`;
    /// - `sequence` must strictly exceed the stored sequence (stale/replay reject);
    /// - `feed_kind` must match the registered kind (no temperature-as-energy);
    /// - `scale` must be in `-9..=0` (matches the plugin's fixed-point range).
    #[allow(clippy::too_many_arguments)]
    pub fn publish_reading(
        ctx: Context<PublishReading>,
        value: i64,
        scale: i8,
        unit: [u8; 12],
        sequence: u64,
        observed_at: i64,
        feed_kind: u8,
    ) -> Result<()> {
        let feed = &mut ctx.accounts.feed;
        require_keys_eq!(
            feed.device,
            ctx.accounts.device.key(),
            OracleError::WrongDevice
        );
        require!(sequence > feed.sequence, OracleError::StaleSequence);
        require!(feed_kind == feed.feed_kind, OracleError::FeedKindMismatch);
        require!((-9..=0).contains(&scale), OracleError::BadScale);

        feed.value = value;
        feed.scale = scale;
        feed.unit = unit;
        feed.sequence = sequence;
        feed.observed_at = observed_at;
        feed.published_at = Clock::get()?.unix_timestamp;

        emit!(ReadingPublished {
            device: feed.device,
            feed_kind,
            value,
            scale,
            sequence,
            published_at: feed.published_at,
        });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct RegisterDevice<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + DeviceFeed::LEN,
        seeds = [b"feed", device.key().as_ref()],
        bump
    )]
    pub feed: Account<'info, DeviceFeed>,
    /// CHECK: only the pubkey is used, as a PDA seed and the recorded publisher.
    pub device: UncheckedAccount<'info>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct PublishReading<'info> {
    #[account(
        mut,
        seeds = [b"feed", device.key().as_ref()],
        bump = feed.bump
    )]
    pub feed: Account<'info, DeviceFeed>,
    pub device: Signer<'info>,
}

#[account]
pub struct DeviceFeed {
    pub authority: Pubkey,
    pub device: Pubkey,
    pub feed_kind: u8,
    pub value: i64,
    pub scale: i8,
    pub unit: [u8; 12],
    pub sequence: u64,
    pub observed_at: i64,
    pub published_at: i64,
    pub bump: u8,
}

impl DeviceFeed {
    // authority + device + feed_kind + value + scale + unit + sequence
    // + observed_at + published_at + bump
    pub const LEN: usize = 32 + 32 + 1 + 8 + 1 + 12 + 8 + 8 + 8 + 1;
}

#[event]
pub struct ReadingPublished {
    pub device: Pubkey,
    pub feed_kind: u8,
    pub value: i64,
    pub scale: i8,
    pub sequence: u64,
    pub published_at: i64,
}

#[error_code]
pub enum OracleError {
    #[msg("device signer does not match the registered feed device")]
    WrongDevice,
    #[msg("sequence must be strictly greater than the stored sequence (stale or replayed reading)")]
    StaleSequence,
    #[msg("feed_kind does not match the registered feed kind")]
    FeedKindMismatch,
    #[msg("scale must be in -9..=0")]
    BadScale,
}
