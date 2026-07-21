//! consumer_example: a downstream program that CONSUMES a zeroclaw_oracle
//! `DeviceFeed` on-chain. Its existence is the answer to "is this a real oracle
//! or a glorified memo?": a reading is only useful if another program can read
//! it, trust its provenance, check its freshness, and act. This does exactly
//! that -- it reads the feed (owner-checked to the oracle program via the typed
//! `Account<DeviceFeed>`), requires the reading be FRESH, and gates an action on
//! its value. A real integrator swaps the emitted event for a payment, an alert,
//! a valve, a rebalance, etc.

use anchor_lang::prelude::*;
use zeroclaw_oracle::DeviceFeed;

// Machine-readable security contact, embedded in the deployed binary and shown
// on explorers (neodyme security.txt standard).
#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "ZeroClaw Oracle Consumer Example",
    project_url: "https://github.com/zeroclaw-labs/zeroclaw-plugins",
    contacts: "link:https://github.com/belumume",
    policy: "Report vulnerabilities privately via the contact link; do not exploit deployments. Best-effort response.",
    preferred_languages: "en",
    source_code: "https://github.com/zeroclaw-labs/zeroclaw-plugins"
}

declare_id!("B2scuv95pA7yA3Kj36wmfoSVZ94WZfUmtwsfr9Kw39Pt");

#[program]
pub mod consumer_example {
    use super::*;

    /// Read a device-oracle feed and act if it is fresh and crosses a threshold.
    /// `max_age_secs` is the freshness window; a reading older than that (or one
    /// that was never published) is refused, so a consumer cannot act on stale
    /// device data.
    pub fn act_on_feed(ctx: Context<ActOnFeed>, threshold: i64, max_age_secs: i64) -> Result<()> {
        let feed = &ctx.accounts.feed;
        let now = Clock::get()?.unix_timestamp;
        require!(feed.published_at > 0, ConsumerError::StaleFeed);
        require!(
            now.saturating_sub(feed.published_at) <= max_age_secs,
            ConsumerError::StaleFeed
        );

        let crossed = feed.value >= threshold;
        emit!(ActionTaken {
            device: feed.device,
            feed_kind: feed.feed_kind,
            value: feed.value,
            scale: feed.scale,
            threshold,
            crossed,
        });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ActOnFeed<'info> {
    /// The device-oracle feed. `Account<DeviceFeed>` enforces the account is
    /// owned by the zeroclaw_oracle program and carries its discriminator, so a
    /// spoofed look-alike account is rejected.
    pub feed: Account<'info, DeviceFeed>,
}

#[event]
pub struct ActionTaken {
    pub device: Pubkey,
    pub feed_kind: u8,
    pub value: i64,
    pub scale: i8,
    pub threshold: i64,
    pub crossed: bool,
}

#[error_code]
pub enum ConsumerError {
    #[msg("feed reading is stale (older than the allowed max age) or was never published")]
    StaleFeed,
}
