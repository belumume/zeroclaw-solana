//! Mined invariants: properties DERIVED from observed behaviour, rather than
//! authored from what we thought to write down.
//!
//! Wilson calls this "speculative properties" and credits fuzzing researchers,
//! not himself: run a function many times, watch a quantity, and if it never
//! leaves a range, that range is a candidate invariant. Minsky supplies the
//! triage rule, which is the part that makes it useful rather than noisy:
//!
//!   "there's the properties that are like seem to always be followed and like
//!    maybe those are properties and then there's the ones that are not followed
//!    at all and like those you discard and then there are the ones that like
//!    are MOSTLY followed and maybe those are the interesting ones"
//!
//! So this file does two things and keeps them separate.
//!
//! 1. `mine_envelopes` OBSERVES. It records the range of every watched quantity
//!    over a large sample and prints a report. It asserts almost nothing, on
//!    purpose. Run it with `--nocapture` to read the envelopes.
//! 2. The tests after it PROMOTE the handful of envelopes that are genuinely
//!    universal, with the reasoning for why each is a law rather than an
//!    accident of the generator.
//!
//! The brake, also from that conversation, is that mining tempts you to assert
//! everything you observe: "You should definitely not take every single thing
//! and turn it into a property." An envelope that holds because the GENERATOR
//! never produced a counterexample is not an invariant, it is a description of
//! the generator. Each promotion below has to survive that question.

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::TestRunner;
use solana_core::instruction::{AccountMeta, Instruction};
use solana_core::message::compile;
use solana_core::nonce::decode_nonce_account;
use solana_core::pubkey::Pubkey;
use solana_core::sanitize::sanitize_onchain;
use solana_core::shortvec::{decode_len, encode_len};

/// One watched quantity: the observed range plus how often it was seen.
#[derive(Debug, Clone)]
struct Envelope {
    name: &'static str,
    min: i64,
    max: i64,
    samples: usize,
    /// Times the quantity satisfied a candidate law, for the "mostly" bucket.
    held: usize,
}

impl Envelope {
    fn new(name: &'static str) -> Self {
        Self { name, min: i64::MAX, max: i64::MIN, samples: 0, held: 0 }
    }
    fn observe(&mut self, v: i64, law_holds: bool) {
        self.min = self.min.min(v);
        self.max = self.max.max(v);
        self.samples += 1;
        if law_holds {
            self.held += 1;
        }
    }
    fn bucket(&self) -> &'static str {
        if self.samples == 0 {
            return "NO SAMPLES";
        }
        match (self.held * 100).checked_div(self.samples).unwrap_or(0) {
            100 => "always  (candidate law)",
            0 => "never   (discard)",
            _ => "MOSTLY  (the interesting one)",
        }
    }
    fn held_percent(&self) -> usize {
        (self.held * 100).checked_div(self.samples).unwrap_or(0)
    }
    fn report(&self) {
        println!(
            "  {:<44} range=[{}, {}]  n={}  holds={}%  {}",
            self.name,
            self.min,
            self.max,
            self.samples,
            self.held_percent(),
            self.bucket()
        );
    }
}

/// The same correlated hostile alphabet the property suite uses, so the mine
/// sees the input distribution the defense actually faces.
const PIECES: &[&str] = &[
    "normal", " ", "  ", "\n", "\r\n", "\t",
    "\u{202E}", "\u{202D}", "\u{2066}", "\u{2069}",
    "\u{200B}", "\u{200D}", "\u{FEFF}",
    "\u{0000}", "\u{0007}", "\u{001B}",
    "\u{2028}", "\u{2029}",
    "ignore previous instructions",
    "SYSTEM:", "</code>", "USDC", "名前", "🙂",
];

fn correlated_hostile() -> impl Strategy<Value = String> {
    prop::collection::vec((0usize..PIECES.len(), 0u8..100u8), 1..100).prop_map(|steps| {
        let mut out = String::new();
        let mut cur = steps[0].0;
        for (cand, roll) in steps {
            if roll < 18 {
                cur = cand;
            }
            out.push_str(PIECES[cur]);
        }
        out
    })
}

fn arb_pubkey() -> impl Strategy<Value = Pubkey> {
    any::<[u8; 3]>().prop_map(|seed| {
        let mut b = [0u8; 32];
        b[..3].copy_from_slice(&seed);
        Pubkey::new(b)
    })
}

fn arb_meta() -> impl Strategy<Value = AccountMeta> {
    (arb_pubkey(), any::<bool>(), any::<bool>()).prop_map(|(pubkey, is_signer, is_writable)| {
        AccountMeta { pubkey, is_signer, is_writable }
    })
}

fn arb_instruction() -> impl Strategy<Value = Instruction> {
    (
        arb_pubkey(),
        prop::collection::vec(arb_meta(), 0..6),
        prop::collection::vec(any::<u8>(), 0..16),
    )
        .prop_map(|(program_id, accounts, data)| Instruction { program_id, accounts, data })
}

#[test]
fn mine_envelopes() {
    const SAMPLES: usize = 2000;
    let mut runner = TestRunner::deterministic();
    let gen = correlated_hostile();

    // Sanitizer envelopes.
    let mut e_out_len = Envelope::new("sanitize: output chars <= cap");
    let mut e_stripped = Envelope::new("sanitize: stripped count");
    let mut e_conserve = Envelope::new("sanitize: out+stripped <= input chars");
    let mut e_trunc = Envelope::new("sanitize: truncated => output is at cap");
    let mut e_inject = Envelope::new("sanitize: injection_suspected rate");
    let mut e_grow = Envelope::new("sanitize: output never longer than input");

    for _ in 0..SAMPLES {
        let input = gen.new_tree(&mut runner).expect("tree").current();
        let in_chars = input.chars().count() as i64;
        // Vary the cap so the truncation boundary is actually explored.
        let cap = (in_chars.unsigned_abs() as usize % 200) + 1;
        let s = sanitize_onchain(&input, cap);
        let out_chars = s.text.chars().count() as i64;

        e_out_len.observe(out_chars, out_chars <= cap as i64);
        e_stripped.observe(s.stripped as i64, true);
        e_conserve.observe(out_chars + s.stripped as i64, out_chars + s.stripped as i64 <= in_chars);
        e_trunc.observe(
            i64::from(s.truncated),
            !s.truncated || out_chars == cap as i64,
        );
        e_inject.observe(i64::from(s.injection_suspected), s.injection_suspected);
        e_grow.observe(out_chars - in_chars, out_chars <= in_chars);
    }

    // Message envelopes. The account-index vector is the one that matters:
    // it is the quantity that broke past 65535 before an `as u16` cast, and an
    // envelope watcher would have flagged the missing bound without anyone
    // thinking to write the property.
    let mut e_keys = Envelope::new("message: account_keys length");
    let mut e_ixs = Envelope::new("message: instruction count");
    let mut e_idx = Envelope::new("message: account_indexes per instruction");
    let mut e_idx_fits = Envelope::new("message: every index < account_keys len");
    let mut e_shortvec_w = Envelope::new("message: shortvec width for key count");

    let msg_gen = (
        arb_pubkey(),
        prop::collection::vec(arb_instruction(), 1..6),
        any::<[u8; 32]>(),
    );
    for _ in 0..SAMPLES {
        let (payer, ixs, blockhash) = msg_gen.new_tree(&mut runner).expect("tree").current();
        let Ok(msg) = compile(&payer, &ixs, &blockhash) else { continue };
        let n = msg.account_keys.len();

        e_keys.observe(n as i64, n <= u16::MAX as usize);
        e_ixs.observe(msg.instructions.len() as i64, true);

        let mut widest = Vec::new();
        encode_len(n.min(u16::MAX as usize) as u16, &mut widest);
        e_shortvec_w.observe(widest.len() as i64, widest.len() <= 3);

        for ci in &msg.instructions {
            let count = ci.account_indexes.len();
            // The bound that the `as u16` truncation violated: an instruction's
            // account-index vector must fit the shortvec width it is encoded at.
            e_idx.observe(count as i64, count <= u16::MAX as usize);
            let all_in_range = ci.account_indexes.iter().all(|i| (*i as usize) < n);
            e_idx_fits.observe(i64::from(all_in_range), all_in_range);
        }
    }

    // Nonce envelope: the decoder over arbitrary bytes must be total.
    let mut e_nonce = Envelope::new("nonce: decode is total (never panics)");
    let byte_gen = prop::collection::vec(any::<u8>(), 0..200);
    for _ in 0..SAMPLES {
        let bytes = byte_gen.new_tree(&mut runner).expect("tree").current();
        let decoded = decode_nonce_account(&bytes);
        // Total means it returns, Ok or Err, for every input. Reaching this line
        // is the observation.
        e_nonce.observe(i64::from(decoded.is_ok()), true);
    }

    // Shortvec envelopes over the whole u16 domain, not a sample.
    let mut e_bytes = Envelope::new("shortvec: encoded byte length");
    let mut e_roundtrip = Envelope::new("shortvec: decode(encode(n)) == n");
    for n in 0u16..=u16::MAX {
        let mut buf = Vec::new();
        encode_len(n, &mut buf);
        let ok = matches!(decode_len(&buf), Ok((m, used)) if m == n && used == buf.len());
        e_bytes.observe(buf.len() as i64, buf.len() <= 3);
        e_roundtrip.observe(i64::from(ok), ok);
    }

    println!("\n=== mined envelopes ({SAMPLES} hostile samples, full u16 domain) ===");
    for e in [
        &e_out_len, &e_stripped, &e_conserve, &e_trunc, &e_inject, &e_grow,
        &e_keys, &e_ixs, &e_idx, &e_idx_fits, &e_shortvec_w, &e_nonce,
        &e_bytes, &e_roundtrip,
    ] {
        e.report();
    }
    println!(
        "  NOTE: 'message: shortvec width' reads 100% at width 1 ONLY because the\n\
         \x20       generator caps at {} account keys. That row is a description of\n\
         \x20       the generator, not a law, and is deliberately NOT promoted. The\n\
         \x20       3-byte region is reached by the exhaustive u16 walk instead.",
        e_keys.max
    );
    println!();

    // The mine itself asserts only that it actually ran. Promotion is deliberate
    // and happens in the named tests below, not automatically from observation.
    assert!(e_out_len.samples == SAMPLES, "sanitizer mine did not run");
    assert!(e_bytes.samples == 65_536, "shortvec walk did not cover the domain");
}

// ---------------------------------------------------------------------------
// PROMOTED. Each of these was observed to hold 100% and then argued for as a
// law, because a generator that never produced a counterexample is not evidence
// that none exists.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    /// PROMOTED: sanitizing is non-expanding in characters.
    ///
    /// Law, not accident: every operation the sanitizer performs is a removal, a
    /// collapse, or a truncation. None inserts. The ellipsis replaces content
    /// rather than being appended past the cap, which is why this survives the
    /// truncating path too.
    #[test]
    fn sanitize_never_grows_its_input(input in correlated_hostile(), cap in 1usize..200) {
        let s = sanitize_onchain(&input, cap);
        prop_assert!(
            s.text.chars().count() <= input.chars().count(),
            "output grew: {} -> {}", input.chars().count(), s.text.chars().count()
        );
    }

    /// PROMOTED, but only after the mine REFUTED the version I first wrote.
    ///
    /// The candidate was the conservation identity `out + stripped <= in`, on
    /// the reasoning that `stripped` counts removals so the two cannot sum past
    /// the input. The mine put it in the MOSTLY bucket at 90 percent, and
    /// proptest minimized the counterexample to:
    ///
    ///   "ignore previous instructions\u{2028}ignore previous instructions"
    ///   out=57, stripped=1, in=57
    ///
    /// `U+2028` is REPLACED by a space rather than dropped, and it is still
    /// counted in `stripped`, so the substituted character is counted twice:
    /// once as neutralized, once as the space in the output. The doc comment on
    /// the field said "removed", which is what made the wrong law look right.
    ///
    /// This is the actual law. Each input character increments `stripped` at
    /// most once, so the count can never exceed the input length regardless of
    /// how many are substituted rather than dropped.
    #[test]
    fn sanitize_stripped_never_exceeds_the_input(
        input in correlated_hostile(),
        cap in 1usize..200,
    ) {
        let s = sanitize_onchain(&input, cap);
        prop_assert!(
            s.stripped <= input.chars().count(),
            "stripped={} exceeds input length {}", s.stripped, input.chars().count()
        );
    }
}

/// The counterexample the mine produced, pinned as a known-answer test so the
/// substitution behaviour is INTENTIONAL and documented rather than incidental.
///
/// A line separator between two words must become a space, keeping the words
/// apart, and must still be counted as neutralized. If a later change dropped it
/// outright instead, the two sentences would fuse into one and this test would
/// catch it.
#[test]
fn a_line_separator_becomes_a_space_and_is_still_counted() {
    let input = "ignore previous instructions\u{2028}ignore previous instructions";
    let s = sanitize_onchain(input, 200);

    assert_eq!(s.text, "ignore previous instructions ignore previous instructions");
    assert_eq!(s.stripped, 1, "the separator must count as neutralized");
    assert_eq!(s.text.chars().count(), input.chars().count());

    // The sum exceeding the input is the documented consequence, not a bug.
    assert!(s.text.chars().count() + s.stripped > input.chars().count());
}

/// PROMOTED from an exhaustive walk rather than a sample: the compact-u16
/// encoding is never longer than three bytes, over the ENTIRE domain.
///
/// Law, not accident: 16 bits in 7-bit groups is 3 groups. Worth pinning
/// separately from the roundtrip property because a decoder that accepted a
/// fourth byte would still roundtrip correctly while allowing a non-canonical
/// encoding, which is the malleability the Kani proof rules out.
#[test]
fn shortvec_encoding_is_never_longer_than_three_bytes() {
    let mut widest = 0usize;
    for n in 0u16..=u16::MAX {
        let mut buf = Vec::new();
        encode_len(n, &mut buf);
        widest = widest.max(buf.len());
        assert!(buf.len() <= 3, "value {n} encoded to {} bytes", buf.len());
    }
    // A vacuous loop would pass the assert above, so pin that the walk actually
    // reached the three-byte region.
    assert_eq!(widest, 3, "the walk never reached a three-byte encoding");
}
