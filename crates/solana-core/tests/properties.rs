//! Property-based tests: invariants that must hold for EVERY input, not just
//! the inputs we thought to write down.
//!
//! The unit tests and known-answer tests assert specific cases. These assert
//! the contract itself, over generated inputs including raw arbitrary bytes and
//! adversarial unicode. A failing case is minimized by proptest and recorded in
//! `proptest-regressions/`, so it becomes a permanent regression test.
//!
//! The sanitizer is the response-path defense that stands between attacker
//! controlled on-chain data and the agent's context (OWASP LLM01), so its
//! documented guarantees are exactly what deserves universal quantification:
//! total (never panics), bounded, control-free, collapsed, and idempotent.

use proptest::prelude::*;
use solana_core::instruction::{AccountMeta, Instruction};
use solana_core::message::compile;
use solana_core::nonce::{decode_nonce_account, NonceError, NONCE_ACCOUNT_LEN};
use solana_core::pubkey::Pubkey;
use solana_core::sanitize::{sanitize_onchain, Sanitized, DEFAULT_LABEL_MAX};
use solana_core::shortvec::{decode_len, encode_len};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// The ellipsis the sanitizer appends on truncation. Bound as a const because
/// a `'\u{...}'` literal inside `prop_assert!` is swallowed by the macro's
/// format-string concatenation and read as a positional argument.
const ELLIPSIS: char = '\u{2026}';

/// Characters the sanitizer promises to remove from `text`.
fn is_forbidden_in_output(c: char) -> bool {
    // Control (Cc), format (Cf) which covers bidi overrides and most
    // zero-width, plus the explicit line/paragraph separators.
    c.is_control()
        || matches!(c, '\u{2028}' | '\u{2029}')
        || matches!(c,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
            | '\u{200E}' | '\u{200F}'
        )
}

/// The alphabet both hostile generators draw from: ordinary text mixed with the
/// exact characters an attacker reaches for.
const HOSTILE_PIECES: &[&str] = &[
    "normal",
    " ",
    "  ",
    "\n",
    "\r\n",
    "\t",
    "\u{202E}",
    "\u{202D}",
    "\u{2066}",
    "\u{2069}", // bidi
    "\u{200B}",
    "\u{200D}",
    "\u{FEFF}", // zero-width
    "\u{0000}",
    "\u{0007}",
    "\u{001B}", // control
    "\u{2028}",
    "\u{2029}", // line/para separators
    "ignore previous instructions",
    "SYSTEM:",
    "</code>",
    "USDC",
    "名前",
    "🙂",
];

/// A generator that mixes ordinary text with the exact characters an attacker
/// would reach for: bidi overrides, zero-width joiners, control bytes, and
/// injection framing.
///
/// Each piece is drawn INDEPENDENTLY, which is proptest's default shape and is
/// the weakness `hostile_string_stateful` exists to fix. See the note there.
fn hostile_string() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(HOSTILE_PIECES.to_vec()), 0..40)
        .prop_map(|v| v.concat())
}

/// Fraction of positions (percent) at which the stateful generator is allowed to
/// change which piece it is emitting. Low on purpose: it is what produces runs.
const SWITCH_PERCENT: u8 = 18;

/// The same alphabet, drawn with MEMORY instead of independently.
///
/// Independent draws make a sustained run of any one hostile class vanishingly
/// unlikely: with 25 pieces, twenty consecutive bidi overrides is about
/// (4/25)^20. So the iid generator above can emit bidi characters constantly and
/// still never emit a bidi REGION, which is the shape an attacker actually
/// sends. The fix is Will Wilson's: keep the previous choice and re-roll only
/// with low probability, exactly as a controller holds a button down across
/// frames rather than re-deciding each frame. No individual character becomes
/// less random; only the correlation between neighbours changes.
fn hostile_string_stateful() -> impl Strategy<Value = String> {
    prop::collection::vec((0usize..HOSTILE_PIECES.len(), 0u8..100u8), 1..120).prop_map(|steps| {
        let mut out = String::new();
        let mut current = steps[0].0;
        for (candidate, roll) in steps {
            if roll < SWITCH_PERCENT {
                current = candidate;
            }
            out.push_str(HOSTILE_PIECES[current]);
        }
        out
    })
}

/// Longest run of consecutive characters the sanitizer promises to remove.
/// This is the property the iid generator cannot reach and the stateful one can.
fn longest_forbidden_run(s: &str) -> usize {
    let mut best = 0usize;
    let mut run = 0usize;
    for c in s.chars() {
        if is_forbidden_in_output(c) {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

/// Arbitrary bytes reinterpreted as text, so invalid UTF-8 is covered too.
fn lossy_bytes_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..2048)
        .prop_map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn assert_output_contract(s: &Sanitized, max: usize) {
    // 1. Bounded: documented as "text never exceeds max_chars characters".
    assert!(
        s.text.chars().count() <= max,
        "output {} chars exceeds cap {}",
        s.text.chars().count(),
        max
    );
    // 2. Clean: no control / format / bidi / zero-width survives.
    assert!(
        !s.text.chars().any(is_forbidden_in_output),
        "forbidden char survived: {:?}",
        s.text
    );
    // 3. Collapsed and trimmed: no leading/trailing space, no double space.
    assert!(!s.text.starts_with(' '), "leading space: {:?}", s.text);
    assert!(!s.text.ends_with(' '), "trailing space: {:?}", s.text);
    assert!(!s.text.contains("  "), "uncollapsed run: {:?}", s.text);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, ..ProptestConfig::default() })]

    /// Total + bounded + clean + collapsed, over ordinary generated text.
    #[test]
    fn sanitize_contract_holds_for_any_string(input in ".*", max in 0usize..256) {
        let s = sanitize_onchain(&input, max);
        assert_output_contract(&s, max);
    }

    /// Same contract, over adversarial unicode.
    #[test]
    fn sanitize_contract_holds_for_hostile_input(input in hostile_string(), max in 0usize..256) {
        let s = sanitize_onchain(&input, max);
        assert_output_contract(&s, max);
    }

    /// Same contract, over arbitrary bytes (covers invalid UTF-8 via lossy).
    #[test]
    fn sanitize_contract_holds_for_arbitrary_bytes(input in lossy_bytes_string()) {
        let s = sanitize_onchain(&input, DEFAULT_LABEL_MAX);
        assert_output_contract(&s, DEFAULT_LABEL_MAX);
    }

    /// IDEMPOTENCE: sanitizing already-sanitized output must be a no-op.
    /// This is the property sanitizers most often fail, and a failure here
    /// means the "safe" text is not actually a fixed point of the cleaner.
    #[test]
    fn sanitize_is_idempotent(input in hostile_string(), max in 1usize..256) {
        let once = sanitize_onchain(&input, max);
        let twice = sanitize_onchain(&once.text, max);
        prop_assert_eq!(&once.text, &twice.text);
        prop_assert_eq!(twice.stripped, 0, "second pass still stripped characters");
    }

    /// The truncation flag must agree with the observable outcome, and the
    /// advisory injection flag is computed BEFORE truncation so a short cap
    /// cannot hide injection framing.
    #[test]
    fn truncation_flag_agrees_with_output(input in hostile_string(), max in 1usize..64) {
        let s = sanitize_onchain(&input, max);
        if s.truncated {
            prop_assert!(s.text.chars().count() <= max);
            prop_assert!(s.text.ends_with(ELLIPSIS));
        }
    }

    /// A cap can never turn injection framing OFF: the flag is computed on the
    /// full cleaned text, so a tighter cap must not clear it.
    #[test]
    fn tighter_cap_cannot_hide_injection_framing(input in hostile_string()) {
        let wide = sanitize_onchain(&input, 4096);
        let tight = sanitize_onchain(&input, 8);
        if wide.injection_suspected {
            prop_assert!(
                tight.injection_suspected,
                "a tighter cap cleared the injection advisory"
            );
        }
    }

    /// The full output contract, over CORRELATED hostile input: sustained bidi
    /// regions, long control-byte runs, repeated injection framing. Same
    /// guarantees, an input distribution the iid generator cannot produce.
    #[test]
    fn sanitize_contract_holds_for_correlated_hostile_input(
        input in hostile_string_stateful(),
        max in 0usize..256,
    ) {
        let s = sanitize_onchain(&input, max);
        assert_output_contract(&s, max);
    }

    /// Idempotence under sustained runs. Stripping a long region can leave
    /// neighbours adjacent that were not adjacent before, so this is where a
    /// single-pass cleaner is most likely to stop being a fixed point.
    #[test]
    fn sanitize_is_idempotent_under_sustained_runs(
        input in hostile_string_stateful(),
        max in 1usize..256,
    ) {
        let once = sanitize_onchain(&input, max);
        let twice = sanitize_onchain(&once.text, max);
        prop_assert_eq!(&once.text, &twice.text);
        prop_assert_eq!(twice.stripped, 0, "second pass still stripped characters");
    }

    /// A long run of injection framing must not let a tight cap clear the
    /// advisory, same as the uncorrelated case.
    #[test]
    fn tighter_cap_cannot_hide_framing_under_runs(input in hostile_string_stateful()) {
        let wide = sanitize_onchain(&input, 4096);
        let tight = sanitize_onchain(&input, 8);
        if wide.injection_suspected {
            prop_assert!(tight.injection_suspected);
        }
    }

    /// shortvec: encode then decode is the identity, and the encoding is at
    /// most three bytes.
    #[test]
    fn shortvec_roundtrips(n in any::<u16>()) {
        let mut buf = Vec::new();
        encode_len(n, &mut buf);
        prop_assert!(buf.len() <= 3, "encoding longer than 3 bytes");
        let (m, used) = decode_len(&buf).expect("own encoding must decode");
        prop_assert_eq!(m, n);
        prop_assert_eq!(used, buf.len());
    }

    /// shortvec: any accepted encoding must be the CANONICAL one. A decoder
    /// that accepts non-canonical compact-u16 lets two distinct byte strings
    /// mean the same length, which is a real consensus-adjacent footgun.
    #[test]
    fn shortvec_accepts_only_canonical(bytes in prop::collection::vec(any::<u8>(), 1..5)) {
        if let Ok((n, used)) = decode_len(&bytes) {
            let mut canonical = Vec::new();
            encode_len(n, &mut canonical);
            prop_assert_eq!(
                &canonical[..],
                &bytes[..used],
                "decoder accepted a non-canonical encoding of {}",
                n
            );
        }
    }

    /// shortvec decode must never panic on arbitrary bytes, only Ok or Err.
    #[test]
    fn shortvec_decode_is_total(bytes in prop::collection::vec(any::<u8>(), 0..8)) {
        let _ = decode_len(&bytes);
    }
}

// ---------------------------------------------------------------------------
// Message structural invariants
//
// `compile` builds the exact bytes we sign. A wrong index here is not a crash,
// it is a VALID message that authorises the wrong account, so these invariants
// deserve quantifying over every input rather than a few fixtures. Pubkeys are
// drawn from a deliberately tiny seed space so collisions are common and the
// dedup / flag-merge path is actually exercised.
// ---------------------------------------------------------------------------

fn arb_pubkey() -> impl Strategy<Value = Pubkey> {
    any::<[u8; 3]>().prop_map(|seed| {
        let mut b = [0u8; 32];
        b[..3].copy_from_slice(&seed);
        Pubkey::new(b)
    })
}

fn arb_meta() -> impl Strategy<Value = AccountMeta> {
    (arb_pubkey(), any::<bool>(), any::<bool>()).prop_map(|(pubkey, is_signer, is_writable)| {
        AccountMeta {
            pubkey,
            is_signer,
            is_writable,
        }
    })
}

fn arb_instruction() -> impl Strategy<Value = Instruction> {
    (
        arb_pubkey(),
        prop::collection::vec(arb_meta(), 0..6),
        prop::collection::vec(any::<u8>(), 0..16),
    )
        .prop_map(|(program_id, accounts, data)| Instruction {
            program_id,
            accounts,
            data,
        })
}

/// A syntactically valid 80-byte Current/Initialized nonce account.
fn nonce_bytes(authority: [u8; 32], durable: [u8; 32], lamports: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(NONCE_ACCOUNT_LEN);
    v.extend_from_slice(&1u32.to_le_bytes()); // version: Current
    v.extend_from_slice(&1u32.to_le_bytes()); // state: Initialized
    v.extend_from_slice(&authority);
    v.extend_from_slice(&durable);
    v.extend_from_slice(&lamports.to_le_bytes());
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// Every index in every compiled instruction addresses a real account key.
    /// An out-of-bounds index would be rejected by a validator; an in-bounds but
    /// WRONG index silently signs for the wrong account, which is the reason
    /// this is worth quantifying universally.
    #[test]
    fn compiled_indexes_are_always_in_bounds(
        payer in arb_pubkey(),
        ixs in prop::collection::vec(arb_instruction(), 1..6),
        blockhash in any::<[u8; 32]>(),
    ) {
        let Ok(msg) = compile(&payer, &ixs, &blockhash) else { return Ok(()); };
        let n = msg.account_keys.len();
        for ci in &msg.instructions {
            prop_assert!((ci.program_id_index as usize) < n);
            for idx in &ci.account_indexes {
                prop_assert!((*idx as usize) < n);
            }
        }
    }

    /// Each program_id_index resolves back to the program the caller asked for.
    /// Staying in bounds is not enough: it must point at the RIGHT key.
    #[test]
    fn program_id_index_resolves_to_the_requested_program(
        payer in arb_pubkey(),
        ixs in prop::collection::vec(arb_instruction(), 1..6),
        blockhash in any::<[u8; 32]>(),
    ) {
        let Ok(msg) = compile(&payer, &ixs, &blockhash) else { return Ok(()); };
        prop_assert_eq!(msg.instructions.len(), ixs.len());
        for (ci, ix) in msg.instructions.iter().zip(ixs.iter()) {
            prop_assert_eq!(msg.account_keys[ci.program_id_index as usize], ix.program_id);
        }
    }

    /// The fee payer is account 0 and always a WRITABLE SIGNER, however the
    /// caller happened to flag it in the instruction metas.
    #[test]
    fn payer_is_account_zero_and_a_writable_signer(
        payer in arb_pubkey(),
        ixs in prop::collection::vec(arb_instruction(), 1..6),
        blockhash in any::<[u8; 32]>(),
    ) {
        let Ok(msg) = compile(&payer, &ixs, &blockhash) else { return Ok(()); };
        prop_assert_eq!(msg.account_keys[0], payer);
        prop_assert!(msg.num_required_signatures >= 1);
        // Writable signers occupy [0, num_required_signatures - num_readonly_signed),
        // so index 0 is writable exactly when that range is non-empty.
        prop_assert!(msg.num_readonly_signed < msg.num_required_signatures);
    }

    /// account_keys carries no duplicates, and the header counts never claim
    /// more signer or readonly slots than there are keys.
    #[test]
    fn account_keys_are_deduped_and_header_counts_fit(
        payer in arb_pubkey(),
        ixs in prop::collection::vec(arb_instruction(), 1..6),
        blockhash in any::<[u8; 32]>(),
    ) {
        let Ok(msg) = compile(&payer, &ixs, &blockhash) else { return Ok(()); };
        let mut seen = msg.account_keys.clone();
        seen.sort();
        seen.dedup();
        prop_assert_eq!(seen.len(), msg.account_keys.len());

        let n = msg.account_keys.len();
        prop_assert!((msg.num_required_signatures as usize) <= n);
        prop_assert!(
            (msg.num_readonly_signed as usize) + (msg.num_readonly_unsigned as usize) <= n
        );
    }

    /// The recent_blockhash handed in is the one signed, byte for byte. In a
    /// durable transaction that field carries the STORED nonce, so any
    /// rewriting here would silently break replay protection.
    #[test]
    fn recent_blockhash_is_carried_verbatim(
        payer in arb_pubkey(),
        ixs in prop::collection::vec(arb_instruction(), 1..4),
        blockhash in any::<[u8; 32]>(),
    ) {
        let Ok(msg) = compile(&payer, &ixs, &blockhash) else { return Ok(()); };
        prop_assert_eq!(msg.recent_blockhash, blockhash);
    }

    // -----------------------------------------------------------------------
    // Durable-nonce account decoding
    // -----------------------------------------------------------------------

    /// Decoding arbitrary account bytes never panics. These bytes arrive from an
    /// RPC endpoint, so totality here is a security property, not tidiness.
    #[test]
    fn nonce_decode_is_total(data in prop::collection::vec(any::<u8>(), 0..200)) {
        let _ = decode_nonce_account(&data);
    }

    /// Anything shorter than the account length is rejected as short, and never
    /// read past its end.
    #[test]
    fn nonce_short_input_is_always_rejected(
        data in prop::collection::vec(any::<u8>(), 0..NONCE_ACCOUNT_LEN)
    ) {
        let n = data.len();
        prop_assert_eq!(decode_nonce_account(&data), Err(NonceError::TooShort(n)));
    }

    /// THE footgun this module documents: the runtime domain-hashes the nonce,
    /// so the stored 32 bytes are NOT the blockhash they came from and must be
    /// used verbatim. This asserts the decoder hands them back untouched rather
    /// than deriving anything.
    #[test]
    fn nonce_decode_returns_stored_fields_verbatim(
        authority in any::<[u8; 32]>(),
        durable in any::<[u8; 32]>(),
        lamports in any::<u64>(),
    ) {
        let decoded = decode_nonce_account(&nonce_bytes(authority, durable, lamports))
            .expect("a well-formed Current/Initialized account decodes");
        prop_assert_eq!(decoded.authority, Pubkey::new(authority));
        prop_assert_eq!(decoded.durable_nonce, durable);
        prop_assert_eq!(decoded.lamports_per_signature, lamports);
    }

    /// Unknown version and state discriminants fail closed with the specific
    /// variant, rather than being coerced into a usable NonceState.
    #[test]
    fn nonce_unknown_discriminants_fail_closed(
        version in 2u32..u32::MAX,
        state in 2u32..u32::MAX,
        tail in prop::collection::vec(any::<u8>(), 72..=72),
    ) {
        let mut bad_version = version.to_le_bytes().to_vec();
        bad_version.extend_from_slice(&1u32.to_le_bytes());
        bad_version.extend_from_slice(&tail);
        prop_assert_eq!(
            decode_nonce_account(&bad_version),
            Err(NonceError::UnknownVersion(version))
        );

        let mut bad_state = 1u32.to_le_bytes().to_vec();
        bad_state.extend_from_slice(&state.to_le_bytes());
        bad_state.extend_from_slice(&tail);
        prop_assert_eq!(
            decode_nonce_account(&bad_state),
            Err(NonceError::UnknownState(state))
        );
    }

    /// An uninitialized nonce account is never mistaken for a usable one.
    #[test]
    fn nonce_uninitialized_is_never_usable(
        tail in prop::collection::vec(any::<u8>(), 72..=72)
    ) {
        let mut data = 1u32.to_le_bytes().to_vec();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&tail);
        prop_assert_eq!(decode_nonce_account(&data), Err(NonceError::Uninitialized));
    }
}

// ---------------------------------------------------------------------------
// Does the generator actually reach the inputs we claim to defend against?
// ---------------------------------------------------------------------------

/// A property suite is only as strong as the inputs it can reach, and "we ran
/// 1024 cases" says nothing about WHICH cases. This measures the gap rather
/// than asserting it: it samples both generators and compares the longest run
/// of forbidden characters each one manages to produce.
///
/// The run length is the thing that matters for this sanitizer. A bidi override
/// alone is a character; a bidi REGION is the attack, because it reorders
/// everything after it. The iid generator emits the same characters at the same
/// rate and essentially never emits a region.
///
/// Deterministic runner, so this is a fixed measurement and not a flaky one.
#[test]
fn stateful_generator_reaches_runs_the_iid_generator_cannot() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    const SAMPLES: usize = 512;

    let mut runner = TestRunner::deterministic();
    let iid = hostile_string();
    let stateful = hostile_string_stateful();

    let mut iid_longest = 0usize;
    let mut stateful_longest = 0usize;

    for _ in 0..SAMPLES {
        let a = iid.new_tree(&mut runner).expect("iid tree").current();
        iid_longest = iid_longest.max(longest_forbidden_run(&a));

        let b = stateful
            .new_tree(&mut runner)
            .expect("stateful tree")
            .current();
        stateful_longest = stateful_longest.max(longest_forbidden_run(&b));
    }

    println!(
        "longest forbidden run over {SAMPLES} samples: iid={iid_longest}, stateful={stateful_longest}"
    );

    // The stateful generator must reach a genuine region, not a scattering.
    assert!(
        stateful_longest >= 12,
        "stateful generator only reached a run of {stateful_longest}; it is not producing regions"
    );

    // And it must reach strictly further than independent draws, which is the
    // whole reason it exists. If this ever stops holding, the switch
    // probability has been tuned until the generator is iid again.
    assert!(
        stateful_longest > iid_longest,
        "stateful run {stateful_longest} did not beat iid run {iid_longest}"
    );
}
