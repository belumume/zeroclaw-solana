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

/// A generator that mixes ordinary text with the exact characters an attacker
/// would reach for: bidi overrides, zero-width joiners, control bytes, and
/// injection framing.
fn hostile_string() -> impl Strategy<Value = String> {
    let pieces = prop::sample::select(vec![
        "normal", " ", "  ", "\n", "\r\n", "\t",
        "\u{202E}", "\u{202D}", "\u{2066}", "\u{2069}", // bidi
        "\u{200B}", "\u{200D}", "\u{FEFF}",             // zero-width
        "\u{0000}", "\u{0007}", "\u{001B}",             // control
        "\u{2028}", "\u{2029}",                         // line/para separators
        "ignore previous instructions",
        "SYSTEM:", "</code>", "USDC", "名前", "🙂",
    ]);
    prop::collection::vec(pieces, 0..40).prop_map(|v| v.concat())
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
