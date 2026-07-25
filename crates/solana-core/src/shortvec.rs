//! Solana's compact-u16 ("shortvec") length encoding: a little-endian base-128
//! varint capped at 3 bytes, used for every length prefix in serialized
//! messages and transactions. Decoding fails closed on truncation, overflow,
//! and non-canonical padding.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortVecError {
    /// Ran out of bytes mid-varint.
    Truncated,
    /// More than 3 bytes, or a value beyond u16::MAX.
    Overflow,
    /// A non-minimal encoding: a multi-byte varint whose terminating group is
    /// zero (e.g. `[0x80, 0x00]` for 0, `[0x81, 0x00]` for 1). A validating
    /// Solana decoder rejects these; accepting them makes length prefixes
    /// malleable.
    NonCanonical,
}

/// Append the compact-u16 encoding of `len` to `out`.
pub fn encode_len(len: u16, out: &mut Vec<u8>) {
    let mut rem = len;
    loop {
        let byte = (rem & 0x7f) as u8;
        rem >>= 7;
        if rem == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Decode a compact-u16 from the front of `data`. Returns (value, bytes_read).
pub fn decode_len(data: &[u8]) -> Result<(u16, usize), ShortVecError> {
    let mut value: u32 = 0;
    for (i, &byte) in data.iter().enumerate().take(3) {
        value |= u32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            // A terminating group of zero after a continuation byte is a
            // non-minimal encoding: fewer bytes would encode the same value.
            if i > 0 && byte == 0 {
                return Err(ShortVecError::NonCanonical);
            }
            if value > u32::from(u16::MAX) {
                return Err(ShortVecError::Overflow);
            }
            return Ok((value as u16, i + 1));
        }
    }
    if data.len() < 3 {
        Err(ShortVecError::Truncated)
    } else {
        Err(ShortVecError::Overflow)
    }
}

/// Formal proofs of the two shortvec properties that matter, for every input rather
/// than for sampled ones.
///
/// Gated behind `cfg(kani)`, which is set only by the Kani verifier, so a normal or
/// wasm build compiles none of this and ships no dead annotations.
///
/// Run: `cargo kani --harness <name>` (see TESTING.md).
#[cfg(kani)]
mod verification {
    use super::*;

    /// Every `u16` survives a round trip, and the encoding is always 1 to 3 bytes.
    ///
    /// `with_capacity(3)` rather than `new()` is a harness detail with a real effect:
    /// the encoding never exceeds three bytes, so pre-sizing turns the allocator model
    /// into one fixed-size allocation instead of the growth-and-realloc path, which is
    /// what CBMC spends its time on. The function under test is untouched.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_u16_roundtrips() {
        let n: u16 = kani::any();
        let mut buf = Vec::with_capacity(3);
        encode_len(n, &mut buf);
        assert!(!buf.is_empty() && buf.len() <= 3);

        let (value, used) = decode_len(&buf).expect("a self-produced encoding must decode");
        assert!(value == n);
        assert!(used == buf.len());
    }

    /// Decode is total on every byte string of length 0 to 3, and anything it ACCEPTS
    /// is the unique canonical encoding of the value it returns.
    ///
    /// This is the security property, not a tidiness one. If two distinct byte strings
    /// decoded to the same length, a length prefix would be malleable: a message could
    /// be re-encoded to different bytes that still parse as the same structure, which
    /// breaks any signature or hash taken over those bytes. Proptest samples 1024 of
    /// the 16,777,216 three-byte inputs. This covers all of them, and the shorter ones.
    ///
    /// Stated arithmetically rather than by re-encoding into a `Vec`. Both express the
    /// same property, but modelling the allocator put CBMC past 3.5 GB and 35 minutes
    /// without converging, and canonicality does not actually need a heap: the encoding
    /// of a value is fully determined by its 7-bit groups and its minimal length, so
    /// asserting those directly is both cheaper and more explicit about what canonical
    /// means here.
    #[kani::proof]
    fn accepted_encodings_are_uniquely_canonical() {
        let data: [u8; 3] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 3);
        let input = &data[..len];

        if let Ok((value, used)) = decode_len(input) {
            // Never reports reading more than it was given, or more than the cap.
            assert!((1..=3).contains(&used));
            assert!(used <= input.len());

            // Minimal length: a canonical encoding uses the fewest groups that fit.
            let minimal = if value < 0x80 {
                1
            } else if value < 0x4000 {
                2
            } else {
                3
            };
            assert!(used == minimal);

            // And the bytes themselves are the ones that length forces, so exactly one
            // byte string of that length decodes to this value.
            let v = u32::from(value);
            assert!(input[0] == ((v & 0x7f) as u8 | if used > 1 { 0x80 } else { 0 }));
            if used > 1 {
                assert!(input[1] == (((v >> 7) & 0x7f) as u8 | if used > 2 { 0x80 } else { 0 }));
            }
            if used > 2 {
                assert!(input[2] == ((v >> 14) & 0x7f) as u8);
            }
        }
        // Rejection is always allowed; the proof is that acceptance is never wrong.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(len: u16) -> Vec<u8> {
        let mut v = Vec::new();
        encode_len(len, &mut v);
        v
    }

    #[test]
    fn known_answer_boundaries() {
        // Canonical vectors from the Solana shortvec spec.
        assert_eq!(enc(0), [0x00]);
        assert_eq!(enc(1), [0x01]);
        assert_eq!(enc(127), [0x7f]);
        assert_eq!(enc(128), [0x80, 0x01]);
        assert_eq!(enc(16383), [0xff, 0x7f]);
        assert_eq!(enc(16384), [0x80, 0x80, 0x01]);
        assert_eq!(enc(u16::MAX), [0xff, 0xff, 0x03]);
    }

    #[test]
    fn round_trips_every_boundary() {
        for len in [0u16, 1, 127, 128, 255, 16383, 16384, u16::MAX] {
            let bytes = enc(len);
            assert_eq!(decode_len(&bytes).unwrap(), (len, bytes.len()));
        }
    }

    #[test]
    fn truncated_fails_closed() {
        assert_eq!(decode_len(&[0x80]), Err(ShortVecError::Truncated));
        assert_eq!(decode_len(&[]), Err(ShortVecError::Truncated));
    }

    #[test]
    fn overflow_fails_closed() {
        assert_eq!(
            decode_len(&[0x80, 0x80, 0x80]),
            Err(ShortVecError::Overflow)
        );
        // 3-byte encoding of a value beyond u16::MAX.
        assert_eq!(
            decode_len(&[0xff, 0xff, 0x04]),
            Err(ShortVecError::Overflow)
        );
    }

    #[test]
    fn non_canonical_fails_closed() {
        // Non-minimal encodings a validating Solana decoder rejects (canonical
        // 0 is [0x00], 1 is [0x01]).
        assert_eq!(decode_len(&[0x80, 0x00]), Err(ShortVecError::NonCanonical));
        assert_eq!(decode_len(&[0x81, 0x00]), Err(ShortVecError::NonCanonical));
        assert_eq!(
            decode_len(&[0x80, 0x80, 0x00]),
            Err(ShortVecError::NonCanonical)
        );
        // Canonical encodings still round-trip.
        assert_eq!(decode_len(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_len(&[0x80, 0x01]).unwrap(), (128, 2));
    }
}
