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
