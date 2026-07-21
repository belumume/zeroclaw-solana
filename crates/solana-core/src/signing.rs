//! Deterministic ed25519 signing for transactions. NO RNG anywhere: the
//! 32-byte seed is operator-provided (host-injected via jailed config in a
//! plugin), never generated, never logged. Anchored to the RFC 8032 test
//! vector, so the primitive is validated against the standard itself.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    /// The public key bytes are not a valid ed25519 point.
    BadPublicKey,
    /// The signature bytes are malformed.
    BadSignature,
}

/// Derive the public key (= the Solana address bytes) for a 32-byte seed.
pub fn pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign an arbitrary message (for transactions: the serialized message bytes).
pub fn sign_message(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Verify a signature. Used in tests and pre-broadcast sanity checks.
pub fn verify_signature(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool, SigningError> {
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| SigningError::BadPublicKey)?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    Ok(vk.verify(message, &sig).is_ok())
}

/// Wire-format transaction: shortvec signature count, signatures, message.
pub fn serialize_transaction(signatures: &[[u8; 64]], message_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + signatures.len() * 64 + message_bytes.len());
    crate::shortvec::encode_len(signatures.len() as u16, &mut out);
    for sig in signatures {
        out.extend_from_slice(sig);
    }
    out.extend_from_slice(message_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.1 TEST 1: the standard's own known-answer vector.
    #[test]
    fn rfc8032_test_vector_1() {
        let seed: [u8; 32] =
            from_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap();
        let expected_pub =
            from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_sig = from_hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        assert_eq!(pubkey_from_seed(&seed).to_vec(), expected_pub);
        assert_eq!(sign_message(&seed, b"").to_vec(), expected_sig);
    }

    #[test]
    fn sign_verify_round_trip_and_tamper_detection() {
        let seed = [42u8; 32];
        let msg = b"zeroclaw attestation payload";
        let pk = pubkey_from_seed(&seed);
        let sig = sign_message(&seed, msg);
        assert_eq!(verify_signature(&pk, msg, &sig), Ok(true));
        assert_eq!(verify_signature(&pk, b"tampered", &sig), Ok(false));
        let mut bad_sig = sig;
        bad_sig[0] ^= 1;
        assert_eq!(verify_signature(&pk, msg, &bad_sig), Ok(false));
    }

    #[test]
    fn transaction_wire_shape() {
        let sig = [7u8; 64];
        let msg = vec![1, 2, 3];
        let tx = serialize_transaction(&[sig], &msg);
        assert_eq!(tx[0], 1); // shortvec count
        assert_eq!(&tx[1..65], &sig);
        assert_eq!(&tx[65..], &msg[..]);
    }
}
