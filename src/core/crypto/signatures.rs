//! Signature verification for website ("Sign in with your wallet") auth.
//!
//! - BTC/LTC: ECDSA secp256k1 over the Bitcoin signed-message hash (BIP-137).
//! - XMR/WOW/Grin: Ed25519 (RFC 8032 over the raw message).
//!
//! Both functions return `Ok(())` ONLY when the signature is cryptographically
//! valid. A malformed input is `ValidationError` (400); a well-formed but
//! non-matching signature is `AuthError` (401). There is deliberately no
//! `Ok(false)` path: a caller that writes `verify(...)?` cannot accidentally
//! treat a bad signature as success.

use sha2::{Digest, Sha256};

use crate::error::AppError;

fn invalid(msg: &str) -> AppError {
    AppError::ValidationError(msg.into())
}

fn unverified() -> AppError {
    AppError::AuthError("signature verification failed".into())
}

/// Verify a Bitcoin-style ECDSA signature (secp256k1).
///
/// * `signature_str` — BIP-137 base64 (65 bytes: header + r + s).
/// * `pubkey_hex` — compressed SEC1 public key (33 bytes / 66 hex chars).
pub fn verify_bitcoin_signature(
    message: &str,
    signature_str: &str,
    pubkey_hex: &str,
) -> Result<(), AppError> {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| invalid("Invalid public key hex"))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&pubkey_bytes)
        .map_err(|_| invalid("Invalid secp256k1 public key"))?;

    let msg_hash = bitcoin_message_hash(message);

    // BIP-137: 65 bytes, drop the recovery/compression header byte.
    let decoded = base64_decode(signature_str)
        .map_err(|_| invalid("Invalid signature encoding (expected base64)"))?;
    if decoded.len() != 65 {
        return Err(invalid("BIP-137 signature must be 65 bytes"));
    }
    let signature =
        Signature::from_slice(&decoded[1..]).map_err(|_| invalid("Invalid ECDSA signature"))?;

    verifying_key
        .verify_prehash(&msg_hash, &signature)
        .map_err(|_| unverified())
}

/// Verify an Ed25519 signature (RFC 8032 over the raw message bytes).
///
/// * `signature_hex` — 64-byte signature (128 hex chars).
/// * `pubkey_hex` — 32-byte public key (64 hex chars).
pub fn verify_ed25519_signature(
    message: &str,
    signature_hex: &str,
    pubkey_hex: &str,
) -> Result<(), AppError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pubkey_bytes = hex::decode(pubkey_hex).map_err(|_| invalid("Invalid public key hex"))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| invalid("Ed25519 public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|_| invalid("Invalid Ed25519 public key"))?;

    let sig_bytes = hex::decode(signature_hex).map_err(|_| invalid("Invalid signature hex"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| invalid("Ed25519 signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| unverified())
}

/// Bitcoin signed-message hash: SHA256d("\x18Bitcoin Signed Message:\n" || varint(len) || message).
fn bitcoin_message_hash(message: &str) -> [u8; 32] {
    let prefix = b"\x18Bitcoin Signed Message:\n";
    let message_bytes = message.as_bytes();
    let len_bytes = encode_varint(message_bytes.len());

    let mut full = Vec::with_capacity(prefix.len() + len_bytes.len() + message_bytes.len());
    full.extend_from_slice(prefix);
    full.extend_from_slice(&len_bytes);
    full.extend_from_slice(message_bytes);

    let first = Sha256::digest(&full);
    let second = Sha256::digest(first);
    second.into()
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(input).map_err(|e| e.to_string())
}

/// Encode an integer as a Bitcoin-style varint.
fn encode_varint(n: usize) -> Vec<u8> {
    if n < 253 {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut buf = vec![0xfd];
        buf.extend_from_slice(&(n as u16).to_le_bytes());
        buf
    } else if n <= 0xFFFF_FFFF {
        let mut buf = vec![0xfe];
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf
    } else {
        let mut buf = vec![0xff];
        buf.extend_from_slice(&(n as u64).to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitcoin_message_hash_is_32_bytes() {
        assert_eq!(bitcoin_message_hash("test").len(), 32);
    }

    #[test]
    fn encode_varint_boundaries() {
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(252), vec![252]);
        assert_eq!(encode_varint(253), vec![0xfd, 253, 0]);
        assert_eq!(encode_varint(0xFFFF), vec![0xfd, 0xFF, 0xFF]);
    }

    #[test]
    fn malformed_pubkey_is_validation_error() {
        let err = verify_ed25519_signature("msg", &"00".repeat(64), "zz").unwrap_err();
        assert!(matches!(err, AppError::ValidationError(_)));
    }

    #[test]
    fn wellformed_but_wrong_ed25519_is_auth_error() {
        // Valid lengths/encodings, but a zero signature against a valid-shaped key
        // will not verify -> AuthError (never Ok).
        let pk = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"; // a valid ed25519 pubkey
        let err = verify_ed25519_signature("hello", &"00".repeat(64), pk).unwrap_err();
        assert!(matches!(err, AppError::AuthError(_)));
    }
}
