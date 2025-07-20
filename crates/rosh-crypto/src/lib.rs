//! Cryptographic primitives for Rosh
//!
//! This module provides encryption and authentication using modern AEAD ciphers.
//! We use ring for crypto operations as it's a well-audited pure Rust implementation.

pub mod cipher;
pub mod key_exchange;

pub use cipher::{
    create_cipher, Cipher, CipherAlgorithm, NonceGenerator, AES_GCM_NONCE_SIZE, CHACHA_NONCE_SIZE,
    TAG_SIZE,
};
pub use key_exchange::{
    decode_key, encode_key, generate_key, get_key_from_env, KeyDerivation, SessionInfo,
    SessionKeys, KEY_ENV_VAR,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}
