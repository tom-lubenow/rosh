//! Cryptographic primitives for Rosh
//! 
//! This module provides encryption and authentication using modern AEAD ciphers.
//! We use ring for crypto operations as it's a well-audited pure Rust implementation.

pub mod cipher;
pub mod key_exchange;

pub use cipher::{
    Cipher, CipherAlgorithm, NonceGenerator,
    create_cipher, TAG_SIZE, AES_GCM_NONCE_SIZE, CHACHA_NONCE_SIZE,
};
pub use key_exchange::{
    generate_key, encode_key, decode_key, 
    SessionInfo, KEY_ENV_VAR, get_key_from_env,
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
}