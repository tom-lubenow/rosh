//! Cryptographic primitives for Rosh
//! 
//! This module provides encryption and authentication using modern AEAD ciphers.
//! We use ring for crypto operations as it's a well-audited pure Rust implementation.

pub mod cipher;
pub mod key_exchange;

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