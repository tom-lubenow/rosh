//! AEAD cipher implementations for Rosh
//!
//! Provides authenticated encryption using modern AEAD ciphers.
//! We support both AES-GCM and ChaCha20-Poly1305 for flexibility.

use crate::CryptoError;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Key, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

/// Size of the authentication tag in bytes
pub const TAG_SIZE: usize = 16;

/// Size of the nonce for AES-GCM
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Size of the nonce for ChaCha20-Poly1305
pub const CHACHA_NONCE_SIZE: usize = 12;

/// Supported cipher algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum CipherAlgorithm {
    /// AES-128-GCM
    #[cfg_attr(feature = "clap", value(name = "aes-gcm"))]
    Aes128Gcm,
    /// AES-256-GCM
    #[cfg_attr(feature = "clap", value(name = "aes-256-gcm"))]
    Aes256Gcm,
    /// ChaCha20-Poly1305
    #[cfg_attr(feature = "clap", value(name = "chacha20-poly1305"))]
    ChaCha20Poly1305,
}

impl CipherAlgorithm {
    /// Get the key size in bytes for this algorithm
    pub fn key_size(&self) -> usize {
        match self {
            CipherAlgorithm::Aes128Gcm => 16,
            CipherAlgorithm::Aes256Gcm => 32,
            CipherAlgorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Get the nonce size in bytes for this algorithm
    pub fn nonce_size(&self) -> usize {
        match self {
            CipherAlgorithm::Aes128Gcm | CipherAlgorithm::Aes256Gcm => AES_GCM_NONCE_SIZE,
            CipherAlgorithm::ChaCha20Poly1305 => CHACHA_NONCE_SIZE,
        }
    }
}

/// Trait for AEAD cipher operations
pub trait Cipher: Send + Sync {
    /// Encrypt a message with associated data
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Decrypt a message with associated data
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Get the algorithm used by this cipher
    fn algorithm(&self) -> CipherAlgorithm;
}

/// AES-128-GCM cipher implementation
pub struct Aes128GcmCipher {
    cipher: Aes128Gcm,
}

impl Aes128GcmCipher {
    /// Create a new AES-128-GCM cipher
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 16,
                got: key.len(),
            });
        }

        let key = Key::<Aes128Gcm>::from_slice(key);
        let cipher = Aes128Gcm::new(key);

        Ok(Self { cipher })
    }
}

impl Cipher for Aes128GcmCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != AES_GCM_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: AES_GCM_NONCE_SIZE,
                got: nonce.len(),
            });
        }

        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != AES_GCM_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: AES_GCM_NONCE_SIZE,
                got: nonce.len(),
            });
        }

        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Aes128Gcm
    }
}

/// AES-256-GCM cipher implementation
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// Create a new AES-256-GCM cipher
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        Ok(Self { cipher })
    }
}

impl Cipher for Aes256GcmCipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != AES_GCM_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: AES_GCM_NONCE_SIZE,
                got: nonce.len(),
            });
        }

        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != AES_GCM_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: AES_GCM_NONCE_SIZE,
                got: nonce.len(),
            });
        }

        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::Aes256Gcm
    }
}

/// ChaCha20-Poly1305 cipher implementation
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new ChaCha20-Poly1305 cipher
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                got: key.len(),
            });
        }

        let key = Key::<ChaCha20Poly1305>::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key);

        Ok(Self { cipher })
    }
}

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != CHACHA_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: CHACHA_NONCE_SIZE,
                got: nonce.len(),
            });
        }

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        self.cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if nonce.len() != CHACHA_NONCE_SIZE {
            return Err(CryptoError::InvalidNonceLength {
                expected: CHACHA_NONCE_SIZE,
                got: nonce.len(),
            });
        }

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        self.cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    fn algorithm(&self) -> CipherAlgorithm {
        CipherAlgorithm::ChaCha20Poly1305
    }
}

/// Create a cipher instance from an algorithm and key
pub fn create_cipher(
    algorithm: CipherAlgorithm,
    key: &[u8],
) -> Result<Box<dyn Cipher>, CryptoError> {
    match algorithm {
        CipherAlgorithm::Aes128Gcm => Ok(Box::new(Aes128GcmCipher::new(key)?)),
        CipherAlgorithm::Aes256Gcm => Ok(Box::new(Aes256GcmCipher::new(key)?)),
        CipherAlgorithm::ChaCha20Poly1305 => Ok(Box::new(ChaCha20Poly1305Cipher::new(key)?)),
    }
}

/// Nonce generator for maintaining unique nonces
pub struct NonceGenerator {
    counter: u64,
    direction: bool, // false = client->server, true = server->client
}

impl NonceGenerator {
    /// Create a new nonce generator
    pub fn new(is_server: bool) -> Self {
        Self {
            counter: 0,
            direction: is_server,
        }
    }

    /// Generate the next nonce
    pub fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];

        // First 4 bytes: zeros
        // Last 8 bytes: direction bit + 63-bit counter
        let direction_and_counter = if self.direction {
            0x8000_0000_0000_0000 | self.counter
        } else {
            self.counter
        };

        nonce[4..].copy_from_slice(&direction_and_counter.to_be_bytes());

        self.counter += 1;
        if self.counter >= 0x7FFF_FFFF_FFFF_FFFF {
            // This would take centuries at reasonable packet rates
            panic!("Nonce counter exhausted");
        }

        nonce
    }

    /// Extract sequence number from a nonce
    pub fn extract_sequence(nonce: &[u8]) -> Option<u64> {
        if nonce.len() < 12 {
            return None;
        }

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&nonce[4..12]);
        let value = u64::from_be_bytes(bytes);

        // Mask off direction bit
        Some(value & 0x7FFF_FFFF_FFFF_FFFF)
    }
}
