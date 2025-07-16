//! Key generation and exchange for Rosh
//! 
//! Like Mosh, we use pre-shared keys transmitted via SSH.
//! However, we provide better key generation and encoding.

use crate::{CipherAlgorithm, CryptoError};
use ring::rand::{SecureRandom, SystemRandom};
use base64::{Engine as _, engine::general_purpose};

/// Generate a random key for the given cipher algorithm
pub fn generate_key(algorithm: CipherAlgorithm) -> Result<Vec<u8>, CryptoError> {
    let key_size = algorithm.key_size();
    let mut key = vec![0u8; key_size];
    
    let rng = SystemRandom::new();
    rng.fill(&mut key)
        .map_err(|_| CryptoError::KeyExchangeFailed("Failed to generate random key".to_string()))?;
    
    Ok(key)
}

/// Encode a key to base64 for transmission
pub fn encode_key(key: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(key)
}

/// Decode a key from base64
pub fn decode_key(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| CryptoError::KeyExchangeFailed(format!("Invalid base64 key: {}", e)))
}

/// Session information transmitted from server to client
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// UDP port number
    pub port: u16,
    /// Base64-encoded session key
    pub key: String,
    /// Cipher algorithm to use
    pub algorithm: CipherAlgorithm,
}

impl SessionInfo {
    /// Create new session info
    pub fn new(port: u16, key: Vec<u8>, algorithm: CipherAlgorithm) -> Self {
        Self {
            port,
            key: encode_key(&key),
            algorithm,
        }
    }
    
    /// Format for transmission over SSH (similar to Mosh)
    pub fn to_connect_string(&self) -> String {
        format!("ROSH CONNECT {} {} {}", 
            self.port, 
            self.key,
            match self.algorithm {
                CipherAlgorithm::Aes128Gcm => "AES128",
                CipherAlgorithm::Aes256Gcm => "AES256", 
                CipherAlgorithm::ChaCha20Poly1305 => "CHACHA20",
            }
        )
    }
    
    /// Parse from connect string
    pub fn from_connect_string(s: &str) -> Result<Self, CryptoError> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 5 || parts[0] != "ROSH" || parts[1] != "CONNECT" {
            return Err(CryptoError::KeyExchangeFailed(
                "Invalid connect string format".to_string()
            ));
        }
        
        let port = parts[2].parse::<u16>()
            .map_err(|_| CryptoError::KeyExchangeFailed("Invalid port number".to_string()))?;
            
        let key = parts[3].to_string();
        
        let algorithm = match parts[4] {
            "AES128" => CipherAlgorithm::Aes128Gcm,
            "AES256" => CipherAlgorithm::Aes256Gcm,
            "CHACHA20" => CipherAlgorithm::ChaCha20Poly1305,
            _ => return Err(CryptoError::KeyExchangeFailed(
                "Unknown cipher algorithm".to_string()
            )),
        };
        
        Ok(Self { port, key, algorithm })
    }
    
    /// Get the decoded key bytes
    pub fn decode_key(&self) -> Result<Vec<u8>, CryptoError> {
        decode_key(&self.key)
    }
}

/// Environment variable name for passing the key (like Mosh)
pub const KEY_ENV_VAR: &str = "ROSH_KEY";

/// Get session key from environment and immediately unset it
pub fn get_key_from_env() -> Option<String> {
    match std::env::var(KEY_ENV_VAR) {
        Ok(key) => {
            // Immediately remove from environment for security
            std::env::remove_var(KEY_ENV_VAR);
            Some(key)
        }
        Err(_) => None,
    }
}

/// Session keys for bidirectional communication
#[derive(Debug, Clone)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", archive(check_bytes))]
pub struct SessionKeys {
    /// Key used by client for encryption (server uses for decryption)
    pub client_write_key: Vec<u8>,
    /// Key used by server for encryption (client uses for decryption)
    pub server_write_key: Vec<u8>,
}

/// Key derivation using HKDF for generating session keys
pub struct KeyDerivation {
    master_key: Vec<u8>,
}

impl KeyDerivation {
    /// Create a new key derivation context
    pub fn new(master_key: &[u8]) -> Self {
        Self {
            master_key: master_key.to_vec(),
        }
    }
    
    /// Derive a key for a specific purpose
    pub fn derive_key(&mut self, info: &[u8]) -> Vec<u8> {
        use ring::hkdf;
        
        let salt = ring::hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(&self.master_key);
        
        let mut output = vec![0u8; 32]; // Always derive 32 bytes
        let info_slice = [info];
        let okm = prk.expand(&info_slice, ring::hkdf::HKDF_SHA256).unwrap();
        okm.fill(&mut output).unwrap();
        
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let key1 = generate_key(CipherAlgorithm::Aes128Gcm).unwrap();
        assert_eq!(key1.len(), 16);
        
        let key2 = generate_key(CipherAlgorithm::ChaCha20Poly1305).unwrap();
        assert_eq!(key2.len(), 32);
        
        // Keys should be different
        let key3 = generate_key(CipherAlgorithm::Aes128Gcm).unwrap();
        assert_ne!(key1, key3);
    }
    
    #[test]
    fn test_key_encoding() {
        let key = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let encoded = encode_key(&key);
        let decoded = decode_key(&encoded).unwrap();
        assert_eq!(key, decoded);
    }
    
    #[test]
    fn test_session_info() {
        let key = generate_key(CipherAlgorithm::ChaCha20Poly1305).unwrap();
        let info = SessionInfo::new(60001, key.clone(), CipherAlgorithm::ChaCha20Poly1305);
        
        let connect_str = info.to_connect_string();
        assert!(connect_str.starts_with("ROSH CONNECT 60001"));
        assert!(connect_str.ends_with("CHACHA20"));
        
        let parsed = SessionInfo::from_connect_string(&connect_str).unwrap();
        assert_eq!(parsed.port, 60001);
        assert_eq!(parsed.algorithm, CipherAlgorithm::ChaCha20Poly1305);
        assert_eq!(parsed.decode_key().unwrap(), key);
    }
}