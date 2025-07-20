//! Error handling tests for rosh-crypto module

use rosh_crypto::{
    create_cipher, CipherAlgorithm, CryptoError, KeyDerivation, NonceGenerator, SessionKeys,
    AES_GCM_NONCE_SIZE,
};

#[test]
fn test_aes128_gcm_invalid_key_length() {
    // AES-128 requires 16 bytes
    let short_key = vec![0u8; 8];
    let result = create_cipher(CipherAlgorithm::Aes128Gcm, &short_key);
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));

    let long_key = vec![0u8; 32];
    let result = create_cipher(CipherAlgorithm::Aes128Gcm, &long_key);
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
}

#[test]
fn test_chacha20_poly1305_invalid_key_length() {
    // ChaCha20-Poly1305 requires 32 bytes
    let short_key = vec![0u8; 16];
    let result = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &short_key);
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));

    let long_key = vec![0u8; 64];
    let result = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &long_key);
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
}

#[test]
fn test_invalid_nonce_length() {
    let key = vec![0u8; 16]; // Correct size for AES-128
    let cipher = create_cipher(CipherAlgorithm::Aes128Gcm, &key).unwrap();

    // Test with wrong nonce size
    let short_nonce = vec![0u8; 8];
    let plaintext = b"Hello, world!";
    let aad = b"additional data";

    let result = cipher.encrypt(&short_nonce, plaintext, aad);
    assert!(matches!(
        result,
        Err(CryptoError::InvalidNonceLength { .. })
    ));

    let long_nonce = vec![0u8; 16];
    let result = cipher.encrypt(&long_nonce, plaintext, aad);
    assert!(matches!(
        result,
        Err(CryptoError::InvalidNonceLength { .. })
    ));
}

#[test]
fn test_encrypt_decrypt_with_invalid_data() {
    let key = vec![0u8; 16]; // Correct size for AES-128
    let cipher = create_cipher(CipherAlgorithm::Aes128Gcm, &key).unwrap();
    let nonce = vec![0u8; AES_GCM_NONCE_SIZE];

    // Test encrypting
    let plaintext = b"Hello, world!";
    let aad = b"additional data";
    let encrypted = cipher.encrypt(&nonce, plaintext, aad).unwrap();

    // Corrupt the ciphertext
    let mut corrupted = encrypted.clone();
    if corrupted.len() > 5 {
        corrupted[5] ^= 0xFF;
    }

    // Try to decrypt corrupted data
    let result = cipher.decrypt(&nonce, &corrupted, aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));

    // Try with wrong AAD
    let wrong_aad = b"wrong additional data";
    let result = cipher.decrypt(&nonce, &encrypted, wrong_aad);
    assert!(matches!(result, Err(CryptoError::DecryptionFailed)));
}

#[test]
fn test_key_derivation_edge_cases() {
    // Test with empty key
    let empty_key = b"";
    let mut kd = KeyDerivation::new(empty_key);
    let derived = kd.derive_key(b"test").unwrap();
    assert_eq!(derived.len(), 32); // Should still produce 32 bytes

    // Test with very long key
    let long_key = vec![0u8; 1024];
    let mut kd = KeyDerivation::new(&long_key);
    let derived = kd.derive_key(b"test").unwrap();
    assert_eq!(derived.len(), 32);

    // Test with empty info
    let mut kd = KeyDerivation::new(b"key");
    let derived = kd.derive_key(b"").unwrap();
    assert_eq!(derived.len(), 32);
}

#[test]
fn test_session_keys_fields() {
    let keys = SessionKeys {
        client_write_key: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        server_write_key: vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
    };

    assert_eq!(keys.client_write_key.len(), 16);
    assert_eq!(keys.server_write_key.len(), 16);
}

#[test]
fn test_nonce_generator() {
    let mut client_gen = NonceGenerator::new(false);
    let mut server_gen = NonceGenerator::new(true);

    // Generate some nonces
    let client_nonce1 = client_gen.next_nonce();
    let client_nonce2 = client_gen.next_nonce();
    let server_nonce1 = server_gen.next_nonce();

    // Nonces should be different
    assert_ne!(client_nonce1, client_nonce2);
    assert_ne!(client_nonce1, server_nonce1);

    // Extract sequence numbers
    let seq1 = NonceGenerator::extract_sequence(&client_nonce1).unwrap();
    let seq2 = NonceGenerator::extract_sequence(&client_nonce2).unwrap();
    assert_eq!(seq1, 0);
    assert_eq!(seq2, 1);
}

#[test]
fn test_nonce_generator_overflow() {
    let key = vec![0u8; 32];
    let cipher = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &key).unwrap();
    let mut nonce_gen = NonceGenerator::new(false);

    // Encrypt many times to test nonce increment
    for _ in 0..100 {
        let nonce = nonce_gen.next_nonce();
        let plaintext = b"test";
        let aad = b"aad";
        let _ = cipher.encrypt(&nonce, plaintext, aad).unwrap();
    }

    // Should not panic or overflow
}

#[test]
fn test_large_data_encryption() {
    let key = vec![0u8; 16];
    let cipher = create_cipher(CipherAlgorithm::Aes128Gcm, &key).unwrap();
    let nonce = vec![0u8; AES_GCM_NONCE_SIZE];

    // Test with large data
    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    let aad = b"";

    let encrypted = cipher.encrypt(&nonce, &large_data, aad).unwrap();
    let decrypted = cipher.decrypt(&nonce, &encrypted, aad).unwrap();

    assert_eq!(decrypted, large_data);
}

#[test]
fn test_cipher_reuse() {
    let key = vec![0u8; 32];
    let cipher = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &key).unwrap();
    let mut nonce_gen = NonceGenerator::new(false);

    // Encrypt multiple messages
    let messages = vec![
        b"First message".as_ref(),
        b"Second message".as_ref(),
        b"Third message".as_ref(),
    ];

    let mut encrypted_messages = Vec::new();
    let mut nonces = Vec::new();

    for msg in &messages {
        let nonce = nonce_gen.next_nonce();
        nonces.push(nonce);
        let encrypted = cipher.encrypt(&nonce, msg, b"").unwrap();
        encrypted_messages.push(encrypted);
    }

    // Decrypt all messages
    for (i, (encrypted, nonce)) in encrypted_messages.iter().zip(nonces.iter()).enumerate() {
        let decrypted = cipher.decrypt(nonce, encrypted, b"").unwrap();
        assert_eq!(decrypted, messages[i]);
    }
}

#[test]
fn test_empty_plaintext() {
    let key = vec![0u8; 16];
    let cipher = create_cipher(CipherAlgorithm::Aes128Gcm, &key).unwrap();
    let nonce = vec![0u8; AES_GCM_NONCE_SIZE];

    // Test with empty plaintext
    let empty: &[u8] = &[];
    let aad = b"metadata";

    let encrypted = cipher.encrypt(&nonce, empty, aad).unwrap();
    // Should have at least the tag
    assert!(encrypted.len() >= 16); // GCM tag size

    let decrypted = cipher.decrypt(&nonce, &encrypted, aad).unwrap();
    assert_eq!(decrypted, empty);
}

#[test]
fn test_aes256_gcm_invalid_key_length() {
    // AES-256 requires 32 bytes
    let short_key = vec![0u8; 16];
    let result = create_cipher(CipherAlgorithm::Aes256Gcm, &short_key);
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));

    let long_key = vec![0u8; 64];
    let result = create_cipher(CipherAlgorithm::Aes256Gcm, &long_key);
    assert!(matches!(result, Err(CryptoError::InvalidKeyLength { .. })));
}

#[test]
fn test_aes256_gcm_encryption() {
    let key = vec![0u8; 32]; // Correct size for AES-256
    let cipher = create_cipher(CipherAlgorithm::Aes256Gcm, &key).unwrap();
    let nonce = vec![0u8; AES_GCM_NONCE_SIZE];

    // Test basic encryption/decryption
    let plaintext = b"Hello, AES-256-GCM!";
    let aad = b"metadata";
    let encrypted = cipher.encrypt(&nonce, plaintext, aad).unwrap();
    let decrypted = cipher.decrypt(&nonce, &encrypted, aad).unwrap();

    assert_eq!(decrypted, plaintext);
}
