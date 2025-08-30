use rosh_crypto::{create_cipher, CipherAlgorithm, NonceGenerator};

#[test]
fn aes256_gcm_encrypt_decrypt_roundtrip_and_nonce_properties() {
    // Deterministic 32-byte key for AES-256-GCM
    let key = [0x42u8; 32];
    let aad = b"associated-data";
    let plaintext = b"hello rosh crypto!";

    let cipher = create_cipher(CipherAlgorithm::Aes256Gcm, &key).expect("cipher");

    // Client direction (is_server = false) should have direction bit 0
    let mut ng_client = NonceGenerator::new(false);
    let n1 = ng_client.next_nonce();
    let n2 = ng_client.next_nonce();
    assert_ne!(n1, n2, "nonces must be unique");

    // Extract sequence should increase
    let s1 = NonceGenerator::extract_sequence(&n1).expect("seq1");
    let s2 = NonceGenerator::extract_sequence(&n2).expect("seq2");
    assert!(s2 > s1, "sequence must increase");

    // Direction bit must be 0 for client
    let dir_bit_client =
        (u64::from_be_bytes(n1[4..12].try_into().unwrap()) & 0x8000_0000_0000_0000) != 0;
    assert!(!dir_bit_client, "client direction bit should be 0");

    // Encrypt and decrypt
    let ciphertext = cipher.encrypt(&n1, plaintext, aad).expect("encrypt");
    assert_ne!(
        ciphertext, plaintext,
        "ciphertext should differ from plaintext"
    );

    let recovered = cipher.decrypt(&n1, &ciphertext, aad).expect("decrypt");
    assert_eq!(&recovered, plaintext);

    // Server direction should set the direction bit
    let mut ng_server = NonceGenerator::new(true);
    let n_server = ng_server.next_nonce();
    let dir_bit_server =
        (u64::from_be_bytes(n_server[4..12].try_into().unwrap()) & 0x8000_0000_0000_0000) != 0;
    assert!(dir_bit_server, "server direction bit should be 1");
}
