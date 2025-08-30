use rosh_crypto::{create_cipher, CipherAlgorithm, NonceGenerator};

#[test]
fn chacha20_poly1305_encrypt_decrypt_roundtrip_and_nonce_properties() {
    // 32-byte key for ChaCha20-Poly1305
    let key = [0x24u8; 32];
    let aad = b"aad";
    let plaintext = b"rosh chacha test";

    let cipher = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &key).expect("cipher");

    // Nonces must be unique and sequences monotonic
    let mut ng_client = NonceGenerator::new(false);
    let n1 = ng_client.next_nonce();
    let n2 = ng_client.next_nonce();
    assert_ne!(n1, n2);
    let s1 = NonceGenerator::extract_sequence(&n1).unwrap();
    let s2 = NonceGenerator::extract_sequence(&n2).unwrap();
    assert!(s2 > s1);

    // Direction bit is 0 for client, 1 for server
    let dir_bit_client =
        (u64::from_be_bytes(n1[4..12].try_into().unwrap()) & 0x8000_0000_0000_0000) != 0;
    assert!(!dir_bit_client);

    let ct = cipher.encrypt(&n1, plaintext, aad).expect("encrypt");
    let pt = cipher.decrypt(&n1, &ct, aad).expect("decrypt");
    assert_eq!(pt.as_slice(), plaintext);

    let mut ng_server = NonceGenerator::new(true);
    let n_server = ng_server.next_nonce();
    let dir_bit_server =
        (u64::from_be_bytes(n_server[4..12].try_into().unwrap()) & 0x8000_0000_0000_0000) != 0;
    assert!(dir_bit_server);
}
