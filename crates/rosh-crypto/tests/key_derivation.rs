use rosh_crypto::key_exchange::KeyDerivation;

#[test]
fn hkdf_derivation_is_deterministic_and_info_separates_keys() {
    let master = [7u8; 32];
    let mut kd1 = KeyDerivation::new(&master);
    let mut kd2 = KeyDerivation::new(&master);

    let k1a = kd1.derive_key(b"client-write").expect("k1a");
    let k1b = kd2.derive_key(b"client-write").expect("k1b");
    assert_eq!(k1a, k1b, "deterministic for same master+info");

    let k2 = kd1.derive_key(b"server-write").expect("k2");
    assert_ne!(k1a, k2, "different info yields different keys");
    assert_eq!(k1a.len(), 32);
    assert_eq!(k2.len(), 32);
}
