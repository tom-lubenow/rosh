use rosh_crypto::key_exchange::{decode_key, encode_key};

#[test]
fn base64_urlsafe_roundtrip() {
    let key = (0u8..32).collect::<Vec<u8>>();
    let enc = encode_key(&key);
    let dec = decode_key(&enc).expect("decode");
    assert_eq!(dec, key);
}
