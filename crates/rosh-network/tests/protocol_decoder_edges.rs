use bytes::BytesMut;
use rosh_network::protocol::{FramedCodec, Message, PROTOCOL_VERSION};

#[test]
fn partial_buffer_then_complete_decodes_once_ready() {
    let msg = Message::ClientHello {
        version: PROTOCOL_VERSION,
        session_id: Some(123),
    };
    let mut full = BytesMut::new();
    FramedCodec::encode(&msg, &mut full).expect("encode");

    // Split buffer into two parts to simulate partial read
    let mid = 2; // less than 4-byte length prefix: still should return None
    let mut buf = BytesMut::from(&full[..mid]);
    let res = FramedCodec::decode(&mut buf).expect("decode ok");
    assert!(res.is_none(), "not enough bytes for length prefix");

    // Append the rest: still may be insufficient for full frame at once, so do it in two steps
    let mid2 = full.len() - mid - 1; // leave 1 byte short
    buf.extend_from_slice(&full[mid..mid + mid2]);
    let res2 = FramedCodec::decode(&mut buf).expect("decode ok");
    assert!(res2.is_none(), "still incomplete frame");

    // Finally, add the last byte
    buf.extend_from_slice(&full[mid + mid2..]);
    let decoded = FramedCodec::decode(&mut buf)
        .expect("decode ok")
        .expect("now complete");

    // Compare by debug format for simplicity
    assert_eq!(format!("{msg:?}"), format!("{:?}", decoded));
    assert!(buf.is_empty());
}

#[test]
fn invalid_payload_returns_error() {
    // Craft a bogus frame: length=3, payload=3 bytes of junk
    let mut buf = BytesMut::new();
    buf.extend_from_slice(&(3u32.to_be_bytes()));
    buf.extend_from_slice(&[0xde, 0xad, 0xbe]);

    let err = FramedCodec::decode(&mut buf).unwrap_err();
    // Should be a protocol error from rkyv validation
    let msg = format!("{err}");
    assert!(msg.contains("Protocol error") || msg.contains("Validation failed"));
}
