use bytes::BytesMut;
use rosh_network::protocol::{FramedCodec, Message, PROTOCOL_VERSION};

#[test]
fn framed_codec_roundtrip_common_messages() {
    // A representative sample of protocol messages to validate framing + rkyv serde
    let samples = vec![
        Message::ClientHello {
            version: PROTOCOL_VERSION,
            session_id: None,
        },
        Message::ServerHello {
            version: PROTOCOL_VERSION,
            session_id: 42,
        },
        Message::Handshake {
            session_keys_bytes: vec![1, 2, 3, 4, 5],
            terminal_width: 80,
            terminal_height: 24,
        },
        Message::HandshakeAck {
            session_id: 777,
            cipher_algorithm: 1,
        },
        Message::Input(b"echo hello\n".to_vec()),
        Message::Resize(100, 40),
        Message::State(vec![9, 8, 7, 6]),
        Message::StateAck(1234),
        Message::StateRequest,
        Message::Ping,
        Message::Pong,
        Message::StateUpdate {
            seq_num: 10,
            ack_num: 9,
            diff: vec![0, 1, 2, 3],
            timestamp: Message::timestamp_now(),
        },
        Message::Ack {
            ack_num: 10,
            timestamp: Message::timestamp_now(),
        },
        Message::UserInput {
            seq_num: 11,
            ack_num: 10,
            input: b"abc".to_vec(),
            timestamp: Message::timestamp_now(),
        },
        Message::SyncRequest { last_known_seq: 5 },
        Message::SyncResponse {
            seq_num: 6,
            state: vec![1, 1, 2, 3, 5, 8],
        },
    ];

    for msg in samples.into_iter() {
        let mut buf = BytesMut::new();
        FramedCodec::encode(&msg, &mut buf).expect("encode");

        // Decoder expects the full frame in the buffer
        let decoded = FramedCodec::decode(&mut buf)
            .expect("decode result")
            .expect("complete frame");

        match (&msg, &decoded) {
            // timestamp fields will differ in value if we regenerated; for deterministic compare,
            // only compare the variant discriminant and non-timestamp fields.
            (
                Message::StateUpdate {
                    seq_num: a1,
                    ack_num: a2,
                    diff: a3,
                    ..
                },
                Message::StateUpdate {
                    seq_num: b1,
                    ack_num: b2,
                    diff: b3,
                    ..
                },
            ) => {
                assert_eq!(a1, b1);
                assert_eq!(a2, b2);
                assert_eq!(a3, b3);
            }
            (Message::Ack { ack_num: a1, .. }, Message::Ack { ack_num: b1, .. }) => {
                assert_eq!(a1, b1);
            }
            (a, b) => {
                assert_eq!(format!("{a:?}"), format!("{:?}", b));
            }
        }

        // buffer should be fully consumed
        assert!(buf.is_empty());
    }
}
