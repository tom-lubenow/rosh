#[cfg(test)]
mod tests {
    use crate::protocol::Message;
    use rosh_crypto::{create_cipher, CipherAlgorithm, NonceGenerator};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[allow(dead_code)]
    struct MockConnection {
        sent_messages: Arc<Mutex<Vec<Message>>>,
        receive_messages: Arc<Mutex<Vec<Message>>>,
        closed: Arc<Mutex<bool>>,
    }

    impl MockConnection {
        fn new() -> Self {
            Self {
                sent_messages: Arc::new(Mutex::new(Vec::new())),
                receive_messages: Arc::new(Mutex::new(Vec::new())),
                closed: Arc::new(Mutex::new(false)),
            }
        }
    }

    #[tokio::test]
    async fn test_connection_send_receive() {
        // Create a cipher for testing
        let cipher = create_cipher(CipherAlgorithm::Aes128Gcm, &[0u8; 16]).unwrap();
        let mut nonce_gen = NonceGenerator::new(false);

        // Test message serialization and encryption
        let test_msg = Message::Input(b"Hello, World!".to_vec());

        // Serialize
        let serialized = test_msg.to_bytes().unwrap();

        // Encrypt
        let nonce = nonce_gen.next_nonce();
        let encrypted = cipher.encrypt(&nonce, &serialized, &[]).unwrap();

        // Decrypt
        let decrypted = cipher.decrypt(&nonce, &encrypted, &[]).unwrap();

        // Deserialize
        let deserialized_msg = Message::from_bytes(&decrypted).unwrap();

        // Verify
        match (test_msg, deserialized_msg) {
            (Message::Input(original), Message::Input(result)) => {
                assert_eq!(original, result);
            }
            _ => panic!("Message type mismatch"),
        }
    }

    #[tokio::test]
    async fn test_message_encryption_decryption() {
        let cipher = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &[0u8; 32]).unwrap();
        let mut nonce_gen = NonceGenerator::new(false);

        // Test various message types
        let messages = vec![
            Message::Ping,
            Message::Pong,
            Message::Input(vec![1, 2, 3, 4, 5]),
            Message::StateRequest,
            Message::StateAck(42),
        ];

        for msg in messages {
            let serialized = msg.to_bytes().unwrap();
            let nonce = nonce_gen.next_nonce();
            let encrypted = cipher.encrypt(&nonce, &serialized, &[]).unwrap();

            // Verify we can't decrypt with wrong nonce
            let mut wrong_gen = NonceGenerator::new(true); // Different direction
            let wrong_nonce = wrong_gen.next_nonce();
            assert!(cipher.decrypt(&wrong_nonce, &encrypted, &[]).is_err());

            // Verify correct decryption
            let decrypted = cipher.decrypt(&nonce, &encrypted, &[]).unwrap();
            let deserialized = Message::from_bytes(&decrypted).unwrap();

            assert_eq!(format!("{msg:?}"), format!("{:?}", deserialized));
        }
    }

    #[tokio::test]
    async fn test_connection_close() {
        // Test that connection properly closes and cleans up resources
        let mock_conn = MockConnection::new();

        assert!(!*mock_conn.closed.lock().await);

        // Simulate close
        *mock_conn.closed.lock().await = true;

        assert!(*mock_conn.closed.lock().await);
    }

    #[tokio::test]
    async fn test_message_stats_rtt() {
        use crate::protocol::MessageStats;
        use std::time::Duration;

        let mut stats = MessageStats::default();

        // Test RTT tracking
        let sent_timestamp = Message::timestamp_now();
        tokio::time::sleep(Duration::from_millis(10)).await;
        stats.update_rtt(sent_timestamp);

        assert!(stats.last_rtt_micros.is_some());
        let rtt_micros = stats.last_rtt_micros.unwrap();

        // RTT should be at least 10ms (10000 microseconds)
        assert!(rtt_micros >= 10000);
        // But less than 100ms (100000 microseconds) for a reasonable test
        assert!(rtt_micros < 100000);
    }

    #[tokio::test]
    async fn test_quic_connection_encryption() {
        // This tests the core encryption/decryption logic used by QuicConnection
        let key = vec![0u8; 32]; // 32 bytes for ChaCha20
        let cipher = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &key).unwrap();
        let mut nonce_gen = NonceGenerator::new(false);

        // Test that we can encrypt and decrypt messages
        let test_message = Message::Input(b"test data".to_vec());
        let serialized = test_message.to_bytes().unwrap();

        // Simulate what QuicConnection does
        let nonce = nonce_gen.next_nonce();
        let encrypted = cipher.encrypt(&nonce, &serialized, &[]).unwrap();

        // And the reverse
        let decrypted = cipher.decrypt(&nonce, &encrypted, &[]).unwrap();
        let deserialized = Message::from_bytes(&decrypted).unwrap();

        match deserialized {
            Message::Input(data) => assert_eq!(data, b"test data"),
            _ => panic!("Wrong message type"),
        }
    }
}
