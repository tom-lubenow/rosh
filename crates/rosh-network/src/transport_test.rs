#[cfg(test)]
mod tests {
    use super::super::*;
    use quinn::VarInt;
    use rosh_crypto::{
        create_cipher, decode_key, encode_key, CipherAlgorithm, NonceGenerator, SessionInfo,
    };
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::timeout;

    fn test_session_info() -> SessionInfo {
        SessionInfo {
            port: 8080,
            key: encode_key(&[0u8; 16]), // 16 bytes for AES-128
            algorithm: CipherAlgorithm::Aes128Gcm,
        }
    }

    #[tokio::test]
    async fn test_client_transport_creation() {
        let config = RoshTransportConfig::default();
        let result = ClientTransport::new(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_server_transport_creation() {
        let config = RoshTransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let result = ServerTransport::new(addr, config).await;
        assert!(result.is_ok());

        let server = result.unwrap();
        let local_addr = server.local_addr();
        assert!(local_addr.is_ok());
        assert_eq!(local_addr.unwrap().ip(), addr.ip());
    }

    #[tokio::test]
    async fn test_connection_to_nonexistent_server() {
        let config = RoshTransportConfig::default();
        let mut client = ClientTransport::new(config).await.unwrap();

        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        // Try to connect with timeout - should fail since no server is listening
        let result = timeout(Duration::from_secs(5), client.connect(addr)).await;

        // Either timeout or connection error is acceptable
        match result {
            Ok(Err(_)) => {
                // Connection failed (expected) - any network error is acceptable
            }
            Err(_) => {
                // Timeout occurred (also acceptable)
            }
            Ok(Ok(_)) => panic!("Connection unexpectedly succeeded"),
        }
    }

    #[tokio::test]
    async fn test_cipher_from_session_info() {
        let session_info = test_session_info();
        let key = decode_key(&session_info.key).unwrap();
        let cipher_result = create_cipher(session_info.algorithm, &key);
        assert!(cipher_result.is_ok());

        let cipher = cipher_result.unwrap();
        let mut nonce_gen = NonceGenerator::new(false);

        // Test encryption/decryption
        let data = b"test data";
        let nonce = nonce_gen.next_nonce();
        let encrypted = cipher.encrypt(&nonce, data, &[]).unwrap();
        let decrypted = cipher.decrypt(&nonce, &encrypted, &[]).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_transport_config() {
        let config = RoshTransportConfig {
            keep_alive_interval: Duration::from_secs(30),
            max_idle_timeout: Duration::from_secs(60),
            initial_window: 1024 * 1024,
            stream_receive_window: VarInt::from_u32(512 * 1024),
        };

        // Test that we can create transports with custom config
        let client_result = ClientTransport::new(config.clone()).await;
        assert!(client_result.is_ok());

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server_result = ServerTransport::new(addr, config).await;
        assert!(server_result.is_ok());
    }

    #[tokio::test]
    async fn test_concurrent_client_creation() {
        let mut handles = vec![];

        // Create multiple clients concurrently
        for _ in 0..5 {
            let handle = tokio::spawn(async move {
                let config = RoshTransportConfig::default();
                ClientTransport::new(config).await
            });
            handles.push(handle);
        }

        // All should succeed
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_server_accept_timeout() {
        let config = RoshTransportConfig::default();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = ServerTransport::new(addr, config).await.unwrap();

        // Try to accept a connection with timeout (no client connecting)
        let key = vec![0u8; 16];
        let accept_result = timeout(
            Duration::from_millis(100),
            server.accept(&key, CipherAlgorithm::Aes128Gcm),
        )
        .await;

        // Should timeout
        assert!(accept_result.is_err());
    }
}
