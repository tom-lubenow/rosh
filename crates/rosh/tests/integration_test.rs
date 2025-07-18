use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

// Test using common helpers
mod common;
mod test_helpers;

/// Test that the server binary can start and bind to a port
/// This test validates the actual binary behavior, so we use subprocess
#[tokio::test]
async fn test_server_binary_startup() {
    // For testing the actual binary, we still need to use subprocess
    let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--one-shot", "--bind", "127.0.0.1:0"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("Failed to start server");

    // Wait for server to output that it's ready
    let stdout = server.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    // Use a timeout to prevent hanging forever
    let timeout_duration = Duration::from_secs(5);
    let start = tokio::time::Instant::now();

    let mut server_ready = false;
    while start.elapsed() < timeout_duration {
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF - process may have exited
                break;
            }
            Ok(_) => {
                // Check if line indicates server is ready
                // Look for ROSH_PORT or similar startup message
                if line.contains("ROSH_PORT=") || line.contains("Listening on") {
                    server_ready = true;
                    break;
                }
                line.clear();
            }
            Err(e) => {
                panic!("Failed to read server output: {e}");
            }
        }
    }

    // Check if process is still running
    match server.try_wait() {
        Ok(None) => {
            if !server_ready {
                panic!("Server started but didn't output ready message within timeout");
            }
            // Process is still running - good
            server.kill().await.ok();
        }
        Ok(Some(status)) => {
            panic!("Server exited unexpectedly with status: {status:?}");
        }
        Err(e) => {
            panic!("Failed to check server status: {e}");
        }
    }
}

/// Test basic client-server connection using in-process helpers
#[tokio::test]
async fn test_basic_connection() {
    use test_helpers::{
        start_test_server as start_in_process_server, TestClient as InProcessClient,
        TestServerConfig,
    };

    // Start in-process server (faster than subprocess)
    let config = TestServerConfig::default();
    let server = start_in_process_server(config)
        .await
        .expect("Failed to start test server");

    // Create client and connect
    let client = InProcessClient::new("127.0.0.1", server.info.port).with_key(&server.info.key);

    let mut connection = client.connect().await.expect("Failed to connect to server");

    // Test basic echo
    let test_data = b"Hello, Rosh!";
    connection
        .send(test_data)
        .await
        .expect("Failed to send data");

    let mut buf = vec![0u8; 1024];
    let n = connection
        .receive(&mut buf)
        .await
        .expect("Failed to receive data");

    assert_eq!(&buf[..n], test_data);

    // Clean up
    connection.close().await.ok();
    server.shutdown().await.ok();
}

/// Test that client handles missing required arguments
/// This test needs the actual binary, so we use subprocess
#[tokio::test]
async fn test_client_invalid_connection() {
    // Test with direct connection (requires --key)
    let output = Command::new(env!("CARGO_BIN_EXE_rosh"))
        .args(["localhost:2022"])
        .output()
        .await
        .expect("Failed to run client");

    // Client should exit with error
    assert!(!output.status.success());

    // The error should mention the missing key
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--key required") || stderr.contains("key"),
        "Expected error message about missing key, got: {stderr}"
    );
}

/// Integration test for state synchronization components
#[cfg(test)]
mod state_sync_tests {
    use rosh_state::StateSynchronizer;
    use rosh_terminal::TerminalState;

    #[test]
    fn test_state_sync_roundtrip() {
        // Create server and client synchronizers
        let initial_state = TerminalState::new(80, 24);
        let mut server_sync = StateSynchronizer::new(initial_state.clone(), true);
        let mut client_sync = StateSynchronizer::new(initial_state, false);

        // Make a change on the server
        let mut new_state = server_sync.current_state().clone();
        new_state.cursor_x = 10;
        new_state.cursor_y = 5;

        // Generate update from server
        let update = server_sync.update_state(new_state).unwrap();
        assert!(update.is_some());

        // Apply update to client
        let update = update.unwrap();
        let ack = client_sync.apply_update(update).unwrap();

        // Verify synchronization
        assert_eq!(ack, 1);
        assert_eq!(client_sync.current_state().cursor_x, 10);
        assert_eq!(client_sync.current_state().cursor_y, 5);
    }

    #[test]
    fn test_delta_compression() {
        use rosh_state::diff::StateDiff;

        let state1 = TerminalState::new(80, 24);
        let mut state2 = state1.clone();

        // Make small changes
        state2.cursor_x = 5;
        state2.cursor_y = 10;

        // Generate diff
        let diff = StateDiff::generate(&state1, &state2).unwrap();

        // Verify diff captures changes
        assert!(diff.cursor_change.is_some());
        if let Some(cursor) = &diff.cursor_change {
            assert_eq!(cursor.x, 5);
            assert_eq!(cursor.y, 10);
        }
        assert!(diff.dimension_change.is_none());

        // Apply diff
        let restored = diff.apply(&state1).unwrap();
        assert_eq!(restored.cursor_x, state2.cursor_x);
        assert_eq!(restored.cursor_y, state2.cursor_y);
    }
}

/// Integration tests for network components
#[cfg(test)]
mod network_tests {
    use rosh_crypto::{create_cipher, generate_key, CipherAlgorithm, NonceGenerator};
    use rosh_network::{Message, RoshTransportConfig};

    #[test]
    fn test_message_crypto_roundtrip() {
        // Test full encryption/decryption flow
        let key = generate_key(CipherAlgorithm::ChaCha20Poly1305).unwrap();
        let cipher = create_cipher(CipherAlgorithm::ChaCha20Poly1305, &key).unwrap();
        let mut nonce_gen = NonceGenerator::new(false);

        // Test different message types
        let messages = vec![
            Message::Ping,
            Message::Input(b"Test input".to_vec()),
            Message::Resize(100, 40),
            Message::StateRequest,
        ];

        for msg in messages {
            // Serialize
            let serialized = msg.to_bytes().unwrap();

            // Encrypt
            let nonce = nonce_gen.next_nonce();
            let encrypted = cipher.encrypt(&nonce, &serialized, &[]).unwrap();

            // Decrypt
            let decrypted = cipher.decrypt(&nonce, &encrypted, &[]).unwrap();

            // Deserialize
            let restored = Message::from_bytes(&decrypted).unwrap();

            assert_eq!(format!("{msg:?}"), format!("{:?}", restored));
        }
    }

    #[tokio::test]
    async fn test_transport_config() {
        use std::time::Duration;

        // Test default config
        let config = RoshTransportConfig::default();

        // Just verify it has reasonable defaults
        assert!(config.keep_alive_interval > Duration::from_secs(0));
        assert!(config.max_idle_timeout > Duration::from_secs(0));
    }
}

/// Test terminal emulation components
#[cfg(test)]
mod terminal_tests {
    use rosh_terminal::{Terminal, TerminalState};

    #[test]
    fn test_terminal_basic() {
        let mut terminal = Terminal::new(80, 24);

        // Test basic text input
        terminal.process(b"Hello, World!");
        let snapshot = terminal.snapshot();
        assert_eq!(snapshot.cursor_x, 13);

        // Test newline
        terminal.process(b"\n");
        let snapshot = terminal.snapshot();
        assert_eq!(snapshot.cursor_x, 0);
        assert_eq!(snapshot.cursor_y, 1);

        // Test carriage return
        terminal.process(b"Test\r");
        let snapshot = terminal.snapshot();
        assert_eq!(snapshot.cursor_x, 0);
    }

    #[test]
    fn test_terminal_state_dimensions() {
        let state = TerminalState::new(80, 24);

        // Initial size
        assert_eq!(state.width, 80);
        assert_eq!(state.height, 24);

        // Create new state with different size
        let state2 = TerminalState::new(100, 30);
        assert_eq!(state2.width, 100);
        assert_eq!(state2.height, 30);
    }

    #[test]
    fn test_escape_sequences() {
        let mut terminal = Terminal::new(80, 24);

        // Test cursor movement
        terminal.process(b"\x1b[5;10H"); // Move to row 5, col 10
        let snapshot = terminal.snapshot();
        assert_eq!(snapshot.cursor_x, 9); // 0-indexed
        assert_eq!(snapshot.cursor_y, 4); // 0-indexed

        // Test clear screen
        terminal.process(b"\x1b[2J");
        // Screen should be cleared
    }
}

/// Test cryptographic components
#[cfg(test)]
mod crypto_tests {
    use rosh_crypto::*;

    #[test]
    fn test_key_generation_and_encoding() {
        // Test key generation for each algorithm
        let algorithms = vec![
            CipherAlgorithm::Aes128Gcm,
            CipherAlgorithm::ChaCha20Poly1305,
        ];

        for alg in algorithms {
            let key = generate_key(alg).unwrap();
            assert_eq!(key.len(), alg.key_size());

            // Test encoding/decoding
            let encoded = encode_key(&key);
            let decoded = decode_key(&encoded).unwrap();
            assert_eq!(key, decoded);
        }
    }

    #[test]
    fn test_session_info_serialization() {
        let session_info = SessionInfo {
            port: 8080,
            key: encode_key(&[0u8; 16]),
            algorithm: CipherAlgorithm::Aes128Gcm,
        };

        // Test connect string format
        let connect_str = session_info.to_connect_string();
        assert!(connect_str.starts_with("ROSH CONNECT"));

        // Test parsing
        let parsed = SessionInfo::from_connect_string(&connect_str).unwrap();
        assert_eq!(parsed.port, session_info.port);
        assert_eq!(parsed.key, session_info.key);
        assert_eq!(parsed.algorithm, session_info.algorithm);
    }
}
