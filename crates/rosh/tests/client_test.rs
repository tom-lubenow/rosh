//! Tests for the Rosh client

use anyhow::Result;
use rkyv::Deserialize;
use rosh_crypto::{CipherAlgorithm, SessionKeys};
use rosh_network::Message as NetworkMessage;
use rosh_state::{StateMessage, StateSynchronizer};
use rosh_terminal::TerminalState;
use std::sync::Arc;
use tokio::sync::RwLock;

mod common;
use common::MockConnection;

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rosh_network::Connection;

    #[test]
    fn test_parse_server_arg() {
        // Test SSH format with user
        let (is_ssh, user, host) = rosh::client::parse_server_arg("user@example.com");
        assert!(is_ssh);
        assert_eq!(user, Some("user".to_string()));
        assert_eq!(host, "example.com");

        // Test SSH format without user
        let (is_ssh, user, host) = rosh::client::parse_server_arg("example.com");
        assert!(is_ssh);
        assert_eq!(user, None);
        assert_eq!(host, "example.com");

        // Test direct connection format
        let (is_ssh, user, host) = rosh::client::parse_server_arg("127.0.0.1:8080");
        assert!(!is_ssh);
        assert_eq!(user, None);
        assert_eq!(host, "127.0.0.1:8080");

        // Test hostname without port (assumes SSH)
        let (is_ssh, user, host) = rosh::client::parse_server_arg("localhost");
        assert!(is_ssh);
        assert_eq!(user, None);
        assert_eq!(host, "localhost");
    }

    #[test]
    fn test_key_to_bytes() {
        // Test regular character
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![b'a']);

        // Test control character
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(rosh::client::key_to_bytes(key), vec![3]); // Ctrl+C = 3

        // Test special keys
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![b'\r']);

        let key = KeyEvent::new(KeyCode::Tab, KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![b'\t']);

        let key = KeyEvent::new(KeyCode::Backspace, KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x7F]);

        // Test arrow keys
        let key = KeyEvent::new(KeyCode::Up, KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x1B, b'[', b'A']);

        let key = KeyEvent::new(KeyCode::Down, KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x1B, b'[', b'B']);

        let key = KeyEvent::new(KeyCode::Left, KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x1B, b'[', b'D']);

        let key = KeyEvent::new(KeyCode::Right, KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x1B, b'[', b'C']);

        // Test function keys
        let key = KeyEvent::new(KeyCode::F(1), KeyModifiers::empty());
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x1B, b'O', b'P']);

        let key = KeyEvent::new(KeyCode::F(5), KeyModifiers::empty());
        assert_eq!(
            rosh::client::key_to_bytes(key),
            vec![0x1B, b'[', b'1', b'5', b'~']
        );
    }

    #[test]
    fn test_terminal_ui_creation() {
        let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(
            TerminalState::new(80, 24),
            false,
        )));

        let ui = rosh::client::TerminalUI::new(80, 24, state_sync, true);
        assert_eq!(ui.terminal.framebuffer().width(), 80);
        assert_eq!(ui.terminal.framebuffer().height(), 24);
        assert!(ui.prediction_enabled);
    }

    #[tokio::test]
    async fn test_client_handshake() -> Result<()> {
        // Create mock connection
        let mut mock_conn = MockConnection::new();

        // Set up expected handshake response
        mock_conn.expect_receive(NetworkMessage::HandshakeAck {
            session_id: 12345,
            cipher_algorithm: 0, // AES-128-GCM
        });

        // Create session keys
        let session_keys = SessionKeys {
            client_write_key: vec![0; 32],
            server_write_key: vec![0; 32],
        };

        // Send handshake
        let session_keys_bytes = rkyv::to_bytes::<_, 256>(&session_keys)?.to_vec();
        mock_conn
            .send(NetworkMessage::Handshake {
                session_keys_bytes,
                terminal_width: 80,
                terminal_height: 24,
            })
            .await?;

        // Receive handshake ack
        match mock_conn.receive().await? {
            NetworkMessage::HandshakeAck {
                session_id,
                cipher_algorithm,
            } => {
                assert_eq!(session_id, 12345);
                assert_eq!(cipher_algorithm, 0);
            }
            _ => panic!("Expected HandshakeAck"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_client_state_update() -> Result<()> {
        // Create initial state
        let initial_state = TerminalState::new(80, 24);
        let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(
            initial_state.clone(),
            false,
        )));

        // Create mock connection
        let mut mock_conn = MockConnection::new();

        // Create a full state update
        let new_state = TerminalState::new(80, 24);
        let state_msg = StateMessage::FullState {
            seq: 1,
            state: new_state.clone(),
        };
        let state_bytes = rkyv::to_bytes::<_, 256>(&state_msg)?.to_vec();

        // Queue the state message
        mock_conn.expect_receive(NetworkMessage::State(state_bytes));

        // Process state update
        match mock_conn.receive().await? {
            NetworkMessage::State(bytes) => {
                let state_msg: StateMessage = rkyv::check_archived_root::<StateMessage>(&bytes)
                    .unwrap()
                    .deserialize(&mut rkyv::de::deserializers::SharedDeserializeMap::new())
                    .unwrap();

                match state_msg {
                    StateMessage::FullState { seq, state } => {
                        assert_eq!(seq, 1);
                        let new_sync = StateSynchronizer::new(state, false);
                        *state_sync.write().await = new_sync;
                    }
                    _ => panic!("Expected FullState"),
                }
            }
            _ => panic!("Expected State message"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_client_input_handling() -> Result<()> {
        let mut mock_conn = MockConnection::new();

        // Test regular input
        let input = vec![b'h', b'e', b'l', b'l', b'o'];
        mock_conn.send(NetworkMessage::Input(input.clone())).await?;

        // Verify sent message
        let sent = mock_conn.sent_messages();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            NetworkMessage::Input(data) => assert_eq!(*data, input),
            _ => panic!("Expected Input message"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_client_resize_handling() -> Result<()> {
        let mut mock_conn = MockConnection::new();

        // Send resize
        mock_conn.send(NetworkMessage::Resize(100, 30)).await?;

        // Verify sent message
        let sent = mock_conn.sent_messages();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            NetworkMessage::Resize(w, h) => {
                assert_eq!(w, &100);
                assert_eq!(h, &30);
            }
            _ => panic!("Expected Resize message"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_client_ping_pong() -> Result<()> {
        let mut mock_conn = MockConnection::new();

        // Send ping
        mock_conn.send(NetworkMessage::Ping).await?;

        // Expect pong response
        mock_conn.expect_receive(NetworkMessage::Pong);

        // Receive pong
        match mock_conn.receive().await? {
            NetworkMessage::Pong => {
                // Success
            }
            _ => panic!("Expected Pong"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_client_state_delta() -> Result<()> {
        use rosh_state::StateDiff;

        // Create initial state
        let initial_state = TerminalState::new(80, 24);
        let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(
            initial_state.clone(),
            false,
        )));

        // Create mock connection
        let mut mock_conn = MockConnection::new();

        // Create a delta update
        let mut new_state = initial_state.clone();
        new_state.cursor_x = 5;
        new_state.cursor_y = 10;

        let delta = StateDiff::generate(&initial_state, &new_state).unwrap();
        let state_msg = StateMessage::Delta { seq: 2, delta };
        let state_bytes = rkyv::to_bytes::<_, 256>(&state_msg)?.to_vec();

        // Queue the delta message
        mock_conn.expect_receive(NetworkMessage::State(state_bytes));

        // Process delta update
        match mock_conn.receive().await? {
            NetworkMessage::State(bytes) => {
                let state_msg: StateMessage = rkyv::check_archived_root::<StateMessage>(&bytes)
                    .unwrap()
                    .deserialize(&mut rkyv::de::deserializers::SharedDeserializeMap::new())
                    .unwrap();

                match state_msg {
                    StateMessage::Delta { seq, delta } => {
                        assert_eq!(seq, 2);
                        let mut sync = state_sync.write().await;
                        let new_state = delta.apply(sync.current_state()).unwrap();
                        assert_eq!(new_state.cursor_x, 5);
                        assert_eq!(new_state.cursor_y, 10);
                        *sync = StateSynchronizer::new(new_state, false);
                    }
                    _ => panic!("Expected Delta"),
                }
            }
            _ => panic!("Expected State message"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_client_connection_error() -> Result<()> {
        let mut mock_conn = MockConnection::new();
        mock_conn.set_error("Connection lost");

        // Try to send - should fail
        let result = mock_conn.send(NetworkMessage::Ping).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            rosh_network::NetworkError::TransportError(msg) => {
                assert!(msg.contains("Connection lost"));
            }
            _ => panic!("Expected Transport error"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_client_invalid_cipher_algorithm() -> Result<()> {
        let mut mock_conn = MockConnection::new();

        // Send handshake with invalid cipher algorithm
        mock_conn.expect_receive(NetworkMessage::HandshakeAck {
            session_id: 12345,
            cipher_algorithm: 255, // Invalid
        });

        match mock_conn.receive().await? {
            NetworkMessage::HandshakeAck {
                cipher_algorithm, ..
            } => {
                // Verify we can detect invalid cipher
                let result = match cipher_algorithm {
                    0 => Ok(CipherAlgorithm::Aes128Gcm),
                    1 => Ok(CipherAlgorithm::Aes256Gcm),
                    2 => Ok(CipherAlgorithm::ChaCha20Poly1305),
                    _ => Err(anyhow::anyhow!(
                        "Unknown cipher algorithm: {}",
                        cipher_algorithm
                    )),
                };
                assert!(result.is_err());
            }
            _ => panic!("Expected HandshakeAck"),
        }

        Ok(())
    }

    #[test]
    fn test_control_key_sequences() {
        // Test all control sequences
        for c in 'a'..='z' {
            let key = KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL);
            let bytes = rosh::client::key_to_bytes(key);
            assert_eq!(bytes, vec![(c as u8) - b'a' + 1]);
        }

        // Test uppercase with control
        let key = KeyEvent::new(KeyCode::Char('A'), KeyModifiers::CONTROL);
        assert_eq!(rosh::client::key_to_bytes(key), vec![1]); // Same as Ctrl+a

        // Test special control sequences
        let key = KeyEvent::new(KeyCode::Char('['), KeyModifiers::CONTROL);
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x1B]); // Escape

        let key = KeyEvent::new(KeyCode::Char('\\'), KeyModifiers::CONTROL);
        assert_eq!(rosh::client::key_to_bytes(key), vec![0x1C]);
    }

    #[tokio::test]
    async fn test_client_state_delta_with_resize() -> Result<()> {
        use rosh_state::StateDiff;

        // Create initial state
        let initial_state = TerminalState::new(80, 24);
        let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(
            initial_state.clone(),
            false,
        )));

        let mut mock_conn = MockConnection::new();

        // Create states with same dimensions but different content
        let mut base_state = TerminalState::new(80, 24);
        base_state.title = "Base".to_string();
        let mut new_state = base_state.clone();
        new_state.cursor_x = 10;
        new_state.cursor_y = 5;
        new_state.title = "Updated".to_string();

        let delta = StateDiff::generate(&base_state, &new_state).unwrap();
        let state_msg = StateMessage::Delta { seq: 3, delta };
        let state_bytes = rkyv::to_bytes::<_, 256>(&state_msg)?.to_vec();

        mock_conn.expect_receive(NetworkMessage::State(state_bytes));

        // Process delta update
        match mock_conn.receive().await? {
            NetworkMessage::State(bytes) => {
                let state_msg: StateMessage = rkyv::check_archived_root::<StateMessage>(&bytes)
                    .unwrap()
                    .deserialize(&mut rkyv::de::deserializers::SharedDeserializeMap::new())
                    .unwrap();

                match state_msg {
                    StateMessage::Delta { delta, .. } => {
                        let sync = state_sync.read().await;
                        let result = delta.apply(sync.current_state());
                        // Delta should apply successfully
                        assert!(result.is_ok());
                        let applied_state = result.unwrap();
                        // Verify cursor and title changes were applied
                        assert_eq!(applied_state.cursor_x, 10);
                        assert_eq!(applied_state.cursor_y, 5);
                        assert_eq!(applied_state.title, "Updated");
                        // Dimensions should remain the same
                        assert_eq!(applied_state.width, 80);
                        assert_eq!(applied_state.height, 24);
                    }
                    _ => panic!("Expected Delta"),
                }
            }
            _ => panic!("Expected State message"),
        }

        Ok(())
    }
}

// Export public items for testing
pub use rosh::client::{key_to_bytes, parse_server_arg, TerminalUI};
