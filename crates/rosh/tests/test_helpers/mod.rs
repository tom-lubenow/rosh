//! Test helpers for integration tests that avoid subprocess spawning
//!
//! This module provides in-process test server and client implementations
//! that are faster and more reliable than spawning external processes.

use anyhow::{Context, Result};
use rosh_crypto::CipherAlgorithm;
use rosh_pty::{PtySession, SessionBuilder};
use rosh_state::{CompressionAlgorithm, StateSynchronizer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tracing::{error, info};
use uuid::Uuid;

/// Configuration for the test server
#[derive(Debug, Clone)]
pub struct TestServerConfig {
    pub bind_addr: SocketAddr,
    pub _cipher: CipherAlgorithm,
    pub compression: Option<CompressionAlgorithm>,
    pub _max_sessions: usize,
    pub _session_timeout: Duration,
    pub _one_shot: bool,
}

impl Default for TestServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            _cipher: CipherAlgorithm::Aes128Gcm,
            compression: None,
            _max_sessions: 100,
            _session_timeout: Duration::from_secs(300),
            _one_shot: true,
        }
    }
}

/// Server connection info returned when server starts
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub port: u16,
    pub key: String,
}

/// Handle to a running test server
pub struct TestServerHandle {
    pub info: ServerInfo,
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
}

impl TestServerHandle {
    /// Shutdown the server gracefully
    pub async fn shutdown(self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        self.task.await?
    }
}

/// Session state for a connected client
struct SessionState {
    _pty: PtySession,
    _synchronizer: StateSynchronizer,
    _last_activity: tokio::time::Instant,
}

/// Mock server implementation for testing
pub struct MockServer {
    listener: TcpListener,
    sessions: Arc<RwLock<HashMap<Uuid, SessionState>>>,
    config: TestServerConfig,
    key: Vec<u8>,
}

impl MockServer {
    /// Create a new mock server
    pub async fn new(config: TestServerConfig) -> Result<(Self, ServerInfo)> {
        // Bind to address
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .context("Failed to bind to address")?;

        // Get actual port
        let port = listener.local_addr()?.port();

        // Generate session key (32 bytes for one-shot mode)
        let mut key = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);

        // Encode key for output
        use base64::Engine;
        let key_encoded = base64::engine::general_purpose::STANDARD.encode(&key);

        let info = ServerInfo {
            port,
            key: key_encoded,
        };

        let server = Self {
            listener,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
            key,
        };

        Ok((server, info))
    }

    /// Run the server
    pub async fn run(self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        loop {
            tokio::select! {
                // Accept new connections
                result = self.listener.accept() => {
                    let (stream, addr) = result?;
                    info!("New connection from {}", addr);

                    // Clone what we need for the handler
                    let sessions = self.sessions.clone();
                    let key = self.key.clone();
                    let compression = self.config.compression;

                    // Spawn handler for this connection
                    tokio::spawn(async move {
                        if let Err(e) = handle_mock_connection(
                            stream,
                            sessions,
                            key,
                            compression,
                        ).await {
                            error!("Connection handler error: {}", e);
                        }
                    });
                }

                // Handle shutdown
                _ = &mut shutdown_rx => {
                    info!("Server shutdown requested");
                    break;
                }
            }
        }

        Ok(())
    }
}

/// Handle a mock connection
async fn handle_mock_connection(
    mut stream: TcpStream,
    sessions: Arc<RwLock<HashMap<Uuid, SessionState>>>,
    _key: Vec<u8>,
    _compression: Option<CompressionAlgorithm>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // For testing, we'll use a simple protocol without encryption
    // Read handshake
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;

    // Expect handshake message
    if n > 0 && buf[0] == 0x01 {
        // Simple handshake byte
        // Send acknowledgment
        stream.write_all(&[0x02]).await?;

        // Create session
        let session_id = Uuid::new_v4();
        info!("Created test session {}", session_id);

        // Create PTY session
        let (pty, _rx) = SessionBuilder::new().build().await?;

        // Create state synchronizer
        let initial_state = pty.get_state().await;
        let synchronizer = StateSynchronizer::new(initial_state, true);

        // Store session
        {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.insert(
                session_id,
                SessionState {
                    _pty: pty,
                    _synchronizer: synchronizer,
                    _last_activity: tokio::time::Instant::now(),
                },
            );
        }

        // Run simple echo loop for testing
        let mut buf = vec![0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    // Echo back for testing
                    stream.write_all(&buf[..n]).await?;
                }
                Err(e) => {
                    error!("Read error: {}", e);
                    break;
                }
            }
        }

        // Clean up session
        {
            let mut sessions_guard = sessions.write().await;
            sessions_guard.remove(&session_id);
        }

        info!("Test session {} ended", session_id);
    }

    Ok(())
}

/// Start a test server
pub async fn start_test_server(config: TestServerConfig) -> Result<TestServerHandle> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let (server, info) = MockServer::new(config).await?;

    info!(
        "Test server listening on port {} with key {}",
        info.port, info.key
    );

    // Spawn server task
    let task = tokio::spawn(async move { server.run(shutdown_rx).await });

    Ok(TestServerHandle {
        info,
        shutdown_tx,
        task,
    })
}

/// Test client for integration tests
pub struct TestClient {
    server_addr: String,
    key: Option<String>,
}

impl TestClient {
    /// Create a new test client
    pub fn new(host: &str, port: u16) -> Self {
        TestClient {
            server_addr: format!("{host}:{port}"),
            key: None,
        }
    }

    /// Set the session key
    pub fn with_key(mut self, key: &str) -> Self {
        self.key = Some(key.to_string());
        self
    }

    /// Connect to the test server
    pub async fn connect(self) -> Result<MockConnection> {
        let stream = TcpStream::connect(&self.server_addr)
            .await
            .context("Failed to connect to server")?;

        // Send simple handshake
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;
        stream.write_all(&[0x01]).await?;

        // Read acknowledgment
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 0x02 {
            anyhow::bail!("Invalid handshake response");
        }

        Ok(MockConnection { stream })
    }
}

/// Mock connection for testing
pub struct MockConnection {
    stream: TcpStream,
}

impl MockConnection {
    /// Send data to the server
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.write_all(data).await?;
        Ok(())
    }

    /// Receive data from the server
    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;
        Ok(self.stream.read(buf).await?)
    }

    /// Close the connection
    pub async fn close(mut self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.shutdown().await?;
        Ok(())
    }
}
