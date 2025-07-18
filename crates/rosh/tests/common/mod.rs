//! Common test utilities for rosh integration tests
//!
//! This module provides two types of test utilities:
//! 1. In-process test servers/clients for fast, reliable testing
//! 2. Subprocess-based testing for end-to-end validation

#![allow(dead_code)]

use anyhow::Result;
use rosh_network::{Connection, Message as NetworkMessage, NetworkError};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

// Note: To use in-process test helpers, import them directly from test_helpers module

/// Test server instance that spawns a real subprocess
/// Use this only when you need to test the actual binary behavior
pub struct SubprocessTestServer {
    process: Option<tokio::process::Child>,
    pub port: u16,
    pub key: String,
}

impl SubprocessTestServer {
    /// Start a new test server subprocess
    /// Only use this when you need to test the actual binary
    pub async fn start() -> Result<Self> {
        eprintln!(
            "Starting subprocess test server (slower, use in-process server when possible)..."
        );

        let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args(["--bind", "127.0.0.1:0", "--one-shot"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        eprintln!("Server subprocess spawned, reading output...");

        let stdout = server.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);

        // Read connection info
        let mut port = None;
        let mut key = None;
        let mut line = String::new();

        timeout(Duration::from_secs(10), async {
            while reader.read_line(&mut line).await? > 0 {
                let trimmed = line.trim();
                eprintln!("Server output: {trimmed}");
                if trimmed.starts_with("ROSH_PORT=") {
                    port = Some(trimmed.strip_prefix("ROSH_PORT=").unwrap().parse()?);
                } else if trimmed.starts_with("ROSH_KEY=") {
                    key = Some(trimmed.strip_prefix("ROSH_KEY=").unwrap().to_string());
                }

                if port.is_some() && key.is_some() {
                    break;
                }
                line.clear();
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let port = port.ok_or_else(|| anyhow::anyhow!("Server didn't provide port"))?;
        let key = key.ok_or_else(|| anyhow::anyhow!("Server didn't provide key"))?;

        eprintln!("Got server port: {port} and key: {key}");

        Ok(SubprocessTestServer {
            process: Some(server),
            port,
            key,
        })
    }

    /// Start a server subprocess with specific options
    pub async fn start_with_options(args: &[&str]) -> Result<Self> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rosh-server"));
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        let mut server = cmd.spawn()?;

        let stdout = server.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);

        // Read connection info
        let mut port = None;
        let mut key = None;
        let mut line = String::new();

        timeout(Duration::from_secs(10), async {
            while reader.read_line(&mut line).await? > 0 {
                let trimmed = line.trim();
                if trimmed.starts_with("ROSH_PORT=") {
                    port = Some(trimmed.strip_prefix("ROSH_PORT=").unwrap().parse()?);
                } else if trimmed.starts_with("ROSH_KEY=") {
                    key = Some(trimmed.strip_prefix("ROSH_KEY=").unwrap().to_string());
                }

                if port.is_some() && key.is_some() {
                    break;
                }
                line.clear();
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let port = port.ok_or_else(|| anyhow::anyhow!("Server didn't provide port"))?;
        let key = key.ok_or_else(|| anyhow::anyhow!("Server didn't provide key"))?;

        Ok(SubprocessTestServer {
            process: Some(server),
            port,
            key,
        })
    }
}

impl Drop for SubprocessTestServer {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            // Try to kill the process
            let _ = process.start_kill();
        }
    }
}

/// Test client builder for subprocess testing
pub struct SubprocessTestClient {
    server_addr: String,
    key: Option<String>,
    args: Vec<String>,
}

impl SubprocessTestClient {
    /// Create a new subprocess test client
    pub fn new(host: &str, port: u16) -> Self {
        SubprocessTestClient {
            server_addr: format!("{host}:{port}"),
            key: None,
            args: Vec::new(),
        }
    }

    /// Set the session key
    pub fn with_key(mut self, key: &str) -> Self {
        self.key = Some(key.to_string());
        self
    }

    /// Add additional arguments
    pub fn with_args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    /// Run the client subprocess and return the output
    pub async fn run(self) -> Result<std::process::Output> {
        eprintln!(
            "Running subprocess client to connect to {}",
            self.server_addr
        );

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rosh"));

        if let Some(key) = self.key {
            eprintln!("Client using key: {key}");
            cmd.args(["--key", &key]);
        }

        for arg in &self.args {
            cmd.arg(arg);
        }

        cmd.arg(&self.server_addr);

        eprintln!("Running client command...");
        Ok(cmd.output().await?)
    }

    /// Spawn the client subprocess
    pub async fn spawn(self) -> Result<tokio::process::Child> {
        eprintln!(
            "Spawning subprocess client to connect to {}",
            self.server_addr
        );

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rosh"));

        if let Some(key) = self.key {
            eprintln!("Client using key: {key}");
            cmd.args(["--key", &key]);
        }

        for arg in &self.args {
            cmd.arg(arg);
        }

        cmd.arg(&self.server_addr);
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        eprintln!("Spawning client process...");
        Ok(cmd.spawn()?)
    }
}

/// Check if we can SSH to localhost
pub async fn can_ssh_localhost() -> bool {
    Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "localhost",
            "echo",
            "test",
        ])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Setup localhost SSH access for testing
#[allow(dead_code)]
pub async fn setup_localhost_ssh() -> Result<()> {
    // Check if already configured
    if can_ssh_localhost().await {
        return Ok(());
    }

    // Get home directory
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;

    let ssh_dir = home.join(".ssh");

    // Create .ssh directory if it doesn't exist
    tokio::fs::create_dir_all(&ssh_dir).await?;

    // Generate test key if needed
    let test_key = ssh_dir.join("id_rsa_rosh_test");
    if !test_key.exists() {
        Command::new("ssh-keygen")
            .args([
                "-t",
                "rsa",
                "-b",
                "2048",
                "-f",
                test_key.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "rosh-test",
            ])
            .status()
            .await?;
    }

    // Add to authorized_keys
    let pub_key_path = ssh_dir.join("id_rsa_rosh_test.pub");
    let authorized_keys = ssh_dir.join("authorized_keys");

    if pub_key_path.exists() {
        let pub_key = tokio::fs::read_to_string(&pub_key_path).await?;
        let mut auth_keys = if authorized_keys.exists() {
            tokio::fs::read_to_string(&authorized_keys).await?
        } else {
            String::new()
        };

        if !auth_keys.contains(pub_key.trim()) {
            if !auth_keys.is_empty() && !auth_keys.ends_with('\n') {
                auth_keys.push('\n');
            }
            auth_keys.push_str(&pub_key);
            tokio::fs::write(&authorized_keys, auth_keys).await?;
        }
    }

    Ok(())
}

/// Wait for a pattern in process output
#[allow(dead_code)]
pub async fn wait_for_output(
    reader: &mut BufReader<tokio::process::ChildStdout>,
    pattern: &str,
    timeout_secs: u64,
) -> Result<String> {
    let mut line = String::new();

    timeout(Duration::from_secs(timeout_secs), async {
        while reader.read_line(&mut line).await? > 0 {
            if line.contains(pattern) {
                return Ok(line.clone());
            }
            line.clear();
        }
        Err(anyhow::anyhow!("Pattern '{}' not found in output", pattern))
    })
    .await?
}

/// Mock connection for testing network message passing
pub struct MockConnection {
    sent_messages: Mutex<Vec<NetworkMessage>>,
    received_messages: Mutex<Vec<NetworkMessage>>,
    error: Mutex<Option<String>>,
}

impl MockConnection {
    pub fn new() -> Self {
        Self {
            sent_messages: Mutex::new(Vec::new()),
            received_messages: Mutex::new(Vec::new()),
            error: Mutex::new(None),
        }
    }

    /// Queue a message to be received
    pub fn expect_receive(&mut self, message: NetworkMessage) {
        self.received_messages.lock().unwrap().push(message);
    }

    /// Set an error to be returned
    pub fn set_error(&mut self, error: &str) {
        *self.error.lock().unwrap() = Some(error.to_string());
    }

    /// Get sent messages
    pub fn sent_messages(&self) -> Vec<NetworkMessage> {
        self.sent_messages.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Connection for MockConnection {
    async fn send(&mut self, message: NetworkMessage) -> Result<(), NetworkError> {
        if let Some(error) = self.error.lock().unwrap().as_ref() {
            return Err(NetworkError::TransportError(error.to_string()));
        }
        self.sent_messages.lock().unwrap().push(message);
        Ok(())
    }

    async fn receive(&mut self) -> Result<NetworkMessage, NetworkError> {
        if let Some(error) = self.error.lock().unwrap().as_ref() {
            return Err(NetworkError::TransportError(error.to_string()));
        }
        let mut messages = self.received_messages.lock().unwrap();
        if messages.is_empty() {
            Err(NetworkError::TransportError(
                "No messages queued".to_string(),
            ))
        } else {
            Ok(messages.remove(0))
        }
    }

    fn clone_box(&self) -> Box<dyn Connection> {
        Box::new(MockConnection {
            sent_messages: Mutex::new(self.sent_messages.lock().unwrap().clone()),
            received_messages: Mutex::new(self.received_messages.lock().unwrap().clone()),
            error: Mutex::new(self.error.lock().unwrap().clone()),
        })
    }
}

// Backward compatibility aliases (deprecated)
#[deprecated(
    note = "Use SubprocessTestServer for subprocess testing or start_in_process_server for fast testing"
)]
pub type TestServer = SubprocessTestServer;

#[deprecated(
    note = "Use SubprocessTestClient for subprocess testing or InProcessClient for fast testing"
)]
pub type TestClient = SubprocessTestClient;
