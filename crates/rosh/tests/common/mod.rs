//! Common test utilities for rosh integration tests

use anyhow::Result;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

/// Test server instance that cleans up on drop
pub struct TestServer {
    process: Option<tokio::process::Child>,
    pub port: u16,
    pub key: String,
}

impl TestServer {
    /// Start a new test server
    pub async fn start() -> Result<Self> {
        eprintln!("Starting test server...");

        // Build server binary
        Command::new("cargo")
            .args(["build", "--bin", "rosh-server"])
            .status()
            .await?;

        eprintln!("Server binary built, spawning server...");

        let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args(["--bind", "127.0.0.1:0", "--one-shot"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        eprintln!("Server spawned, reading output...");

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

        Ok(TestServer {
            process: Some(server),
            port,
            key,
        })
    }

    /// Start a server with specific options
    pub async fn start_with_options(args: &[&str]) -> Result<Self> {
        // Build server binary
        Command::new("cargo")
            .args(["build", "--bin", "rosh-server"])
            .status()
            .await?;

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

        Ok(TestServer {
            process: Some(server),
            port,
            key,
        })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            // Try to kill the process
            let _ = process.start_kill();
        }
    }
}

/// Test client builder
pub struct TestClient {
    server_addr: String,
    key: Option<String>,
    args: Vec<String>,
}

impl TestClient {
    /// Create a new test client
    pub fn new(host: &str, port: u16) -> Self {
        TestClient {
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

    /// Run the client and return the output
    pub async fn run(self) -> Result<std::process::Output> {
        eprintln!("Running client to connect to {}", self.server_addr);

        // Build client binary
        Command::new("cargo")
            .args(["build", "--bin", "rosh"])
            .status()
            .await?;

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

    /// Spawn the client process
    pub async fn spawn(self) -> Result<tokio::process::Child> {
        eprintln!("Spawning client to connect to {}", self.server_addr);

        // Build client binary
        Command::new("cargo")
            .args(["build", "--bin", "rosh"])
            .status()
            .await?;

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
