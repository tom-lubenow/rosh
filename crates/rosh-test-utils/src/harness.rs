use anyhow::{Context, Result};
use rosh_pty::Pty;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

pub struct TestHarness {
    temp_dir: TempDir,
    config: crate::TestConfig,
}

pub struct ServerHandle {
    process: Child,
    port: u16,
    address: String,
    log_path: PathBuf,
}

pub struct ClientHandle {
    pub process: Child,
    log_path: PathBuf,
}

pub struct PtyClientHandle {
    pub process: rosh_pty::PtyProcess,
    log_path: PathBuf,
}

impl TestHarness {
    pub fn new(config: crate::TestConfig) -> Result<Self> {
        let temp_dir = TempDir::new()?;
        Ok(Self { temp_dir, config })
    }

    pub async fn spawn_server(&self) -> Result<ServerHandle> {
        let port = self
            .config
            .server_port
            .unwrap_or_else(|| portpicker::pick_unused_port().expect("No free ports"));

        let log_path = self.temp_dir.path().join("server.log");
        let log_file = std::fs::File::create(&log_path)?;

        let binary_path = std::env::var("CARGO_BIN_EXE_rosh-server")
            .or_else(|_| std::env::var("ROSH_SERVER_BIN"))
            .unwrap_or_else(|_| {
                // Try to find in workspace root
                let manifest_dir =
                    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
                let workspace_root = std::path::Path::new(&manifest_dir)
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));

                let release_path = workspace_root.join("target/release/rosh-server");
                let debug_path = workspace_root.join("target/debug/rosh-server");

                if release_path.exists() {
                    release_path.to_string_lossy().to_string()
                } else if debug_path.exists() {
                    debug_path.to_string_lossy().to_string()
                } else {
                    // Last resort - try relative paths
                    if std::path::Path::new("target/debug/rosh-server").exists() {
                        "target/debug/rosh-server".to_string()
                    } else {
                        "rosh-server".to_string()
                    }
                }
            });
        eprintln!("Server binary path: {binary_path}");
        let mut cmd = Command::new(&binary_path);
        cmd.arg("--bind")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--one-shot");

        if self.config.capture_output {
            cmd.stdout(Stdio::from(log_file.try_clone()?))
                .stderr(Stdio::from(log_file));
        } else {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        }

        let mut process = cmd.spawn().context("Failed to spawn rosh-server")?;

        // Wait for server to be ready
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Check if process is still running
        if let Some(status) = process.try_wait()? {
            anyhow::bail!("Server exited early with status: {}", status)
        }

        Ok(ServerHandle {
            process,
            port,
            address: format!("127.0.0.1:{port}"),
            log_path,
        })
    }

    pub async fn spawn_client_with_pty(
        &self,
        server_handle: &ServerHandle,
    ) -> Result<PtyClientHandle> {
        let log_path = self.temp_dir.path().join("client.log");

        // Get the session key from server logs
        let server_key = server_handle.get_key().await?;

        let binary_path = std::env::var("CARGO_BIN_EXE_rosh")
            .or_else(|_| std::env::var("ROSH_CLIENT_BIN"))
            .unwrap_or_else(|_| {
                // Try to find in workspace root
                let manifest_dir =
                    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
                let workspace_root = std::path::Path::new(&manifest_dir)
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));

                let release_path = workspace_root.join("target/release/rosh");
                let debug_path = workspace_root.join("target/debug/rosh");

                if release_path.exists() {
                    release_path.to_string_lossy().to_string()
                } else if debug_path.exists() {
                    debug_path.to_string_lossy().to_string()
                } else {
                    // Last resort - try relative paths
                    if std::path::Path::new("target/debug/rosh").exists() {
                        "target/debug/rosh".to_string()
                    } else {
                        "rosh".to_string()
                    }
                }
            });

        eprintln!("Client binary path: {binary_path}");

        // Create PTY
        let mut pty = Pty::new().context("Failed to create PTY")?;

        // Set a reasonable terminal size
        pty.resize(24, 80)?;

        let mut cmd = Command::new(&binary_path);
        cmd.arg("--key")
            .arg(&server_key)
            .arg(server_handle.address());

        eprintln!(
            "Client command: {} --key {} {}",
            binary_path,
            server_key,
            server_handle.address()
        );

        // Spawn the client process with PTY
        let process = pty
            .spawn(cmd)
            .context("Failed to spawn rosh client with PTY")?;

        Ok(PtyClientHandle { process, log_path })
    }

    pub async fn spawn_client(&self, server_handle: &ServerHandle) -> Result<ClientHandle> {
        let log_path = self.temp_dir.path().join("client.log");
        let log_file = std::fs::File::create(&log_path)?;

        // Get the session key from server logs
        let server_key = server_handle.get_key().await?;

        let binary_path = std::env::var("CARGO_BIN_EXE_rosh")
            .or_else(|_| std::env::var("ROSH_CLIENT_BIN"))
            .unwrap_or_else(|_| {
                // Try to find in workspace root
                let manifest_dir =
                    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
                let workspace_root = std::path::Path::new(&manifest_dir)
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));

                let release_path = workspace_root.join("target/release/rosh");
                let debug_path = workspace_root.join("target/debug/rosh");

                if release_path.exists() {
                    release_path.to_string_lossy().to_string()
                } else if debug_path.exists() {
                    debug_path.to_string_lossy().to_string()
                } else {
                    // Last resort - try relative paths
                    if std::path::Path::new("target/debug/rosh").exists() {
                        "target/debug/rosh".to_string()
                    } else {
                        "rosh".to_string()
                    }
                }
            });
        eprintln!("Client binary path: {binary_path}");
        let mut cmd = Command::new(&binary_path);
        cmd.arg("--key")
            .arg(&server_key)
            .arg(server_handle.address());

        eprintln!(
            "Client command: {} --key {} {}",
            binary_path,
            server_key,
            server_handle.address()
        );

        if self.config.capture_output {
            cmd.stdout(Stdio::from(log_file.try_clone()?))
                .stderr(Stdio::from(log_file));
        } else {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        }

        let process = cmd.spawn().context("Failed to spawn rosh client")?;

        Ok(ClientHandle { process, log_path })
    }

    pub async fn spawn_ssh_client(&self, user: &str, host: &str) -> Result<ClientHandle> {
        let log_path = self.temp_dir.path().join("client.log");
        let log_file = std::fs::File::create(&log_path)?;

        let binary_path = std::env::var("CARGO_BIN_EXE_rosh")
            .or_else(|_| std::env::var("ROSH_CLIENT_BIN"))
            .unwrap_or_else(|_| {
                // Try to find in workspace root
                let manifest_dir =
                    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
                let workspace_root = std::path::Path::new(&manifest_dir)
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));

                let release_path = workspace_root.join("target/release/rosh");
                let debug_path = workspace_root.join("target/debug/rosh");

                if release_path.exists() {
                    release_path.to_string_lossy().to_string()
                } else if debug_path.exists() {
                    debug_path.to_string_lossy().to_string()
                } else {
                    // Last resort - try relative paths
                    if std::path::Path::new("target/debug/rosh").exists() {
                        "target/debug/rosh".to_string()
                    } else {
                        "rosh".to_string()
                    }
                }
            });
        let mut cmd = Command::new(binary_path);
        cmd.arg(format!("{user}@{host}"));

        if self.config.capture_output {
            cmd.stdout(Stdio::from(log_file.try_clone()?))
                .stderr(Stdio::from(log_file));
        } else {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        }

        let process = cmd.spawn().context("Failed to spawn rosh SSH client")?;

        Ok(ClientHandle { process, log_path })
    }

    pub fn temp_dir(&self) -> &TempDir {
        &self.temp_dir
    }
}

impl ServerHandle {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub async fn wait_for_ready(&mut self) -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(10);

        while start.elapsed() < timeout {
            // Check if process is still running
            if let Some(status) = self.process.try_wait()? {
                // Try to read logs for debugging
                let logs = self
                    .read_logs()
                    .await
                    .unwrap_or_else(|_| "No logs available".to_string());
                anyhow::bail!("Server exited with status: {}. Logs:\n{}", status, logs)
            }

            // Check if server is listening by looking for the log message
            if let Ok(logs) = self.read_logs().await {
                if logs.contains("Server listening on") {
                    // Give it a bit more time to fully initialize
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    return Ok(());
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        // Try to read logs for debugging
        let logs = self
            .read_logs()
            .await
            .unwrap_or_else(|_| "No logs available".to_string());
        anyhow::bail!("Server failed to start within timeout. Logs:\n{}", logs)
    }

    pub fn kill(&mut self) -> Result<()> {
        self.process.kill()?;
        Ok(())
    }

    pub async fn read_logs(&self) -> Result<String> {
        match tokio::fs::read_to_string(&self.log_path).await {
            Ok(logs) => Ok(logs),
            Err(e) => {
                eprintln!("Failed to read server logs from {:?}: {}", self.log_path, e);
                Err(e).context("Failed to read server logs")
            }
        }
    }

    pub async fn get_key(&self) -> Result<String> {
        let logs = self.read_logs().await?;
        // Look for ROSH_KEY=... in logs
        for line in logs.lines() {
            if let Some(key_start) = line.find("ROSH_KEY=") {
                let key = &line[key_start + 9..];
                return Ok(key.trim().to_string());
            }
        }
        anyhow::bail!("Could not find server key in logs")
    }
}

impl ClientHandle {
    pub fn kill(&mut self) -> Result<()> {
        self.process.kill()?;
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        Ok(self.process.wait()?)
    }

    pub async fn read_logs(&self) -> Result<String> {
        tokio::fs::read_to_string(&self.log_path)
            .await
            .context("Failed to read client logs")
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

impl PtyClientHandle {
    pub fn kill(&mut self) -> Result<()> {
        self.process.kill()?;
        Ok(())
    }

    pub async fn wait(&mut self) -> Result<i32> {
        Ok(self.process.wait()?)
    }

    pub fn try_wait(&self) -> Result<Option<i32>> {
        self.process.try_wait().map_err(|e| e.into())
    }

    pub async fn read_logs(&self) -> Result<String> {
        // For PTY-based clients, logs might not be in the file
        // We could potentially capture output from the PTY master instead
        // For now, return empty string if file doesn't exist
        match tokio::fs::read_to_string(&self.log_path).await {
            Ok(logs) => Ok(logs),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e).context("Failed to read client logs"),
        }
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}

impl Drop for PtyClientHandle {
    fn drop(&mut self) {
        let _ = self.process.kill();
    }
}
