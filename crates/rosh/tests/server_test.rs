//! Tests for the Rosh server
//!
//! This module contains both in-process tests (fast) and subprocess tests (for binary validation)

use anyhow::Result;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

mod common;
mod test_helpers;

#[cfg(test)]
mod in_process_tests {
    use super::*;
    use crate::test_helpers::{
        start_test_server as start_in_process_server, TestClient as InProcessClient,
        TestServerConfig,
    };

    #[tokio::test]
    async fn test_server_accepts_connections() -> Result<()> {
        // Start in-process server
        let config = TestServerConfig::default();
        let server = start_in_process_server(config).await?;

        // Connect multiple clients
        for i in 0..3 {
            let client =
                InProcessClient::new("127.0.0.1", server.info.port).with_key(&server.info.key);

            let mut conn = client.connect().await?;

            // Send test data
            let data = format!("Client {i} data").into_bytes();
            conn.send(&data).await?;

            // Receive echo
            let mut buf = vec![0u8; 1024];
            let n = conn.receive(&mut buf).await?;
            assert_eq!(&buf[..n], &data);

            conn.close().await.ok();
        }

        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_server_handles_large_data() -> Result<()> {
        let config = TestServerConfig::default();
        let server = start_in_process_server(config).await?;

        let client = InProcessClient::new("127.0.0.1", server.info.port).with_key(&server.info.key);

        let mut conn = client.connect().await?;

        // Send large data
        let large_data = vec![b'x'; 10_000];
        conn.send(&large_data).await?;

        // Receive in chunks
        let mut received = Vec::new();
        let mut buf = vec![0u8; 1024];

        while received.len() < large_data.len() {
            let n = conn.receive(&mut buf).await?;
            received.extend_from_slice(&buf[..n]);
        }

        assert_eq!(received, large_data);

        conn.close().await.ok();
        server.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod binary_tests {
    use super::*;

    #[tokio::test]
    async fn test_server_binary_starts_one_shot() -> Result<()> {
        // Test the actual binary in one-shot mode
        let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args(["--bind", "127.0.0.1:0", "--one-shot"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = server.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);

        // Read server output
        let mut port = None;
        let mut key = None;
        let mut line = String::new();

        timeout(Duration::from_secs(10), async {
            while reader.read_line(&mut line).await? > 0 {
                let trimmed = line.trim();
                if trimmed.starts_with("ROSH_PORT=") {
                    port = Some(trimmed.strip_prefix("ROSH_PORT=").unwrap().parse::<u16>()?);
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

        assert!(port.is_some(), "Server didn't provide port");
        assert!(key.is_some(), "Server didn't provide key");
        assert!(port.unwrap() > 0, "Port should be valid");
        assert!(!key.unwrap().is_empty(), "Key should not be empty");

        // Kill the server
        server.kill().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_server_binary_args_parsing() -> Result<()> {
        // Test help output
        let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .arg("--help")
            .output()
            .await?;

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Rosh server"));
        assert!(stdout.contains("--bind"));
        assert!(stdout.contains("--cert"));
        assert!(stdout.contains("--key"));

        Ok(())
    }

    #[tokio::test]
    async fn test_server_binary_version() -> Result<()> {
        let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .arg("--version")
            .output()
            .await?;

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Version output might just be "rosh" without "-server"
        assert!(stdout.contains("rosh") || stdout.contains("0.1."));

        Ok(())
    }

    #[tokio::test]
    async fn test_server_binary_requires_cert_without_one_shot() -> Result<()> {
        // Try to start server without cert/key and without --one-shot
        let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args(["--bind", "127.0.0.1:0"])
            .output()
            .await?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("required") || stderr.contains("--cert"),
            "Should require cert without --one-shot"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_server_binary_cipher_algorithms() -> Result<()> {
        // Test that all cipher algorithms are accepted by the binary
        let ciphers = ["aes-gcm", "aes-256-gcm", "chacha20-poly1305"];

        for cipher in &ciphers {
            let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
                .args(["--bind", "127.0.0.1:0", "--one-shot", "--cipher", cipher])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;

            // Check server started by reading its output
            let stdout = server.stdout.take().unwrap();
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();

            // Wait for server to indicate it's ready
            let ready = timeout(Duration::from_secs(2), async {
                while reader.read_line(&mut line).await? > 0 {
                    if line.contains("ROSH_PORT=") || line.contains("Listening") {
                        return Ok::<_, anyhow::Error>(true);
                    }
                    line.clear();
                }
                Ok(false)
            })
            .await??;

            assert!(
                ready || server.try_wait()?.is_none(),
                "Server should start successfully with cipher {cipher}"
            );

            server.kill().await?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_server_binary_max_sessions_arg() -> Result<()> {
        let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args([
                "--bind",
                "127.0.0.1:0",
                "--one-shot",
                "--max-sessions",
                "50",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        // Check server started by reading its output
        let stdout = server.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        // Wait for server to indicate it's ready
        let ready = timeout(Duration::from_secs(2), async {
            while reader.read_line(&mut line).await? > 0 {
                if line.contains("ROSH_PORT=") || line.contains("Listening") {
                    return Ok::<_, anyhow::Error>(true);
                }
                line.clear();
            }
            Ok(false)
        })
        .await??;

        assert!(
            ready || server.try_wait()?.is_none(),
            "Server should accept --max-sessions argument"
        );

        server.kill().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_server_binary_log_levels() -> Result<()> {
        let levels = ["trace", "debug", "info", "warn", "error"];

        for level in &levels {
            let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
                .args(["--bind", "127.0.0.1:0", "--one-shot", "--log-level", level])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;

            // Check server started by reading its output
            let stdout = server.stdout.take().unwrap();
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();

            // Wait for server to indicate it's ready
            let ready = timeout(Duration::from_secs(2), async {
                while reader.read_line(&mut line).await? > 0 {
                    if line.contains("ROSH_PORT=") || line.contains("Listening") {
                        return Ok::<_, anyhow::Error>(true);
                    }
                    line.clear();
                }
                Ok(false)
            })
            .await??;

            assert!(
                ready || server.try_wait()?.is_none(),
                "Server should accept log level {level}"
            );

            server.kill().await?;
        }

        Ok(())
    }
}

// Unit tests for server internal functions
#[cfg(test)]
mod unit_tests {
    use rosh_crypto::CipherAlgorithm;

    #[test]
    fn test_cipher_algorithm_values() {
        // Verify cipher algorithm enum values match what server expects
        assert_eq!(CipherAlgorithm::Aes128Gcm as u8, 0);
        assert_eq!(CipherAlgorithm::Aes256Gcm as u8, 1);
        assert_eq!(CipherAlgorithm::ChaCha20Poly1305 as u8, 2);
    }

    #[test]
    fn test_server_config_defaults() {
        use super::test_helpers::TestServerConfig;
        use std::time::Duration;

        let config = TestServerConfig::default();
        assert_eq!(config._max_sessions, 100);
        assert_eq!(config._session_timeout, Duration::from_secs(300));
        assert!(config._one_shot);
        assert!(config.compression.is_none());
    }
}
