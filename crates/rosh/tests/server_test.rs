//! Tests for the Rosh server

use anyhow::Result;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_starts_one_shot() -> Result<()> {
        // Start server in one-shot mode
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
    async fn test_server_args_parsing() -> Result<()> {
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
    async fn test_server_version() -> Result<()> {
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
    async fn test_server_requires_cert_without_one_shot() -> Result<()> {
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
    async fn test_server_cipher_algorithms() -> Result<()> {
        // Test that all cipher algorithms are accepted
        let ciphers = ["aes-gcm", "aes-256-gcm", "chacha20-poly1305"];

        for cipher in &ciphers {
            let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
                .args(["--bind", "127.0.0.1:0", "--one-shot", "--cipher", cipher])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;

            // Give it a moment to start
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Should start successfully
            assert!(
                server.try_wait()?.is_none(),
                "Server should still be running with cipher {cipher}"
            );

            server.kill().await?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_server_max_sessions_arg() -> Result<()> {
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

        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should start successfully
        assert!(
            server.try_wait()?.is_none(),
            "Server should accept --max-sessions argument"
        );

        server.kill().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_server_log_levels() -> Result<()> {
        let levels = ["trace", "debug", "info", "warn", "error"];

        for level in &levels {
            let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
                .args(["--bind", "127.0.0.1:0", "--one-shot", "--log-level", level])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()?;

            // Give it a moment to start
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Should start successfully
            assert!(
                server.try_wait()?.is_none(),
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
}
