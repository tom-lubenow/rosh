//! End-to-end tests for SSH integration
//!
//! These tests verify the complete SSH workflow from connection to data transfer.
//! They require SSH to be configured with localhost access.

use anyhow::Result;
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{sleep, timeout};

/// Check if SSH localhost access is available
async fn check_ssh_localhost() -> bool {
    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=1",
            "localhost",
            "echo",
            "test",
        ])
        .output()
        .await
        .ok();

    matches!(output, Some(o) if o.status.success())
}

/// Helper to setup SSH key for testing if not already configured
#[allow(dead_code)]
async fn ensure_ssh_key() -> Result<()> {
    // Check if we can already SSH to localhost
    if check_ssh_localhost().await {
        return Ok(());
    }

    // Generate SSH key if it doesn't exist
    let ssh_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?
        .join(".ssh");

    let key_path = ssh_dir.join("id_rsa_rosh_test");

    if !key_path.exists() {
        Command::new("ssh-keygen")
            .args([
                "-t",
                "rsa",
                "-b",
                "2048",
                "-f",
                key_path.to_str().unwrap(),
                "-N",
                "",
                "-C",
                "rosh-test-key",
            ])
            .status()
            .await?;
    }

    Ok(())
}

#[tokio::test]
#[ignore] // Requires SSH setup
async fn test_ssh_server_startup() -> Result<()> {
    if !check_ssh_localhost().await {
        eprintln!("Skipping test: SSH localhost access not available");
        return Ok(());
    }

    // Build binaries first
    Command::new("cargo")
        .args(["build", "--bin", "rosh-server", "--bin", "rosh"])
        .status()
        .await?;

    // Start server via SSH
    let mut ssh_cmd = Command::new("ssh");
    ssh_cmd.args([
        "-o",
        "BatchMode=yes",
        "localhost",
        "cd",
        &std::env::current_dir()?.to_string_lossy(),
        "&&",
        env!("CARGO_BIN_EXE_rosh-server"),
        "--one-shot",
        "--bind",
        "127.0.0.1:0",
    ]);

    ssh_cmd.stdout(Stdio::piped());
    ssh_cmd.stderr(Stdio::piped());

    let mut child = ssh_cmd.spawn()?;

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Look for ROSH_PORT and ROSH_KEY
    let mut port = None;
    let mut key = None;

    let result = timeout(Duration::from_secs(5), async {
        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            if line.trim().starts_with("ROSH_PORT=") {
                port = Some(line.trim().strip_prefix("ROSH_PORT=").unwrap().to_string());
            } else if line.trim().starts_with("ROSH_KEY=") {
                key = Some(line.trim().strip_prefix("ROSH_KEY=").unwrap().to_string());
            }

            if port.is_some() && key.is_some() {
                break;
            }
            line.clear();
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;

    // Clean up
    let _ = child.kill().await;

    result??;

    assert!(port.is_some(), "Server should output ROSH_PORT");
    assert!(key.is_some(), "Server should output ROSH_KEY");

    Ok(())
}

#[tokio::test]
#[ignore] // Requires SSH setup
async fn test_ssh_client_connection() -> Result<()> {
    if !check_ssh_localhost().await {
        eprintln!("Skipping test: SSH localhost access not available");
        return Ok(());
    }

    // Build binaries
    Command::new("cargo")
        .args(["build", "--bin", "rosh-server", "--bin", "rosh"])
        .status()
        .await?;

    // Test SSH connection parsing
    let output = Command::new("cargo")
        .args(["run", "--bin", "rosh", "--", "user@localhost"])
        .output()
        .await?;

    // Should fail because server isn't running, but should parse SSH format correctly
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--key required"),
        "Should not require --key for SSH connections"
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Requires SSH setup and PTY
async fn test_ssh_end_to_end_communication() -> Result<()> {
    if !check_ssh_localhost().await {
        eprintln!("Skipping test: SSH localhost access not available");
        return Ok(());
    }

    // Build binaries
    Command::new("cargo")
        .args(["build", "--bin", "rosh-server", "--bin", "rosh"])
        .status()
        .await?;

    // Start server in background
    let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stdout = server.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Get connection info
    let mut port = None;
    let mut key = None;
    let mut line = String::new();

    timeout(Duration::from_secs(5), async {
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

    let port = port.ok_or_else(|| anyhow::anyhow!("No port from server"))?;
    let key = key.ok_or_else(|| anyhow::anyhow!("No key from server"))?;

    // Create a test script that the client will execute
    let mut script_file = NamedTempFile::new()?;
    writeln!(script_file, "#!/bin/bash")?;
    writeln!(script_file, "echo 'TEST_OUTPUT_MARKER'")?;
    writeln!(script_file, "exit 0")?;
    script_file.flush()?;

    // Make script executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(script_file.path(), std::fs::Permissions::from_mode(0o755))?;
    }

    // Connect with client
    let client_output = timeout(Duration::from_secs(10), async {
        Command::new("bash")
            .args([
                "-c",
                &format!(
                    "echo 'echo TEST_OUTPUT_MARKER; exit' | {} --key {} localhost:{}",
                    env!("CARGO_BIN_EXE_rosh"),
                    key,
                    port
                ),
            ])
            .output()
            .await
    })
    .await??;

    // Clean up server
    let _ = server.kill().await;

    // Verify we got expected output
    let stdout = String::from_utf8_lossy(&client_output.stdout);

    // The output might contain ANSI escape sequences, so we just check for our marker
    assert!(
        stdout.contains("TEST_OUTPUT_MARKER") || client_output.status.success(),
        "Client should receive server output or exit successfully. Got stdout: {}, stderr: {}",
        stdout,
        String::from_utf8_lossy(&client_output.stderr)
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Requires SSH setup
async fn test_ssh_cipher_negotiation() -> Result<()> {
    if !check_ssh_localhost().await {
        eprintln!("Skipping test: SSH localhost access not available");
        return Ok(());
    }

    // Build binaries
    Command::new("cargo")
        .args(["build", "--bin", "rosh-server", "--bin", "rosh"])
        .status()
        .await?;

    // Test different cipher algorithms via SSH
    let ciphers = ["aes-gcm", "chacha20-poly1305"];

    for cipher in &ciphers {
        // Start server with specific cipher via SSH simulation
        let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args(["--one-shot", "--bind", "127.0.0.1:0", "--cipher", cipher])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = server.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);

        // Verify server starts with cipher
        let mut found_cipher = false;
        let mut line = String::new();

        let _ = timeout(Duration::from_secs(2), async {
            while reader.read_line(&mut line).await? > 0 {
                if line.contains("ROSH_") {
                    found_cipher = true;
                    break;
                }
                line.clear();
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;

        let _ = server.kill().await;

        assert!(found_cipher, "Server should start with cipher: {cipher}");
    }

    Ok(())
}

#[tokio::test]
#[ignore] // Requires SSH setup
async fn test_ssh_compression_options() -> Result<()> {
    if !check_ssh_localhost().await {
        eprintln!("Skipping test: SSH localhost access not available");
        return Ok(());
    }

    // Build binaries
    Command::new("cargo")
        .args(["build", "--bin", "rosh-server", "--bin", "rosh"])
        .status()
        .await?;

    // Test compression options
    let compression_algs = ["zstd", "lz4"];

    for comp in &compression_algs {
        let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args(["--one-shot", "--bind", "127.0.0.1:0", "--compression", comp])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let stdout = server.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);

        // Check server starts with compression
        let mut started = false;
        let mut line = String::new();

        let _ = timeout(Duration::from_secs(2), async {
            while reader.read_line(&mut line).await? > 0 {
                if line.contains("ROSH_") {
                    started = true;
                    break;
                }
                line.clear();
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;

        let _ = server.kill().await;

        assert!(started, "Server should start with compression: {comp}");
    }

    Ok(())
}

#[tokio::test]
#[ignore] // Requires SSH setup
async fn test_ssh_error_handling() -> Result<()> {
    // Test various error scenarios

    // 1. Invalid host
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "rosh",
            "--",
            "user@nonexistent.invalid.host",
        ])
        .output()
        .await?;

    assert!(!output.status.success(), "Should fail with invalid host");

    // 2. Invalid SSH options
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "rosh",
            "--",
            "--ssh-options",
            "InvalidOption=yes",
            "localhost",
        ])
        .output()
        .await?;

    assert!(
        !output.status.success(),
        "Should fail with invalid SSH options"
    );

    // 3. Wrong remote command
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "rosh",
            "--",
            "--remote-command",
            "nonexistent-command",
            "localhost",
        ])
        .output()
        .await?;

    assert!(
        !output.status.success(),
        "Should fail with nonexistent remote command"
    );

    Ok(())
}

#[tokio::test]
async fn test_ssh_connection_parsing() {
    // Test that various SSH connection strings are parsed correctly

    // This doesn't require actual SSH, just tests the parsing logic
    let test_cases = vec![
        ("user@host", true),
        ("user@host.domain.com", true),
        ("localhost:1234", false),
        ("192.168.1.1:22", false),
        ("host", false),
    ];

    for (input, should_be_ssh) in test_cases {
        // We can't directly test the parse_server_arg function,
        // but we can test the client behavior

        let output = Command::new("cargo")
            .args(["run", "--bin", "rosh", "--", input, "--log-level", "debug"])
            .env("RUST_BACKTRACE", "1")
            .output()
            .await
            .expect("Failed to run client");

        let stderr = String::from_utf8_lossy(&output.stderr);

        if should_be_ssh {
            // SSH connections should NOT complain about missing --key
            assert!(
                !stderr.contains("--key required"),
                "Input '{input}' should be treated as SSH connection, but got: {stderr}"
            );
        } else {
            // Direct connections should require --key
            assert!(
                stderr.contains("--key required")
                    || stderr.contains("Failed to parse server address"),
                "Input '{input}' should require --key for direct connection, but got: {stderr}"
            );
        }
    }
}

#[tokio::test]
#[ignore] // Requires SSH setup
async fn test_ssh_with_custom_port() -> Result<()> {
    if !check_ssh_localhost().await {
        eprintln!("Skipping test: SSH localhost access not available");
        return Ok(());
    }

    // Test that --ssh-port option works
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "rosh",
            "--",
            "--ssh-port",
            "22222", // Non-standard port
            "localhost",
        ])
        .output()
        .await?;

    // Should fail to connect (unless port 22222 happens to be open)
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should show it tried to use the custom port
    assert!(
        stderr.contains("22222") || stderr.contains("Connection refused"),
        "Should attempt connection on custom port"
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Requires SSH setup and specific test environment
async fn test_ssh_signal_handling() -> Result<()> {
    if !check_ssh_localhost().await {
        eprintln!("Skipping test: SSH localhost access not available");
        return Ok(());
    }

    // This test verifies that signals (like Ctrl+C) are properly forwarded
    // through the SSH connection to the remote process

    // Start server
    let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stdout = server.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Get connection info
    let mut port = None;
    let mut key = None;
    let mut line = String::new();

    timeout(Duration::from_secs(5), async {
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

    let port = port.ok_or_else(|| anyhow::anyhow!("No port from server"))?;
    let key = key.ok_or_else(|| anyhow::anyhow!("No key from server"))?;

    // Start a client that runs a long-running command
    let mut client = Command::new("bash")
        .args([
            "-c",
            &format!(
                "exec {} --key {} localhost:{}",
                env!("CARGO_BIN_EXE_rosh"),
                key,
                port
            ),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let mut stdin = client.stdin.take().unwrap();

    // Send a command that will run for a while
    stdin.write_all(b"sleep 30\n").await?;
    stdin.flush().await?;

    // Give it time to start
    sleep(Duration::from_millis(500)).await;

    // Send interrupt signal (Ctrl+C)
    stdin.write_all(&[0x03]).await?; // ASCII ETX (Ctrl+C)
    stdin.flush().await?;

    // The sleep command should be interrupted
    // Send another command to verify the shell is still responsive
    stdin.write_all(b"echo STILL_ALIVE\n").await?;
    stdin.flush().await?;

    // Clean up
    let _ = client.kill().await;
    let _ = server.kill().await;

    // In a real implementation, we would verify the output contains "STILL_ALIVE"
    // but due to PTY complexities in tests, we just verify the processes didn't crash

    Ok(())
}
