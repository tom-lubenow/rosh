//! Unit tests for SSH integration functionality

use anyhow::Result;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};

/// Test that we can parse SSH connection strings correctly
#[test]
fn test_ssh_connection_string_parsing() {
    // Test various SSH connection string formats
    let test_cases = vec![
        ("user@host", true, Some("user"), "host"),
        (
            "user@host.example.com",
            true,
            Some("user"),
            "host.example.com",
        ),
        ("user@192.168.1.1", true, Some("user"), "192.168.1.1"),
        ("host", false, None, "host"),
        ("192.168.1.1:22", false, None, "192.168.1.1:22"),
        ("localhost:8080", false, None, "localhost:8080"),
    ];

    for (input, _expected_ssh, _expected_user, _expected_host) in test_cases {
        // We can't directly test the parse_server_arg function from here,
        // but we can verify the behavior through the command line
        println!("Testing: {input}");

        // The actual parsing happens in the client binary
        // For unit tests, we'd need to expose the parsing function
    }
}

/// Test SSH command construction
#[tokio::test]
async fn test_ssh_command_construction() -> Result<()> {
    // Test that SSH commands are constructed correctly

    // This would be tested if we had access to the start_server_via_ssh function
    // For now, we can only test the binary behavior

    Ok(())
}

/// Test that server outputs correct format in one-shot mode
#[tokio::test]
async fn test_server_oneshot_output_format() -> Result<()> {
    let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:0", "--one-shot"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stdout = server.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    let mut found_port = false;
    let mut found_key = false;
    let mut line = String::new();

    // Read output with timeout
    let result = timeout(Duration::from_secs(5), async {
        while reader.read_line(&mut line).await? > 0 {
            let trimmed = line.trim();

            if trimmed.starts_with("ROSH_PORT=") {
                found_port = true;
                // Verify it's a valid port number
                let port_str = trimmed.strip_prefix("ROSH_PORT=").unwrap();
                let port: u16 = port_str
                    .parse()
                    .expect("ROSH_PORT should be a valid port number");
                assert!(port > 0, "Port should be non-zero");
            } else if trimmed.starts_with("ROSH_KEY=") {
                found_key = true;
                // Verify it's base64
                let key_str = trimmed.strip_prefix("ROSH_KEY=").unwrap();
                assert!(!key_str.is_empty(), "Key should not be empty");
                // Basic base64 validation
                assert!(
                    key_str
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='),
                    "Key should be valid base64"
                );
            }

            line.clear();

            if found_port && found_key {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;

    // Clean up
    let _ = server.kill().await;

    result??;

    assert!(found_port, "Server should output ROSH_PORT");
    assert!(found_key, "Server should output ROSH_KEY");

    Ok(())
}

/// Test cipher algorithm parameter handling
#[tokio::test]
async fn test_cipher_algorithm_params() -> Result<()> {
    // Test that server accepts different cipher algorithms
    let ciphers = ["aes-gcm", "chacha20-poly1305"];

    for cipher in &ciphers {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rosh-server"));
        cmd.args(["--bind", "127.0.0.1:0", "--one-shot", "--cipher", cipher]);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Wait a bit for server to start
        sleep(Duration::from_millis(100)).await;

        // Kill the server
        let _ = child.kill().await;

        // Check if it started without errors
        let output = child.wait_with_output().await?;
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Should have started successfully (may have info logs but no errors)
        assert!(
            !stderr.to_lowercase().contains("error")
                || stderr.contains("Server listening")
                || stderr.is_empty(),
            "Server should accept cipher {cipher}: {stderr}"
        );
    }

    Ok(())
}

/// Test compression algorithm parameter handling
#[tokio::test]
async fn test_compression_params() -> Result<()> {
    // Test that server accepts compression algorithms
    let compressions = ["zstd", "lz4"];

    for comp in &compressions {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rosh-server"));
        cmd.args(["--bind", "127.0.0.1:0", "--one-shot", "--compression", comp]);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        // Wait a bit for server to start
        sleep(Duration::from_millis(100)).await;

        // Kill the server
        let _ = child.kill().await;

        // Check if it started without errors
        let output = child.wait_with_output().await?;
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stderr.to_lowercase().contains("error")
                || stderr.contains("Server listening")
                || stderr.is_empty(),
            "Server should accept compression {comp}: {stderr}"
        );
    }

    Ok(())
}

/// Test that client requires --key for direct connections
#[tokio::test]
async fn test_client_requires_key_for_direct() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_rosh"))
        .args(["127.0.0.1:8080"])
        .output()
        .await?;

    assert!(!output.status.success(), "Should fail without --key");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--key required"),
        "Should mention missing --key"
    );

    Ok(())
}

/// Test that client doesn't require --key for SSH connections
#[tokio::test]
async fn test_client_ssh_no_key_required() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_rosh"))
        .args(["user@nonexistent.example.com"])
        .output()
        .await?;

    // Will fail because host doesn't exist, but shouldn't complain about --key
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--key required"),
        "Should not require --key for SSH connections"
    );

    Ok(())
}

/// Test various SSH-style connection strings
/// Test direct connection strings
#[tokio::test]
async fn test_direct_style_connections() -> Result<()> {
    let direct_hosts = vec![
        "localhost:8080",
        "127.0.0.1:22",
        "example.com:2022",
        "192.168.1.1:8888",
    ];

    for host in direct_hosts {
        let output = Command::new(env!("CARGO_BIN_EXE_rosh"))
            .args([host])
            .output()
            .await?;

        let stderr = String::from_utf8_lossy(&output.stderr);

        // Should complain about missing --key
        assert!(
            stderr.contains("--key required") || stderr.contains("Failed to parse"),
            "Host '{host}' should require --key for direct connection"
        );
    }

    Ok(())
}
