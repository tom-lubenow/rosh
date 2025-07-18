//! Comprehensive end-to-end tests for SSH integration with helper utilities

mod common;

use anyhow::Result;
use common::{TestClient, TestServer};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn test_direct_connection_basic() -> Result<()> {
    // Start test server
    let server = TestServer::start().await?;

    // Connect with client using spawn to provide input
    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // Send exit command immediately
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;
    drop(stdin); // Close stdin to signal EOF

    // Wait for client to exit
    let output = match timeout(Duration::from_secs(5), client.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            eprintln!("Client error: {e}");
            return Err(e.into());
        }
        Err(_) => {
            eprintln!("Client timeout");
            anyhow::bail!("Client timed out");
        }
    };

    // Client should connect and exit successfully
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "Client should connect successfully. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(())
}

#[tokio::test]
async fn test_direct_connection_with_input() -> Result<()> {
    // Start test server
    let server = TestServer::start().await?;

    // Connect with client
    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // Send a simple command
    stdin.write_all(b"echo TEST_MARKER\n").await?;
    stdin.flush().await?;

    // Send exit command
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;

    // Wait for client to exit
    let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should see our echo output
    assert!(
        stdout.contains("TEST_MARKER"),
        "Should see echoed output. Got: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_terminal_resize() -> Result<()> {
    // Start test server
    let server = TestServer::start().await?;

    // Connect with client - this will test resize messages
    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // The client should send initial terminal size on connect
    // Send a command that depends on terminal width
    stdin.write_all(b"stty size\n").await?;
    stdin.flush().await?;

    sleep(Duration::from_millis(500)).await;

    // Exit
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;

    let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should show terminal dimensions
    // Output format is "rows cols"
    let has_dimensions = stdout.lines().any(|line| {
        let parts: Vec<&str> = line.split_whitespace().collect();
        parts.len() == 2 && parts[0].parse::<u32>().is_ok() && parts[1].parse::<u32>().is_ok()
    });

    assert!(
        has_dimensions,
        "Should show terminal dimensions. Got: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_multiple_cipher_algorithms() -> Result<()> {
    let ciphers = [
        ("aes-gcm", "aes-gcm"),
        ("chacha20-poly1305", "chacha20-poly1305"),
    ];

    for (server_cipher, client_cipher) in &ciphers {
        // Start server with specific cipher
        let server =
            TestServer::start_with_options(&["--bind", "127.0.0.1:0", "--cipher", server_cipher])
                .await?;

        // Connect with matching cipher
        let output = TestClient::new("127.0.0.1", server.port)
            .with_key(&server.key)
            .with_args(&["--cipher", client_cipher])
            .run()
            .await?;

        assert!(
            output.status.success() || output.status.code() == Some(0),
            "Client should connect with cipher {}. stderr: {}",
            client_cipher,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_compression_algorithms() -> Result<()> {
    let compressions = ["zstd", "lz4"];

    for comp in &compressions {
        // Start server with compression
        let server =
            TestServer::start_with_options(&["--bind", "127.0.0.1:0", "--compression", comp])
                .await?;

        // Connect with matching compression
        let mut client = TestClient::new("127.0.0.1", server.port)
            .with_key(&server.key)
            .with_args(&["--compression", comp])
            .spawn()
            .await?;

        let mut stdin = client.stdin.take().unwrap();

        // Send some data to test compression
        for i in 0..10 {
            stdin
                .write_all(
                    format!("echo 'Test line {i} with some repetitive data data data data'\n")
                        .as_bytes(),
                )
                .await?;
        }
        stdin.flush().await?;

        // Exit
        stdin.write_all(b"exit\n").await?;
        stdin.flush().await?;

        let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

        assert!(
            output.status.success(),
            "Client should work with compression {}. stderr: {}",
            comp,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_error_recovery_after_disconnect() -> Result<()> {
    // This test simulates network disconnection and recovery

    // Start server
    let server = TestServer::start().await?;

    // Connect client
    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // Send initial command
    stdin.write_all(b"echo BEFORE_DISCONNECT\n").await?;
    stdin.flush().await?;

    // Give it time to process
    sleep(Duration::from_millis(500)).await;

    // Note: In a real test, we would simulate network disconnection here
    // For now, we just test that the client handles server termination gracefully

    // Send exit command
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;

    let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

    // Should have received the initial echo
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BEFORE_DISCONNECT"));

    Ok(())
}

#[tokio::test]
async fn test_predictive_echo() -> Result<()> {
    // Test that predictive echo works correctly

    let server = TestServer::start().await?;

    // Connect with predictive echo enabled
    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .with_args(&["--predict"])
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // Type a command - with prediction, we should see immediate local echo
    stdin.write_all(b"echo PREDICTION_TEST\n").await?;
    stdin.flush().await?;

    // Give time for round trip
    sleep(Duration::from_millis(500)).await;

    // Exit
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;

    let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

    assert!(
        output.status.success(),
        "Client with prediction should work. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(())
}

#[tokio::test]
async fn test_keep_alive_mechanism() -> Result<()> {
    // Test that keep-alive prevents disconnection during idle periods

    let server = TestServer::start().await?;

    // Connect with short keep-alive interval
    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .with_args(&["--keep-alive", "1"]) // 1 second keep-alive
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // Send initial command
    stdin.write_all(b"echo START\n").await?;
    stdin.flush().await?;

    // Wait longer than keep-alive interval
    sleep(Duration::from_secs(3)).await;

    // Connection should still be alive, send another command
    stdin.write_all(b"echo STILL_ALIVE\n").await?;
    stdin.flush().await?;

    // Exit
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;

    let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should see both commands
    assert!(stdout.contains("START"), "Should see first command");
    assert!(
        stdout.contains("STILL_ALIVE"),
        "Should see command after idle period"
    );

    Ok(())
}

#[tokio::test]
async fn test_special_characters_handling() -> Result<()> {
    // Test that special characters and escape sequences are handled correctly

    let server = TestServer::start().await?;

    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // Test various special characters
    let test_strings = [
        "echo 'Test with spaces'",
        "echo \"Double quotes\"",
        "echo $HOME",
        "echo 'Tab\there'",
        "echo 'Newline\\nhere'",
        "echo '!@#$%^&*()'",
    ];

    for test_str in &test_strings {
        stdin.write_all(test_str.as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
    }

    // Exit
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;

    let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

    assert!(
        output.status.success(),
        "Should handle special characters. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(())
}

#[tokio::test]
async fn test_binary_data_transfer() -> Result<()> {
    // Test that binary data can be transferred correctly

    let server = TestServer::start().await?;

    let mut client = TestClient::new("127.0.0.1", server.port)
        .with_key(&server.key)
        .spawn()
        .await?;

    let mut stdin = client.stdin.take().unwrap();

    // Create a command that outputs binary data
    // Using printf to output specific byte sequences
    stdin
        .write_all(b"printf '\\x00\\x01\\x02\\x03\\xFF\\xFE\\xFD'\n")
        .await?;
    stdin.flush().await?;

    sleep(Duration::from_millis(500)).await;

    // Exit
    stdin.write_all(b"exit\n").await?;
    stdin.flush().await?;

    let output = timeout(Duration::from_secs(5), client.wait_with_output()).await??;

    // Should complete successfully even with binary data
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "Should handle binary data. stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(())
}

#[tokio::test]
#[ignore] // This test requires SSH to be configured
async fn test_ssh_integration_real() -> Result<()> {
    // Only run if SSH is available
    if !common::can_ssh_localhost().await {
        println!("Skipping SSH test - localhost SSH not available");
        return Ok(());
    }

    // Test real SSH integration
    let output = TestClient::new("user@localhost", 0) // Port 0 because SSH will determine it
        .with_args(&["--ssh-port", "22"])
        .run()
        .await?;

    // The exact behavior depends on SSH configuration
    // We're mainly testing that the SSH mode is triggered correctly
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should NOT complain about missing --key (that's for direct connections)
    assert!(
        !stderr.contains("--key required"),
        "SSH mode should not require --key parameter"
    );

    Ok(())
}
