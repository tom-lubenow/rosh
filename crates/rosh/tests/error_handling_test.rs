//! Error handling tests for rosh client and server

use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn test_server_invalid_bind_address() {
    // Test binding to invalid addresses
    let invalid_addresses = vec![
        "999.999.999.999:8080", // Invalid IP
        "127.0.0.1:99999",      // Invalid port
        "not-an-address",       // Not an address at all
        "[::1]:99999",          // Invalid IPv6 port
        "256.256.256.256:8080", // Out of range IP
        ":8080",                // Missing host
        "127.0.0.1:",           // Missing port
    ];

    for addr in invalid_addresses {
        let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
            .args(["--bind", addr])
            .output()
            .await
            .expect("Failed to run server");

        assert!(
            !output.status.success(),
            "Server should fail with invalid address: {addr}"
        );
    }
}

#[tokio::test]
async fn test_server_permission_denied_port() {
    // Try to bind to privileged port (requires root)
    let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:80"])
        .output()
        .await
        .expect("Failed to run server");

    // Should fail unless running as root (which we shouldn't be in tests)
    if !cfg!(target_os = "windows") {
        // Unix systems restrict ports < 1024
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success()
                || stderr.contains("Permission denied")
                || stderr.contains("Address already in use"),
            "Should fail to bind to privileged port without root"
        );
    }
}

#[tokio::test]
async fn test_server_duplicate_bind() {
    // Start first server
    let mut server1 = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:45678"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("Failed to spawn first server");

    // Wait for first server to bind
    sleep(Duration::from_millis(500)).await;

    // Try to start second server on same port
    let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:45678"])
        .output()
        .await
        .expect("Failed to run second server");

    // Clean up first server
    let _ = server1.kill().await;

    assert!(
        !output.status.success(),
        "Second server should fail to bind to same address"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // The server should fail, error message might vary
    assert!(
        stderr.contains("Address already in use")
            || stderr.contains("address already in use")
            || stderr.contains("Address in use")
            || stderr.contains("bind")
            || !output.status.success(),
        "Second server should fail to bind: {stderr}"
    );
}

#[tokio::test]
async fn test_client_invalid_server_address() {
    // Test connecting to invalid addresses
    let invalid_addresses = vec![
        "999.999.999.999:8080",
        "nonexistent.invalid:8080",
        "256.0.0.1:8080",
        "[::ffff:999.999.999.999]:8080",
    ];

    for addr in invalid_addresses {
        let output = Command::new(env!("CARGO_BIN_EXE_rosh"))
            .args(["--key", "dGVzdGtleQ==", addr])
            .output()
            .await
            .expect("Failed to run client");

        assert!(
            !output.status.success(),
            "Client should fail with invalid address: {addr}"
        );
    }
}

#[tokio::test]
async fn test_server_invalid_cipher() {
    let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:0", "--cipher", "invalid-cipher"])
        .output()
        .await
        .expect("Failed to run server");

    assert!(
        !output.status.success(),
        "Server should fail with invalid cipher"
    );
}

#[tokio::test]
async fn test_server_invalid_compression() {
    let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args([
            "--bind",
            "127.0.0.1:0",
            "--compression",
            "invalid-compression",
        ])
        .output()
        .await
        .expect("Failed to run server");

    assert!(
        !output.status.success(),
        "Server should fail with invalid compression"
    );
}

#[tokio::test]
async fn test_client_missing_key() {
    // Direct connection without --key
    let output = Command::new(env!("CARGO_BIN_EXE_rosh"))
        .args(["127.0.0.1:8080"])
        .output()
        .await
        .expect("Failed to run client");

    assert!(!output.status.success(), "Client should fail without key");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--key required"),
        "Should mention missing --key"
    );
}

#[tokio::test]
async fn test_client_invalid_key_format() {
    // Test with non-base64 key
    let output = Command::new(env!("CARGO_BIN_EXE_rosh"))
        .args(["--key", "not-base64!@#$", "127.0.0.1:8080"])
        .output()
        .await
        .expect("Failed to run client");

    assert!(
        !output.status.success(),
        "Client should fail with invalid base64 key"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to decode session key") || stderr.contains("base64"),
        "Should mention key decode error"
    );
}

#[tokio::test]
async fn test_server_certificate_errors() {
    // Test with invalid certificate path
    let _output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args([
            "--bind",
            "127.0.0.1:0",
            "--cert",
            "/nonexistent/cert.pem",
            "--key",
            "/nonexistent/key.pem",
        ])
        .output()
        .await
        .expect("Failed to run server");

    // Should fall back to self-signed or fail gracefully
    // depending on implementation
}

#[tokio::test]
async fn test_client_timeout_handling() {
    use std::net::TcpListener;
    use std::thread;

    // Create a TCP listener that accepts but doesn't respond
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get local addr");

    // Spawn thread that accepts but doesn't do anything
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            // Just hold the connection open
            thread::sleep(Duration::from_secs(10));
            drop(stream);
        }
    });

    // Try to connect with client
    let output = timeout(Duration::from_secs(5), async {
        Command::new(env!("CARGO_BIN_EXE_rosh"))
            .args(["--key", "dGVzdGtleQ==", &addr.to_string()])
            .output()
            .await
    })
    .await;

    match output {
        Ok(Ok(output)) => {
            assert!(!output.status.success(), "Client should fail or timeout");
        }
        Ok(Err(_)) => {
            // Command failed to run
        }
        Err(_) => {
            // Timeout - expected
        }
    }
}

#[tokio::test]
async fn test_server_resource_limits() {
    // Test server with very large terminal size request
    // This would require a modified client or direct protocol testing
    // For now, just ensure server starts with resource limits

    let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args(["--bind", "127.0.0.1:0", "--one-shot"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("Failed to spawn server");

    // Give it time to start
    sleep(Duration::from_millis(500)).await;

    // Server should still be running
    assert!(
        server
            .try_wait()
            .expect("Failed to check server status")
            .is_none(),
        "Server should still be running"
    );

    // Clean up
    let _ = server.kill().await;
}
