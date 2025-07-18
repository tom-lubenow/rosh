//! Integration test for AES-256-GCM cipher

use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

#[tokio::test]
async fn test_aes256_gcm_server_accepts_cipher() {
    // Test that server accepts AES-256-GCM cipher option
    let mut server = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args([
            "--bind",
            "127.0.0.1:0",
            "--one-shot",
            "--cipher",
            "aes-256-gcm",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("Failed to spawn server with AES-256-GCM");

    let stdout = server.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // Server should start successfully and output port/key
    let mut found_port = false;
    let mut found_key = false;
    let mut line = String::new();

    let result = timeout(Duration::from_secs(5), async {
        while reader.read_line(&mut line).await.unwrap() > 0 {
            if line.trim().starts_with("ROSH_PORT=") {
                found_port = true;
            } else if line.trim().starts_with("ROSH_KEY=") {
                found_key = true;
            }
            if found_port && found_key {
                break;
            }
            line.clear();
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;

    // Clean up
    let _ = server.kill().await;

    // Verify server started successfully with AES-256-GCM
    assert!(result.is_ok(), "Server should start within timeout");
    assert!(
        found_port && found_key,
        "Server should output port and key when using AES-256-GCM"
    );
}

#[tokio::test]
async fn test_invalid_cipher_rejected() {
    // Test that server rejects invalid cipher option
    let output = Command::new(env!("CARGO_BIN_EXE_rosh-server"))
        .args([
            "--bind",
            "127.0.0.1:0",
            "--one-shot",
            "--cipher",
            "invalid-cipher",
        ])
        .output()
        .await
        .expect("Failed to run server");

    assert!(
        !output.status.success(),
        "Server should fail with invalid cipher"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value") || stderr.contains("possible values"),
        "Should report invalid cipher value"
    );
}
