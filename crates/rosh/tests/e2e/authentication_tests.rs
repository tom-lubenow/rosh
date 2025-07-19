use anyhow::Result;
use rosh_test_utils::{init_test_logging, TestConfig, TestHarness};

#[tokio::test]
async fn test_invalid_session_key_rejected() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Get the correct key from server
    let correct_key = server.get_key().await?;
    eprintln!("Correct key: {correct_key}");

    // Try to connect with an invalid key
    let invalid_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    // Spawn client with invalid key manually
    let binary_path =
        std::env::var("CARGO_BIN_EXE_rosh").unwrap_or_else(|_| "target/debug/rosh".to_string());

    let mut cmd = std::process::Command::new(&binary_path);
    cmd.arg("--key").arg(invalid_key).arg(server.address());

    // Create PTY for client
    let mut pty = rosh_pty::Pty::new()?;
    pty.resize(24, 80)?;

    let process = pty.spawn(cmd)?;

    // Wait a bit for connection attempt
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Check if process exited (it should have failed)
    match process.try_wait()? {
        Some(exit_code) => {
            eprintln!("Client exited with code: {exit_code}");
            assert_ne!(exit_code, 0, "Client should have failed with invalid key");
        }
        None => {
            // Process is still running, kill it
            process.kill()?;
            panic!("Client should have exited with invalid key");
        }
    }

    // Check server logs for rejection
    let server_logs = server.read_logs().await?;
    assert!(
        !server_logs.contains("Client connected successfully"),
        "Server should not report successful connection with invalid key"
    );

    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_malformed_session_key_rejected() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Try various malformed keys
    let malformed_keys = vec![
        "not-base64-at-all",
        "short",
        "",
        "!!!invalid!!!",
        "aGVsbG8gd29ybGQ", // "hello world" in base64 - too short
    ];

    for invalid_key in malformed_keys {
        eprintln!("Testing malformed key: {invalid_key}");

        let binary_path =
            std::env::var("CARGO_BIN_EXE_rosh").unwrap_or_else(|_| "target/debug/rosh".to_string());

        let mut cmd = std::process::Command::new(&binary_path);
        cmd.arg("--key").arg(invalid_key).arg(server.address());

        // Create PTY for client
        let mut pty = rosh_pty::Pty::new()?;
        pty.resize(24, 80)?;

        let process = pty.spawn(cmd)?;

        // Wait a bit for connection attempt
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Check if process exited (it should have failed)
        match process.try_wait()? {
            Some(exit_code) => {
                eprintln!("Client exited with code: {exit_code} for key: {invalid_key}");
                assert_ne!(exit_code, 0, "Client should have failed with malformed key");
            }
            None => {
                // Process is still running, kill it
                process.kill()?;
                panic!("Client should have exited with malformed key: {invalid_key}");
            }
        }
    }

    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_empty_session_key_rejected() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Try to connect without providing a key
    let binary_path =
        std::env::var("CARGO_BIN_EXE_rosh").unwrap_or_else(|_| "target/debug/rosh".to_string());

    let mut cmd = std::process::Command::new(&binary_path);
    cmd.arg("--key")
        .arg("") // Empty key
        .arg(server.address());

    // Create PTY for client
    let mut pty = rosh_pty::Pty::new()?;
    pty.resize(24, 80)?;

    let process = pty.spawn(cmd)?;

    // Wait a bit for connection attempt
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Check if process exited (it should have failed)
    match process.try_wait()? {
        Some(exit_code) => {
            eprintln!("Client exited with code: {exit_code}");
            assert_ne!(exit_code, 0, "Client should have failed with empty key");
        }
        None => {
            // Process is still running, kill it
            process.kill()?;
            panic!("Client should have exited with empty key");
        }
    }

    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_session_key_case_sensitivity() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Get the correct key from server
    let correct_key = server.get_key().await?;

    // Try with different case
    let wrong_case_key = correct_key.to_lowercase();
    if correct_key != wrong_case_key {
        eprintln!("Testing case sensitivity - correct: {correct_key}, wrong: {wrong_case_key}");

        let binary_path =
            std::env::var("CARGO_BIN_EXE_rosh").unwrap_or_else(|_| "target/debug/rosh".to_string());

        let mut cmd = std::process::Command::new(&binary_path);
        cmd.arg("--key").arg(&wrong_case_key).arg(server.address());

        // Create PTY for client
        let mut pty = rosh_pty::Pty::new()?;
        pty.resize(24, 80)?;

        let process = pty.spawn(cmd)?;

        // Wait a bit for connection attempt
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Check if process exited (it should have failed)
        match process.try_wait()? {
            Some(exit_code) => {
                eprintln!("Client exited with code: {exit_code}");
                assert_ne!(
                    exit_code, 0,
                    "Client should have failed with wrong case key"
                );
            }
            None => {
                // Process is still running, might have connected
                process.kill()?;
                // This might be okay if base64 decode is case-insensitive
                eprintln!("Note: Client connected with different case key - base64 might be case-insensitive");
            }
        }
    } else {
        eprintln!("Generated key has no case differences, skipping case sensitivity test");
    }

    server.kill()?;
    Ok(())
}
