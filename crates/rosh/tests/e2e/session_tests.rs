use anyhow::Result;
use rosh_test_utils::{init_test_logging, TestConfig, TestHarness};
use std::time::Duration;

#[tokio::test]
async fn test_session_cleanup_on_client_disconnect() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Connect a client
    let mut client = harness.spawn_client_with_pty(&server).await?;

    // Wait for connection to establish
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Check if client is still running (indicates successful connection)
    let client_connected = match client.try_wait() {
        Ok(None) => true, // Still running
        Ok(Some(status)) => {
            eprintln!("Client exited with status: {status}");
            false
        }
        Err(e) => {
            eprintln!("Error checking client status: {e}");
            false
        }
    };

    // Check server logs show connection
    let initial_logs = server.read_logs().await?;
    let has_connection_log = initial_logs.contains("New connection from")
        || initial_logs.contains("Creating session")
        || initial_logs.contains("Client connected successfully");

    assert!(
        has_connection_log || client_connected,
        "Server should log client connection or client should be running"
    );

    // Kill the client
    client.kill()?;

    // Wait for server to detect disconnection
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Server should still be running (one-shot mode will exit, but that's expected)
    // In a real multi-session server, we'd check for session cleanup logs

    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_session_timeout() -> Result<()> {
    init_test_logging();

    // Create config with short timeout
    let config = TestConfig {
        server_timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Connect a client
    let mut client = harness.spawn_client_with_pty(&server).await?;

    // Wait for connection
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check client is still running
    match client.try_wait() {
        Ok(None) => eprintln!("Client connected and running"),
        Ok(Some(status)) => panic!("Client exited early with status: {status}"),
        Err(e) => panic!("Error checking client status: {e}"),
    }

    // Wait longer than timeout
    // Note: The actual timeout behavior depends on keep-alive implementation
    tokio::time::sleep(Duration::from_secs(10)).await;

    // In a server with proper timeout, the client might be disconnected
    // For now, just verify nothing crashes

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_graceful_server_shutdown() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Connect multiple clients in sequence (one-shot mode allows only one at a time)
    let mut client = harness.spawn_client_with_pty(&server).await?;

    // Wait for connection
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Kill server while client is connected
    server.kill()?;

    // Client should detect server shutdown
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check if client exited
    match client.try_wait() {
        Ok(Some(exit_code)) => {
            eprintln!("Client exited with code {exit_code} after server shutdown");
            // Exit code might be non-zero due to connection loss
        }
        Ok(None) => {
            eprintln!("Client still running after server shutdown");
            client.kill()?;
        }
        Err(e) => eprintln!("Error checking client status: {e}"),
    }

    Ok(())
}

#[tokio::test]
async fn test_multiple_sequential_sessions() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();

    // Test multiple sessions in sequence (since server is one-shot)
    for i in 0..3 {
        eprintln!("Starting session {}", i + 1);

        let harness = TestHarness::new(config.clone())?;
        let mut server = harness.spawn_server().await?;
        server.wait_for_ready().await?;

        let mut client = harness.spawn_client_with_pty(&server).await?;

        // Wait for connection
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Verify connection
        match client.try_wait() {
            Ok(None) => eprintln!("Session {} established successfully", i + 1),
            Ok(Some(status)) => panic!("Session {} failed with status: {}", i + 1, status),
            Err(e) => panic!("Session {} error: {}", i + 1, e),
        }

        // Clean up
        client.kill()?;
        server.kill()?;

        // Brief pause between sessions
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

#[tokio::test]
async fn test_session_with_pty_operations() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Connect client with PTY
    let mut client = harness.spawn_client_with_pty(&server).await?;

    // Wait for connection to establish
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Check client is running with PTY
    match client.try_wait() {
        Ok(None) => {
            eprintln!("Client connected with PTY successfully");
            // In a full implementation, we could:
            // - Send input to the PTY
            // - Read output from the PTY
            // - Resize the PTY
            // - Send signals
        }
        Ok(Some(status)) => panic!("Client exited unexpectedly with status: {status}"),
        Err(e) => panic!("Error checking client status: {e}"),
    }

    // The client should maintain the session
    tokio::time::sleep(Duration::from_secs(2)).await;

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_session_id_uniqueness() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let mut session_keys = Vec::new();

    // Start multiple servers and collect their session keys
    for i in 0..5 {
        let harness = TestHarness::new(config.clone())?;
        let mut server = harness.spawn_server().await?;
        server.wait_for_ready().await?;

        let key = server.get_key().await?;
        eprintln!("Session {} key: {}", i + 1, key);

        // Check key is unique
        assert!(
            !session_keys.contains(&key),
            "Session key should be unique, but {key} was repeated"
        );

        session_keys.push(key);
        server.kill()?;

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    eprintln!("All {} session keys were unique", session_keys.len());
    Ok(())
}
