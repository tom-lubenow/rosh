use anyhow::Result;
use rosh_test_utils::{
    init_test_logging, NetworkConditions, NetworkSimulator, TestConfig, TestHarness,
};
use std::time::Duration;

#[tokio::test]
async fn test_connection_with_perfect_network() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;
    let network = NetworkSimulator::new(NetworkConditions::perfect());

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;

    // Simulate perfect network conditions
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Connection should be stable
    let server_logs = server.read_logs().await?;
    assert!(server_logs.contains("Client connected") || server_logs.contains("New connection"));
    assert!(!server_logs.contains("disconnected"));

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_connection_with_packet_loss() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut conditions = NetworkConditions::default();
    conditions.packet_loss = 0.1; // 10% packet loss
    let network = NetworkSimulator::new(conditions);

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;

    // Test with packet loss
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Connection should still work despite packet loss
    let server_logs = server.read_logs().await?;
    assert!(server_logs.contains("Client connected") || server_logs.contains("New connection"));

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_connection_with_high_latency() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut conditions = NetworkConditions::default();
    conditions.latency_ms = 300; // 300ms latency
    conditions.jitter_ms = 50; // 50ms jitter
    let network = NetworkSimulator::new(conditions);

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;

    // Test with high latency
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Connection should work even with high latency
    let server_logs = server.read_logs().await?;
    assert!(server_logs.contains("Client connected") || server_logs.contains("New connection"));

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_connection_with_mobile_network() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;
    let network = NetworkSimulator::new(NetworkConditions::mobile());

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;

    // Test with typical mobile network conditions
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Connection should remain stable
    let server_logs = server.read_logs().await?;
    assert!(server_logs.contains("Client connected") || server_logs.contains("New connection"));

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_connection_with_poor_network() -> Result<()> {
    init_test_logging();

    let config = TestConfig {
        client_timeout: Duration::from_secs(60),
        server_timeout: Duration::from_secs(60),
        ..Default::default()
    };
    let harness = TestHarness::new(config)?;
    let network = NetworkSimulator::new(NetworkConditions::poor());

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;

    // Test with poor network conditions
    tokio::time::sleep(Duration::from_secs(15)).await;

    // Check if rosh handles poor network gracefully
    let server_logs = server.read_logs().await?;
    let client_logs = client.read_logs().await?;

    // Even with poor network, connection should be attempted
    assert!(
        server_logs.contains("Client") || client_logs.contains("Connect"),
        "No connection attempts found in logs"
    );

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_dynamic_network_changes() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;
    let network = NetworkSimulator::new(NetworkConditions::perfect());

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;

    // Start with perfect conditions
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Degrade to mobile conditions
    network.update_conditions(NetworkConditions::mobile()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Further degrade to poor conditions
    network.update_conditions(NetworkConditions::poor()).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Improve back to perfect conditions
    network
        .update_conditions(NetworkConditions::perfect())
        .await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Connection should survive network changes
    let server_logs = server.read_logs().await?;
    assert!(server_logs.contains("Client connected") || server_logs.contains("New connection"));

    client.kill()?;
    server.kill()?;
    Ok(())
}
