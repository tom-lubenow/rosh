use anyhow::Result;
use futures::future::join_all;
use rosh_test_utils::{
    init_test_logging, NetworkConditions, NetworkSimulator, TestConfig, TestHarness,
};
use std::time::Duration;

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Simulate concurrent operations
    let operations = vec![
        tokio::spawn(async {
            // Simulate rapid typing
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }),
        tokio::spawn(async {
            // Simulate terminal resizing
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }),
        tokio::spawn(async {
            // Simulate large pastes
            for _ in 0..5 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }),
    ];

    join_all(operations).await;

    // Connection should remain stable
    let server_logs = server.read_logs().await?;
    assert!(!server_logs.contains("panic"));
    assert!(!server_logs.contains("error"));

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_network_chaos() -> Result<()> {
    init_test_logging();

    let config = TestConfig {
        client_timeout: Duration::from_secs(120),
        server_timeout: Duration::from_secs(120),
        ..Default::default()
    };
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut client = harness.spawn_client(&server).await?;

    // Create chaotic network conditions
    let mut conditions = NetworkConditions::default();
    let network = NetworkSimulator::new(conditions.clone());

    // Randomly change network conditions
    for _ in 0..20 {
        conditions.packet_loss = rand::random::<f64>() * 0.3; // 0-30% loss
        conditions.latency_ms = rand::random::<u64>() % 1000; // 0-1000ms
        conditions.jitter_ms = rand::random::<u64>() % 200; // 0-200ms
        conditions.reorder_probability = rand::random::<f64>() * 0.1; // 0-10%

        network.update_conditions(conditions.clone()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Connection should survive chaos
    let server_logs = server.read_logs().await?;
    let client_logs = client.read_logs().await?;

    assert!(
        !server_logs.contains("fatal") && !client_logs.contains("fatal"),
        "Fatal errors found during network chaos"
    );

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_resource_exhaustion() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let mut clients = Vec::new();

    // Try to exhaust server resources
    for i in 0..50 {
        match harness.spawn_client(&server).await {
            Ok(client) => {
                clients.push(client);
                if i % 10 == 0 {
                    println!("Created {} clients", i + 1);
                }
            }
            Err(e) => {
                println!("Failed to create client {i}: {e}");
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Server should handle resource limits gracefully
    let server_logs = server.read_logs().await?;
    assert!(!server_logs.contains("panic"));

    // Clean up
    for mut client in clients {
        client.kill()?;
    }
    server.kill()?;
    Ok(())
}
