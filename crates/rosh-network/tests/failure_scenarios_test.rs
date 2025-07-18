use rosh_network::{NetworkTransport, RoshTransportConfig};
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_connection_timeout() {
    // This test verifies that connection attempts timeout appropriately
    let config = RoshTransportConfig {
        max_idle_timeout: Duration::from_secs(1),
        keep_alive_interval: Duration::from_millis(100),
        ..Default::default()
    };

    let mut client = NetworkTransport::new_client(config)
        .await
        .expect("Failed to create client");

    // Try to connect to a non-existent server
    let result = timeout(
        Duration::from_secs(2),
        client.connect("127.0.0.1:9999".parse().unwrap()),
    )
    .await;

    // Should timeout or fail to connect
    assert!(result.is_err() || result.unwrap().is_err());
}
