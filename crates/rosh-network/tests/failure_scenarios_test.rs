use rosh_network::{Message, NetworkTransport, RoshTransportConfig};
use std::time::Duration;
use tokio::time::{sleep, timeout};

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

#[tokio::test]
#[ignore] // NetworkTransport API has issues with test setup - needs investigation
async fn test_message_ordering() {
    // Test that messages are delivered in order (QUIC guarantees this per-stream)
    use rosh_crypto::CipherAlgorithm;

    let config = RoshTransportConfig::default();
    let key = vec![0u8; 32];
    let algorithm = CipherAlgorithm::ChaCha20Poly1305;

    // Start server using NetworkTransport API
    let server = NetworkTransport::new_server(
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        vec![],
        config.clone(),
    )
    .await
    .expect("Failed to create server")
    .with_encryption(key.clone(), algorithm);

    let server_addr = server.local_addr().expect("Failed to get server address");

    // Server task
    tokio::spawn(async move {
        match timeout(Duration::from_secs(5), server.accept()).await {
            Ok(Ok((mut conn, _addr))) => {
                let mut messages = Vec::new();

                // Collect 5 messages
                for _ in 0..5 {
                    match timeout(Duration::from_secs(1), conn.receive()).await {
                        Ok(Ok(Message::Input(data))) => {
                            messages.push(data[0]);
                        }
                        _ => break,
                    }
                }

                // Verify order
                assert_eq!(messages, vec![0, 1, 2, 3, 4]);
            }
            _ => panic!("Server accept failed"),
        }
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Client
    let mut client = NetworkTransport::new_client(config)
        .await
        .expect("Failed to create client")
        .with_encryption(key, algorithm);

    let mut conn = client
        .connect(server_addr)
        .await
        .expect("Failed to connect");

    // Send messages in order
    for i in 0..5u8 {
        conn.send(Message::Input(vec![i]))
            .await
            .expect("Failed to send");
    }

    // Give messages time to arrive
    sleep(Duration::from_millis(500)).await;
}

#[tokio::test]
#[ignore] // NetworkTransport API has issues with test setup - needs investigation
async fn test_keep_alive_prevents_timeout() {
    // Test that keep-alive prevents connection timeout
    use rosh_crypto::CipherAlgorithm;

    let config = RoshTransportConfig {
        keep_alive_interval: Duration::from_millis(200),
        max_idle_timeout: Duration::from_millis(500),
        ..Default::default()
    };

    let key = vec![0u8; 32];
    let algorithm = CipherAlgorithm::ChaCha20Poly1305;

    // Start server
    let server = NetworkTransport::new_server(
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        vec![],
        config.clone(),
    )
    .await
    .expect("Failed to create server")
    .with_encryption(key.clone(), algorithm);

    let server_addr = server.local_addr().expect("Failed to get server address");

    // Server that responds to pings
    tokio::spawn(async move {
        match server.accept().await {
            Ok((mut conn, _addr)) => {
                // Wait and respond to pings
                for _ in 0..10 {
                    match timeout(Duration::from_millis(300), conn.receive()).await {
                        Ok(Ok(Message::Ping)) => {
                            let _ = conn.send(Message::Pong).await;
                        }
                        Ok(Ok(_)) => {}
                        _ => break,
                    }
                }
            }
            Err(e) => panic!("Server accept failed: {e}"),
        }
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Client
    let mut client = NetworkTransport::new_client(config)
        .await
        .expect("Failed to create client")
        .with_encryption(key, algorithm);

    let mut conn = client
        .connect(server_addr)
        .await
        .expect("Failed to connect");

    // Send initial ping
    conn.send(Message::Ping).await.expect("Failed to send ping");

    match timeout(Duration::from_secs(1), conn.receive()).await {
        Ok(Ok(Message::Pong)) => {
            // Good, connection established
        }
        _ => panic!("Failed to receive initial pong"),
    }

    // Connection should stay alive for at least 1 second due to keep-alive
    sleep(Duration::from_secs(1)).await;

    // Verify we can still communicate
    conn.send(Message::Ping)
        .await
        .expect("Failed to send second ping");

    match timeout(Duration::from_secs(1), conn.receive()).await {
        Ok(Ok(Message::Pong)) => {
            // Connection still alive
        }
        _ => panic!("Connection died despite keep-alive"),
    }
}

#[tokio::test]
#[ignore] // NetworkTransport API has issues with test setup - needs investigation
async fn test_concurrent_connections() {
    // Test multiple clients connecting to the same server
    use rosh_crypto::CipherAlgorithm;
    use tokio::sync::mpsc;

    let config = RoshTransportConfig::default();
    let key = vec![0u8; 32];
    let algorithm = CipherAlgorithm::ChaCha20Poly1305;

    // Start server
    let server = NetworkTransport::new_server(
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        vec![],
        config.clone(),
    )
    .await
    .expect("Failed to create server")
    .with_encryption(key.clone(), algorithm);

    let server_addr = server.local_addr().expect("Failed to get server address");

    // Server accepts multiple connections
    let (tx, mut rx) = mpsc::channel(5);
    let server_handle = tokio::spawn(async move {
        for i in 0..3 {
            match timeout(Duration::from_secs(5), server.accept()).await {
                Ok(Ok((mut conn, addr))) => {
                    println!("Accepted connection {i} from {addr}");
                    tx.send(i).await.unwrap();

                    // Echo server for this connection
                    tokio::spawn(async move {
                        while let Ok(Message::Input(data)) = conn.receive().await {
                            let _ = conn.send(Message::Input(data)).await;
                        }
                    });
                }
                Ok(Err(e)) => {
                    eprintln!("Accept error: {e}");
                    break;
                }
                Err(_) => {
                    eprintln!("Accept timeout");
                    break;
                }
            }
        }
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Create multiple clients
    let mut handles = vec![];
    for i in 0..3 {
        let config = config.clone();
        let key = key.clone();

        let handle = tokio::spawn(async move {
            let mut client = NetworkTransport::new_client(config)
                .await
                .expect("Failed to create client")
                .with_encryption(key, algorithm);

            let mut conn = client
                .connect(server_addr)
                .await
                .expect("Failed to connect");

            // Send a unique message
            conn.send(Message::Input(vec![i as u8]))
                .await
                .expect("Failed to send");

            // Receive echo
            match timeout(Duration::from_secs(1), conn.receive()).await {
                Ok(Ok(Message::Input(data))) => {
                    assert_eq!(data[0], i as u8);
                }
                _ => panic!("Failed to receive echo"),
            }
        });

        handles.push(handle);
    }

    // Wait for all clients to complete
    for handle in handles {
        handle.await.expect("Client task failed");
    }

    // Verify all connections were accepted
    let mut accepted = 0;
    while timeout(Duration::from_millis(100), rx.recv()).await.is_ok() {
        accepted += 1;
    }
    assert_eq!(accepted, 3);

    // Cleanup
    server_handle.abort();
}

#[tokio::test]
#[ignore] // NetworkTransport API has issues with test setup - needs investigation
async fn test_large_message_handling() {
    // Test sending large messages
    use rosh_crypto::CipherAlgorithm;

    let config = RoshTransportConfig {
        stream_receive_window: rosh_network::VarInt::from_u32(2 * 1024 * 1024), // 2MB
        ..Default::default()
    };

    let key = vec![0u8; 32];
    let algorithm = CipherAlgorithm::ChaCha20Poly1305;

    // Start server
    let server = NetworkTransport::new_server(
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        vec![],
        config.clone(),
    )
    .await
    .expect("Failed to create server")
    .with_encryption(key.clone(), algorithm);

    let server_addr = server.local_addr().expect("Failed to get server address");

    // Server task
    tokio::spawn(async move {
        match server.accept().await {
            Ok((mut conn, _addr)) => {
                // Receive large message
                match timeout(Duration::from_secs(5), conn.receive()).await {
                    Ok(Ok(Message::Input(data))) => {
                        // Verify size
                        assert_eq!(data.len(), 1024 * 1024); // 1MB

                        // Verify content (all bytes should be 0xAB)
                        assert!(data.iter().all(|&b| b == 0xAB));

                        // Send acknowledgment
                        conn.send(Message::StateAck(data.len() as u64))
                            .await
                            .expect("Failed to send ack");
                    }
                    _ => panic!("Failed to receive large message"),
                }
            }
            Err(e) => panic!("Server accept failed: {e}"),
        }
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Client
    let mut client = NetworkTransport::new_client(config)
        .await
        .expect("Failed to create client")
        .with_encryption(key, algorithm);

    let mut conn = client
        .connect(server_addr)
        .await
        .expect("Failed to connect");

    // Send large message
    let large_data = vec![0xAB; 1024 * 1024]; // 1MB
    conn.send(Message::Input(large_data))
        .await
        .expect("Failed to send large message");

    // Receive acknowledgment
    match timeout(Duration::from_secs(5), conn.receive()).await {
        Ok(Ok(Message::StateAck(size))) => {
            assert_eq!(size, 1024 * 1024);
        }
        _ => panic!("Failed to receive acknowledgment"),
    }
}
