use anyhow::Result;
use rosh_test_utils::{init_test_logging, TestConfig, TestHarness};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_server_handles_invalid_udp_packets() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Send garbage UDP packets to the server
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr: SocketAddr = server.address().parse()?;

    // Send various invalid packets
    let invalid_packets = vec![
        b"random garbage".to_vec(),
        vec![0xFF; 1000],                   // Large packet of 0xFF
        vec![0x00; 10],                     // Small packet of nulls
        b"GET / HTTP/1.1\r\n\r\n".to_vec(), // HTTP request
        vec![],                             // Empty packet
    ];

    for packet in invalid_packets {
        eprintln!("Sending invalid packet of size: {}", packet.len());
        let _ = socket.send_to(&packet, server_addr).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Wait a bit to see if server crashes
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Server should still be running
    let server_logs = server.read_logs().await?;
    eprintln!("Server logs after invalid packets:\n{server_logs}");

    // Try a valid connection to ensure server is still functional
    let mut client = harness.spawn_client_with_pty(&server).await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Check if client is running (server didn't crash)
    match client.try_wait() {
        Ok(None) => eprintln!("Client connected successfully after invalid packets"),
        Ok(Some(status)) => panic!("Client exited with status {status} - server may have crashed"),
        Err(e) => panic!("Error checking client status: {e}"),
    }

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_server_handles_oversized_messages() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // This test would require more sophisticated message injection
    // For now, we just verify the server stays up with large UDP packets
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr: SocketAddr = server.address().parse()?;

    // Send very large UDP packet (near MTU limit)
    let large_packet = vec![0xAB; 65000];
    eprintln!("Sending oversized packet of {} bytes", large_packet.len());
    let _ = socket.send_to(&large_packet, server_addr).await;

    // Wait to see if server handles it gracefully
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Server should still be running
    let server_logs = server.read_logs().await?;
    assert!(
        server_logs.contains("Server listening on"),
        "Server should still be running after oversized packet"
    );

    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_connection_with_invalid_quic_handshake() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Send a TCP connection attempt (server expects QUIC/UDP)
    match tokio::net::TcpStream::connect(server.address()).await {
        Ok(_) => eprintln!("TCP connection unexpectedly succeeded"),
        Err(e) => eprintln!("TCP connection failed as expected: {e}"),
    }

    // Server should still be running
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let server_logs = server.read_logs().await?;
    assert!(
        server_logs.contains("Server listening on"),
        "Server should still be running after invalid connection attempt"
    );

    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_rapid_connection_attempts() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_addr: SocketAddr = server.address().parse()?;

    // Send many packets rapidly
    eprintln!("Sending rapid UDP packets...");
    for i in 0..100 {
        let packet = format!("packet {i}").into_bytes();
        let _ = socket.send_to(&packet, server_addr).await;
        if i % 10 == 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    // Wait and check server is still healthy
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Try a valid connection
    let mut client = harness.spawn_client_with_pty(&server).await?;
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    match client.try_wait() {
        Ok(None) => eprintln!("Client connected successfully after rapid packets"),
        Ok(Some(status)) => panic!("Client exited with status {status} - server may be unhealthy"),
        Err(e) => panic!("Error checking client status: {e}"),
    }

    client.kill()?;
    server.kill()?;
    Ok(())
}

#[tokio::test]
async fn test_connection_from_wrong_port() -> Result<()> {
    init_test_logging();

    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;

    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;

    // Try connecting to wrong port
    let wrong_port = server.port() + 1;
    let wrong_address = format!("127.0.0.1:{wrong_port}");

    eprintln!("Attempting connection to wrong port: {wrong_address}");

    let binary_path =
        std::env::var("CARGO_BIN_EXE_rosh").unwrap_or_else(|_| "target/debug/rosh".to_string());

    let mut cmd = std::process::Command::new(&binary_path);
    cmd.arg("--key")
        .arg(&server.get_key().await?)
        .arg(&wrong_address);

    let mut pty = rosh_pty::Pty::new()?;
    pty.resize(24, 80)?;

    let process = pty.spawn(cmd)?;

    // Wait for connection attempt
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Client should fail to connect
    match process.try_wait()? {
        Some(exit_code) => {
            eprintln!("Client exited with code: {exit_code}");
            assert_ne!(
                exit_code, 0,
                "Client should fail when connecting to wrong port"
            );
        }
        None => {
            process.kill()?;
            panic!("Client should have exited when connecting to wrong port");
        }
    }

    server.kill()?;
    Ok(())
}
