//! UDP hole punching implementation for NAT traversal
//!
//! This module implements a simple UDP hole punching protocol to establish
//! connectivity through NAT before upgrading to QUIC.

use anyhow::{Context, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Magic bytes for hole punch packets
const HOLE_PUNCH_MAGIC: &[u8] = b"ROSH_PUNCH_V1";
const HOLE_PUNCH_ACK_MAGIC: &[u8] = b"ROSH_PUNCH_ACK_V1";

/// Configuration for hole punching
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// Number of punch attempts
    pub attempts: u32,
    /// Interval between punch attempts
    pub interval: Duration,
    /// Total timeout for hole punching
    pub timeout: Duration,
    /// Session key for authentication
    pub session_key: Vec<u8>,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            attempts: 5,
            interval: Duration::from_millis(200),
            timeout: Duration::from_secs(3),
            session_key: vec![],
        }
    }
}

/// Result of hole punching
#[derive(Debug)]
pub struct HolePunchResult {
    /// The UDP socket with established connectivity
    pub socket: UdpSocket,
    /// The peer's actual address (may differ from expected due to NAT)
    pub peer_addr: SocketAddr,
}

/// Perform UDP hole punching as a client
pub async fn punch_hole_client(
    local_addr: SocketAddr,
    server_addr: SocketAddr,
    config: HolePunchConfig,
) -> Result<HolePunchResult> {
    info!("Starting client hole punch to {}", server_addr);

    // Create and bind socket
    let socket =
        UdpSocket::bind(local_addr).with_context(|| format!("Failed to bind to {local_addr}"))?;

    socket.set_nonblocking(true)?;

    // Prepare punch packet with session key
    let mut punch_packet = Vec::with_capacity(HOLE_PUNCH_MAGIC.len() + config.session_key.len());
    punch_packet.extend_from_slice(HOLE_PUNCH_MAGIC);
    punch_packet.extend_from_slice(&config.session_key);

    let start = Instant::now();
    let mut attempt = 0;

    // Send punch packets and wait for ACK
    while attempt < config.attempts && start.elapsed() < config.timeout {
        attempt += 1;
        debug!("Hole punch attempt {} to {}", attempt, server_addr);

        // Send punch packet
        match socket.send_to(&punch_packet, server_addr) {
            Ok(n) => debug!("Sent {} bytes to {}", n, server_addr),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                debug!("Socket would block on send");
            }
            Err(e) => return Err(e).context("Failed to send punch packet"),
        }

        // Try to receive ACK
        let deadline = Instant::now() + config.interval;
        while Instant::now() < deadline {
            let mut buf = vec![0u8; 1024];
            match socket.recv_from(&mut buf) {
                Ok((n, from_addr)) => {
                    debug!("Received {} bytes from {}", n, from_addr);

                    // Verify magic and session key
                    if n >= HOLE_PUNCH_ACK_MAGIC.len() + config.session_key.len()
                        && buf.starts_with(HOLE_PUNCH_ACK_MAGIC)
                        && buf[HOLE_PUNCH_ACK_MAGIC.len()..n] == config.session_key
                    {
                        info!("Hole punch successful! Peer at {}", from_addr);
                        return Ok(HolePunchResult {
                            socket,
                            peer_addr: from_addr,
                        });
                    } else {
                        warn!("Received invalid punch response from {}", from_addr);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available yet
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => {
                    debug!("Error receiving: {}", e);
                    break;
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "Hole punch failed after {} attempts",
        attempt
    ))
}

/// Perform UDP hole punching as a server
pub async fn punch_hole_server(
    socket: UdpSocket,
    expected_session_key: &[u8],
    timeout: Duration,
) -> Result<SocketAddr> {
    info!("Server waiting for hole punch...");

    socket.set_nonblocking(true)?;

    let start = Instant::now();
    let mut ack_packet =
        Vec::with_capacity(HOLE_PUNCH_ACK_MAGIC.len() + expected_session_key.len());
    ack_packet.extend_from_slice(HOLE_PUNCH_ACK_MAGIC);
    ack_packet.extend_from_slice(expected_session_key);

    while start.elapsed() < timeout {
        let mut buf = vec![0u8; 1024];
        match socket.recv_from(&mut buf) {
            Ok((n, from_addr)) => {
                debug!("Server received {} bytes from {}", n, from_addr);

                // Check if it's a valid punch packet
                if n >= HOLE_PUNCH_MAGIC.len() + expected_session_key.len()
                    && buf.starts_with(HOLE_PUNCH_MAGIC)
                    && buf[HOLE_PUNCH_MAGIC.len()..n] == *expected_session_key
                {
                    info!("Valid hole punch from {}, sending ACK", from_addr);

                    // Send ACK back
                    for _ in 0..3 {
                        // Send multiple ACKs to increase reliability
                        match socket.send_to(&ack_packet, from_addr) {
                            Ok(_) => debug!("Sent ACK to {}", from_addr),
                            Err(e) => warn!("Failed to send ACK: {}", e),
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }

                    return Ok(from_addr);
                } else {
                    warn!("Invalid punch packet from {}", from_addr);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => {
                debug!("Error receiving: {}", e);
            }
        }
    }

    Err(anyhow::anyhow!("Hole punch timeout"))
}

/// Helper to get the client's address from SSH_CONNECTION if available
pub fn get_client_addr_from_ssh() -> Option<SocketAddr> {
    if let Ok(ssh_conn) = std::env::var("SSH_CONNECTION") {
        let parts: Vec<&str> = ssh_conn.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(client_ip) = parts[0].parse::<std::net::IpAddr>() {
                if let Ok(client_port) = parts[1].parse::<u16>() {
                    // Use a different port for hole punching to avoid SSH conflict
                    return Some(SocketAddr::new(client_ip, client_port + 10000));
                }
            }
        }
    }
    None
}
