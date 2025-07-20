use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};
use tracing::{debug, info, warn};

/// Magic bytes for hole punch packets
const HOLE_PUNCH_MAGIC: &[u8] = b"ROSH_PUNCH";
const HOLE_PUNCH_READY: &[u8] = b"ROSH_READY";
const MAX_PUNCH_ATTEMPTS: u32 = 10;
const PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const PUNCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Perform UDP hole punching from client side
/// This serves two purposes:
/// 1. Punches through NAT/firewalls by sending outgoing UDP packets
/// 2. Confirms the server is ready before attempting QUIC connection
pub async fn client_hole_punch(server_addr: SocketAddr, session_key: &[u8]) -> Result<()> {
    info!("Starting UDP hole punch to {}", server_addr);

    // Bind to any available port
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind UDP socket for hole punching")?;

    let local_addr = socket.local_addr()?;
    debug!("Hole punch socket bound to {}", local_addr);

    // Create punch packet with session key prefix for basic validation
    let mut punch_packet = Vec::with_capacity(HOLE_PUNCH_MAGIC.len() + 16);
    punch_packet.extend_from_slice(HOLE_PUNCH_MAGIC);
    punch_packet.extend_from_slice(&session_key[..16.min(session_key.len())]);

    let start = Instant::now();
    let mut attempts = 0;

    // Send punch packets until we get a response or timeout
    loop {
        attempts += 1;
        debug!("Sending hole punch packet {} to {}", attempts, server_addr);

        socket
            .send_to(&punch_packet, server_addr)
            .await
            .context("Failed to send hole punch packet")?;

        // Wait for response with short timeout
        let mut buf = vec![0u8; 256];
        match timeout(PUNCH_INTERVAL, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                if from == server_addr
                    && len >= HOLE_PUNCH_READY.len()
                    && &buf[..HOLE_PUNCH_READY.len()] == HOLE_PUNCH_READY
                {
                    info!(
                        "Server ready confirmation received after {} attempts",
                        attempts
                    );
                    return Ok(());
                }
                debug!("Received non-ready packet from {}: {} bytes", from, len);
            }
            Ok(Err(e)) => {
                warn!("Error receiving hole punch response: {}", e);
            }
            Err(_) => {
                // Timeout - this is expected, continue sending
            }
        }

        // Check overall timeout
        if start.elapsed() > PUNCH_TIMEOUT {
            anyhow::bail!(
                "UDP hole punch timeout after {} attempts. Server may not be ready or UDP is blocked.", 
                attempts
            );
        }

        // Don't send too many packets too quickly
        if attempts >= MAX_PUNCH_ATTEMPTS {
            // Wait a bit longer between batches
            tokio::time::sleep(Duration::from_millis(500)).await;
            attempts = 0;
        }
    }
}

/// Server-side hole punch responder
/// Listens for hole punch packets and responds with ready confirmation
pub async fn server_hole_punch_responder(
    port: u16,
    session_key: &[u8],
    ready_signal: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = UdpSocket::bind(addr)
        .await
        .context("Failed to bind UDP socket for hole punch responder")?;

    info!("Hole punch responder listening on {}", socket.local_addr()?);

    // Wait for ready signal
    let _ = ready_signal.await;
    info!("Server ready, responding to hole punch packets");

    let ready_packet = HOLE_PUNCH_READY;
    let expected_prefix_len = HOLE_PUNCH_MAGIC.len() + 16.min(session_key.len());

    let mut buf = vec![0u8; 256];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                if len >= expected_prefix_len {
                    // Validate magic bytes
                    if &buf[..HOLE_PUNCH_MAGIC.len()] == HOLE_PUNCH_MAGIC {
                        // Validate session key prefix
                        let key_prefix = &buf[HOLE_PUNCH_MAGIC.len()..expected_prefix_len];
                        if key_prefix == &session_key[..16.min(session_key.len())] {
                            debug!("Valid hole punch received from {}, sending ready", from);
                            if let Err(e) = socket.send_to(ready_packet, from).await {
                                warn!("Failed to send ready response: {}", e);
                            }
                        } else {
                            debug!("Invalid session key in hole punch from {}", from);
                        }
                    } else {
                        debug!("Invalid magic in packet from {}", from);
                    }
                } else {
                    debug!("Packet too small from {}: {} bytes", from, len);
                }
            }
            Err(e) => {
                warn!("Error in hole punch responder: {}", e);
                // Continue listening
            }
        }
    }
}
