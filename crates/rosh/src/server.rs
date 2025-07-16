//! Rosh server implementation

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rkyv::Deserialize;
use rosh_crypto::{CipherAlgorithm, SessionKeys};
use rosh_network::{Message as NetworkMessage, NetworkTransport, RoshTransportConfig, VarInt};
use rosh_pty::{PtySession, SessionBuilder, SessionEvent};
use rosh_state::{CompressionAlgorithm, StateMessage, StateSynchronizer};
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Rosh server - Modern mobile shell server")]
struct Args {
    /// Address to bind to
    #[arg(short, long, default_value = "0.0.0.0:2022")]
    bind: SocketAddr,

    /// Path to server certificate (required unless --one-shot)
    #[arg(short, long, required_unless_present = "one_shot")]
    cert: Option<PathBuf>,

    /// Path to server private key (required unless --one-shot)
    #[arg(short, long, required_unless_present = "one_shot")]
    key: Option<PathBuf>,

    /// Cipher algorithm to use
    #[arg(short = 'a', long, value_enum, default_value = "aes-gcm")]
    cipher: CipherAlgorithm,

    /// Enable compression
    #[arg(long, value_enum)]
    compression: Option<CompressionAlgorithm>,

    /// Keep-alive interval in seconds
    #[arg(long, default_value = "30")]
    keep_alive: u64,

    /// Log level
    #[arg(long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Maximum number of concurrent sessions
    #[arg(long, default_value = "100")]
    max_sessions: usize,

    /// One-shot mode: generate key, serve one connection, then exit
    #[arg(long)]
    one_shot: bool,
}

/// Active session state
struct Session {
    id: Uuid,
    pty_session: PtySession,
    _state_sync: Arc<RwLock<StateSynchronizer>>,
    _client_addr: SocketAddr,
    last_activity: Arc<RwLock<time::Instant>>,
}

/// Server state
struct ServerState {
    sessions: Arc<RwLock<HashMap<Uuid, Arc<Session>>>>,
    max_sessions: usize,
}

impl ServerState {
    fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_sessions,
        }
    }

    async fn add_session(&self, session: Session) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= self.max_sessions {
            anyhow::bail!("Maximum number of sessions reached");
        }
        sessions.insert(session.id, Arc::new(session));
        Ok(())
    }

    async fn remove_session(&self, id: &Uuid) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(id);
    }

    async fn get_session(&self, id: &Uuid) -> Option<Arc<Session>> {
        let sessions = self.sessions.read().await;
        sessions.get(id).cloned()
    }
}

/// Generate a self-signed certificate for one-shot mode
fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{Certificate, CertificateParams, DistinguishedName};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".to_string()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        rcgen::SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];

    let cert = Certificate::from_params(params)
        .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| anyhow::anyhow!("Failed to serialize certificate: {}", e))?;
    let key_pem = cert.serialize_private_key_pem();

    Ok((cert_pem.into_bytes(), key_pem.into_bytes()))
}

pub async fn run() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = match args.log_level {
        LogLevel::Trace => tracing::Level::TRACE,
        LogLevel::Debug => tracing::Level::DEBUG,
        LogLevel::Info => tracing::Level::INFO,
        LogLevel::Warn => tracing::Level::WARN,
        LogLevel::Error => tracing::Level::ERROR,
    };

    // In one-shot mode, only output to stderr
    if args.one_shot {
        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt().with_max_level(log_level).init();
    }

    // Generate session key for one-shot mode
    let session_key = if args.one_shot {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Some(key)
    } else {
        None
    };

    info!("Starting Rosh server on {}", args.bind);

    // Load certificates
    let (cert_chain, private_key) = if args.one_shot {
        // Generate self-signed certificate for one-shot mode
        generate_self_signed_cert()?
    } else {
        // Load from files
        let cert_path = args.cert.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Certificate path required when not in one-shot mode")
        })?;
        let key_path = args
            .key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Key path required when not in one-shot mode"))?;

        let cert = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read certificate from {cert_path:?}"))?;
        let key = std::fs::read(key_path)
            .with_context(|| format!("Failed to read private key from {key_path:?}"))?;
        (cert, key)
    };

    // Create transport config
    let transport_config = RoshTransportConfig {
        keep_alive_interval: Duration::from_secs(args.keep_alive),
        max_idle_timeout: Duration::from_secs(args.keep_alive * 3),
        initial_window: 256 * 1024,
        stream_receive_window: VarInt::from_u32(256 * 1024),
    };

    // Create network transport
    let transport =
        NetworkTransport::new_server(args.bind, cert_chain, private_key, transport_config).await?;

    // Get actual bound address (in case port was 0)
    let bound_addr = transport.local_addr()?;

    // Output connection info for one-shot mode
    if args.one_shot {
        use base64::Engine;
        let encoded_key =
            base64::engine::general_purpose::STANDARD.encode(session_key.as_ref().unwrap());
        println!("ROSH_PORT={}", bound_addr.port());
        println!("ROSH_KEY={encoded_key}");
        std::io::stdout().flush()?;
    }

    let server_state = Arc::new(ServerState::new(args.max_sessions));

    info!("Server listening on {}", bound_addr);

    // Accept connections
    let mut _connection_count = 0;
    loop {
        match transport.accept().await {
            Ok((connection, client_addr)) => {
                info!("New connection from {}", client_addr);

                let server_state = server_state.clone();
                let cipher_algo = args.cipher;
                let compression = args.compression;
                let one_shot = args.one_shot;
                let session_key_clone = session_key.clone();

                if one_shot {
                    // In one-shot mode, handle synchronously and exit
                    if let Err(e) = handle_connection(
                        connection,
                        client_addr,
                        server_state,
                        cipher_algo,
                        compression,
                        session_key_clone,
                    )
                    .await
                    {
                        error!("Connection error from {}: {}", client_addr, e);
                    }
                    info!("One-shot connection completed, exiting");
                    return Ok(());
                } else {
                    // Normal mode, spawn task
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            connection,
                            client_addr,
                            server_state,
                            cipher_algo,
                            compression,
                            session_key_clone,
                        )
                        .await
                        {
                            error!("Connection error from {}: {}", client_addr, e);
                        }
                    });
                }

                _connection_count += 1;
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    mut connection: Box<dyn rosh_network::Connection>,
    client_addr: SocketAddr,
    server_state: Arc<ServerState>,
    cipher_algo: CipherAlgorithm,
    _compression: Option<CompressionAlgorithm>,
    _one_shot_key: Option<Vec<u8>>,
) -> Result<()> {
    // Receive initial handshake message
    let msg = time::timeout(Duration::from_secs(10), connection.receive())
        .await
        .context("Handshake timeout")?
        .context("Failed to receive handshake")?;

    let (session_keys_bytes, terminal_width, terminal_height) = match msg {
        NetworkMessage::Handshake {
            session_keys_bytes,
            terminal_width,
            terminal_height,
        } => (session_keys_bytes, terminal_width, terminal_height),
        _ => anyhow::bail!("Expected handshake message"),
    };

    // Deserialize session keys
    let _session_keys: SessionKeys =
        match rkyv::check_archived_root::<SessionKeys>(&session_keys_bytes) {
            Ok(archived) => archived
                .deserialize(&mut rkyv::de::deserializers::SharedDeserializeMap::new())
                .map_err(|e| anyhow::anyhow!("Failed to deserialize session keys: {:?}", e))?,
            Err(e) => anyhow::bail!("Failed to validate session keys: {:?}", e),
        };

    // Create session
    let session_id = Uuid::new_v4();
    info!("Creating session {} for {}", session_id, client_addr);

    // Create PTY session
    let (pty_session, mut pty_events) = SessionBuilder::new()
        .dimensions(terminal_height, terminal_width)
        .build()
        .await
        .context("Failed to create PTY session")?;

    // Create state synchronizer
    let initial_state = pty_session.get_state().await;
    let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(initial_state, true)));

    // Create session
    let session = Session {
        id: session_id,
        pty_session,
        _state_sync: state_sync.clone(),
        _client_addr: client_addr,
        last_activity: Arc::new(RwLock::new(time::Instant::now())),
    };

    server_state.add_session(session).await?;

    // Send handshake acknowledgment
    connection
        .send(NetworkMessage::HandshakeAck {
            session_id: session_id.as_u128() as u64, // Use lower 64 bits of UUID
            cipher_algorithm: cipher_algo as u8,
        })
        .await?;

    // Get session reference
    let session = server_state
        .get_session(&session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

    // Spawn PTY handler
    let pty_state_sync = state_sync.clone();
    let mut pty_connection = connection.clone();
    let pty_last_activity = session.last_activity.clone();
    tokio::spawn(async move {
        let result: Result<()> = async {
            while let Some(event) = pty_events.recv().await {
                match event {
                    SessionEvent::StateChanged(new_state) => {
                        // Update state synchronizer
                        let state_msg = {
                            let mut sync = pty_state_sync.write().await;
                            match sync.update_state(new_state) {
                                Ok(Some(update)) => {
                                    // Convert StateUpdate to StateMessage
                                    StateMessage::FullState {
                                        seq: update.seq_num,
                                        state: sync.current_state().clone(),
                                    }
                                }
                                Ok(None) => {
                                    // No changes, send ack
                                    StateMessage::Ack(sync.current_seq())
                                }
                                Err(e) => {
                                    error!("Failed to update state: {}", e);
                                    StateMessage::Ack(sync.current_seq())
                                }
                            }
                        };

                        // Send state update
                        let state_bytes = rkyv::to_bytes::<_, 1024>(&state_msg)
                            .map_err(|e| {
                                anyhow::anyhow!("Failed to serialize state message: {}", e)
                            })?
                            .to_vec();
                        if let Err(e) = pty_connection
                            .send(NetworkMessage::State(state_bytes))
                            .await
                        {
                            error!("Failed to send state update: {}", e);
                            break;
                        }

                        // Update activity
                        *pty_last_activity.write().await = time::Instant::now();
                    }
                    SessionEvent::ProcessExited(code) => {
                        info!("Session {} process exited with code {}", session_id, code);
                        break;
                    }
                    SessionEvent::Error(e) => {
                        error!("Session {} error: {}", session_id, e);
                        break;
                    }
                }
            }
            Ok(())
        }
        .await;

        if let Err(e) = result {
            error!("PTY handler error: {}", e);
        }
    });

    // Start PTY session in the session object
    let session = server_state
        .get_session(&session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

    let mut pty_handle = tokio::spawn(async move {
        info!("PTY session started for {}", session_id);
        // PTY session is handled by the event loop
    });

    // Main message loop
    loop {
        tokio::select! {
            // Receive client messages
            result = connection.receive() => {
                match result {
                    Ok(msg) => {
                        *session.last_activity.write().await = time::Instant::now();

                        match msg {
                            NetworkMessage::Input(data) => {
                                debug!("Received {} bytes of input", data.len());
                                session.pty_session.write_input(&data).await?;
                            }
                            NetworkMessage::Resize(cols, rows) => {
                                debug!("Resizing terminal to {}x{}", cols, rows);
                                session.pty_session.resize(rows, cols).await?;
                            }
                            NetworkMessage::StateAck(seq) => {
                                let mut sync = state_sync.write().await;
                                sync.process_ack(seq);
                            }
                            NetworkMessage::Ping => {
                                connection.send(NetworkMessage::Pong).await?;
                            }
                            _ => {
                                warn!("Unexpected message type");
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to receive message: {}", e);
                        break;
                    }
                }
            }

            // Check PTY completion
            _ = &mut pty_handle => {
                info!("PTY session ended");
                break;
            }

            // Periodic tasks
            _ = time::sleep(Duration::from_secs(5)) => {
                // Check for timeout
                let last_activity = *session.last_activity.read().await;
                if last_activity.elapsed() > Duration::from_secs(300) {
                    warn!("Session {} timed out", session_id);
                    break;
                }

                // Send any pending state updates
                let state_msg = {
                    let sync = state_sync.read().await;
                    // For now, just send current state
                    StateMessage::FullState {
                        seq: sync.current_seq(),
                        state: sync.current_state().clone(),
                    }
                };

                if !matches!(state_msg, StateMessage::Ack(_)) {
                    let state_bytes = rkyv::to_bytes::<_, 1024>(&state_msg)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize state message: {}", e))?
                        .to_vec();
                    if let Err(e) = connection.send(NetworkMessage::State(state_bytes)).await {
                        error!("Failed to send periodic state update: {}", e);
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    info!("Cleaning up session {}", session_id);
    session.pty_session.shutdown();
    server_state.remove_session(&session_id).await;

    Ok(())
}
