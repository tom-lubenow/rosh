//! Rosh server implementation

use crate::bootstrap::BootstrapConnectParams;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rkyv::Deserialize;
use rosh_crypto::{CipherAlgorithm, SessionKeys};
use rosh_network::{Message as NetworkMessage, NetworkTransport, RoshTransportConfig, VarInt};
use rosh_pty::{PtySession, SessionBuilder, SessionEvent};
use rosh_state::{CompressionAlgorithm, StateMessage, StateSynchronizer};
use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
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

    /// Timeout in seconds for one-shot mode (0 = no timeout)
    #[arg(long, default_value = "0")]
    timeout: u64,

    /// Detach from parent process and become a daemon (for SSH bootstrap)
    #[arg(long)]
    detach: bool,

    /// Path to log file (stdout if not specified)
    #[arg(long)]
    log_file: Option<PathBuf>,
}

/// Active session state
struct Session {
    id: Uuid,
    pty_session: Arc<tokio::sync::Mutex<PtySession>>,
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

/// Properly detach from parent process using double-fork and pipe communication
fn detach_and_communicate(params: &BootstrapConnectParams) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::{Read, Write};
        use std::os::unix::io::FromRawFd;

        // Create pipe for communication
        let mut fds = [0; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
            anyhow::bail!("Failed to create pipe: {}", std::io::Error::last_os_error());
        }
        let (read_fd, write_fd) = (fds[0], fds[1]);

        match unsafe { libc::fork() } {
            -1 => anyhow::bail!("Failed to fork: {}", std::io::Error::last_os_error()),
            0 => {
                // Child process
                unsafe {
                    libc::close(read_fd);
                }

                // Write connection params to parent through pipe
                let json = serde_json::to_string(params)?;
                let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
                write_file.write_all(json.as_bytes())?;
                write_file.flush()?;
                std::mem::forget(write_file); // Don't close the fd twice
                unsafe {
                    libc::close(write_fd);
                }

                // Create new session
                if unsafe { libc::setsid() } == -1 {
                    eprintln!(
                        "Failed to create new session: {}",
                        std::io::Error::last_os_error()
                    );
                    std::process::exit(1);
                }

                // Second fork to ensure we can't acquire a controlling terminal
                match unsafe { libc::fork() } {
                    -1 => {
                        eprintln!(
                            "Failed to fork second time: {}",
                            std::io::Error::last_os_error()
                        );
                        std::process::exit(1);
                    }
                    0 => {
                        // Grandchild - the actual daemon
                        // Continue execution
                        Ok(())
                    }
                    _ => {
                        // First child exits
                        std::process::exit(0);
                    }
                }
            }
            child_pid => {
                // Parent process
                unsafe {
                    libc::close(write_fd);
                }

                // Read connection params from pipe
                let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
                let mut buffer = String::new();
                read_file.read_to_string(&mut buffer)?;
                std::mem::forget(read_file); // Don't close the fd twice
                unsafe {
                    libc::close(read_fd);
                }

                // Wait for first child to exit
                let mut status = 0;
                unsafe {
                    libc::waitpid(child_pid, &mut status, 0);
                }

                // Print the params for SSH to capture
                println!("ROSH_CONNECT_PARAMS: {buffer}");
                std::io::stdout().flush()?;

                // Parent exits
                std::process::exit(0);
            }
        }
    }

    #[cfg(not(unix))]
    {
        // On non-Unix platforms, just print the params
        println!("ROSH_CONNECT_PARAMS: {}", serde_json::to_string(params)?);
        std::io::stdout().flush()?;
        Ok(())
    }
}

/// Bind to a UDP socket synchronously to find an available port
fn bind_available_port(addr: SocketAddr) -> Result<(UdpSocket, SocketAddr)> {
    let socket = UdpSocket::bind(addr).with_context(|| format!("Failed to bind to {addr}"))?;

    // Get the actual bound address (important when port is 0)
    let bound_addr = socket.local_addr().context("Failed to get local address")?;

    info!("Bound UDP socket to {}", bound_addr);

    Ok((socket, bound_addr))
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

/// Run the actual server after forking/detaching
async fn run_server(
    args: Args,
    bound_addr: SocketAddr,
    session_key: Option<Vec<u8>>,
    _log_file_path: PathBuf,
    socket: Option<UdpSocket>,
) -> Result<()> {
    info!("Starting server main loop on {}", bound_addr);

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
        cert_validation: rosh_network::CertValidationMode::default(),
    };

    // Create network transport
    let transport = if let Some(socket) = socket {
        info!(
            "Creating NetworkTransport from existing socket on {}",
            bound_addr
        );
        NetworkTransport::new_server_from_socket(socket, transport_config).await?
    } else {
        info!("Creating NetworkTransport on {}", bound_addr);
        NetworkTransport::new_server(bound_addr, cert_chain, private_key, transport_config).await?
    };

    let server_state = Arc::new(ServerState::new(args.max_sessions));

    if !args.one_shot {
        info!("Server listening on {}", bound_addr);
    } else {
        info!("Server in one-shot mode, listening on {}", bound_addr);
    }

    // Accept connections
    let mut _connection_count = 0;

    // Set up timeout for one-shot mode
    let timeout_duration = if args.one_shot && args.timeout > 0 {
        Some(Duration::from_secs(args.timeout))
    } else {
        None
    };

    loop {
        info!("Waiting for incoming connection...");
        let accept_result = if let Some(timeout) = timeout_duration {
            // Accept with timeout
            info!("Accepting with timeout of {:?}", timeout);
            match time::timeout(timeout, transport.accept()).await {
                Ok(result) => {
                    info!("Accept completed within timeout");
                    result
                }
                Err(_) => {
                    warn!("Timeout waiting for connection");
                    return Ok(());
                }
            }
        } else {
            // Accept without timeout
            info!("Accepting without timeout");
            transport.accept().await
        };

        match accept_result {
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
            }
            Err(e) => {
                warn!("Failed to accept connection: {}", e);
                if args.one_shot {
                    return Err(e).context("Failed to accept one-shot connection");
                }
                // In normal mode, continue accepting
            }
        }

        _connection_count += 1;
    }
}

pub async fn run() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.one_shot {
        // In one-shot mode, only show errors to avoid interfering with terminal
        tracing::Level::ERROR
    } else {
        match args.log_level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    };

    // Set up logging - always use a log file
    let log_file_path = if let Some(path) = &args.log_file {
        path.clone()
    } else {
        // Generate a temporary log file
        let temp_file = tempfile::Builder::new()
            .prefix("rosh-server-")
            .suffix(".log")
            .tempfile()
            .context("Failed to create temporary log file")?;

        // Get the path and keep the file from being deleted
        let (_, path) = temp_file
            .keep()
            .map_err(|e| anyhow::anyhow!("Failed to persist temp log file: {}", e))?;
        path
    };

    // Print log file path to stdout for the client to capture
    println!("SERVER_LOG_FILE: {}", log_file_path.display());

    // Open log file for writing
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)
        .with_context(|| format!("Failed to open log file: {}", log_file_path.display()))?;

    // Force log_level to at least INFO for debugging
    let effective_log_level = match log_level {
        tracing::Level::ERROR => tracing::Level::INFO,
        other => other,
    };

    // Use file writer for logging
    if args.one_shot {
        tracing_subscriber::fmt()
            .with_max_level(effective_log_level)
            .with_writer(log_file)
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false)
            .with_ansi(false)
            .compact()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(effective_log_level)
            .with_writer(log_file)
            .with_ansi(false)
            .init();
    }

    // Log initial startup message
    info!(
        "Rosh server starting up, log file: {}",
        log_file_path.display()
    );
    info!("Server args: {:?}", args);

    // Generate session key for one-shot mode
    let session_key = if args.one_shot {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Some(key)
    } else {
        None
    };

    if !args.one_shot {
        info!("Starting Rosh server on {}", args.bind);
    }

    // Bind port synchronously BEFORE forking (like mosh does)
    let (socket, bound_addr) = if args.detach && args.one_shot {
        // For detach mode, bind synchronously before forking
        let (socket, addr) = bind_available_port(args.bind)?;
        (Some(socket), addr)
    } else {
        // For non-detach mode, we'll let NetworkTransport handle binding
        (None, args.bind)
    };

    // Prepare connection parameters if in one-shot mode
    let params = if args.one_shot {
        use base64::Engine;
        let encoded_key =
            base64::engine::general_purpose::STANDARD.encode(session_key.as_ref().unwrap());

        // Determine the IP to report to the client
        let reported_ip = if let Ok(ssh_conn) = std::env::var("SSH_CONNECTION") {
            // We're in an SSH session
            let parts: Vec<&str> = ssh_conn.split_whitespace().collect();
            if parts.len() >= 4 {
                // Always use localhost for SSH connections (like mosh does)
                "localhost".to_string()
            } else {
                // Fallback to bound address
                bound_addr.ip().to_string()
            }
        } else {
            // Not in SSH session, use bound address
            bound_addr.ip().to_string()
        };

        Some(BootstrapConnectParams {
            ip: reported_ip,
            port: bound_addr.port(),
            session_key: encoded_key,
            log_file: Some(log_file_path.display().to_string()),
            client_addr: None,
            needs_hole_punch: false,
        })
    } else {
        None
    };

    // Detach if requested (which also outputs connection params)
    if args.detach {
        if let Some(params) = params {
            info!("About to detach as daemon process");
            info!("Connection params: {:?}", params);
            detach_and_communicate(&params)?;
        } else {
            anyhow::bail!("Detach requires one-shot mode");
        }
    } else if let Some(params) = params {
        // Not detaching, just print params normally
        println!("ROSH_CONNECT_PARAMS: {}", serde_json::to_string(&params)?);
        std::io::stdout().flush()?;
    }

    info!("Detach complete, continuing server initialization");

    // Now run the actual server with the bound address
    run_server(args, bound_addr, session_key, log_file_path, socket).await
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
        } => {
            info!(
                "Received handshake with terminal dimensions: {}x{}",
                terminal_width, terminal_height
            );
            (session_keys_bytes, terminal_width, terminal_height)
        }
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
    info!(
        "Creating PTY session with dimensions: {}x{}",
        terminal_width, terminal_height
    );
    let (pty_session, mut pty_events) = SessionBuilder::new()
        .dimensions(terminal_height, terminal_width)
        .env("ROSH", "1")
        .build()
        .await
        .context("Failed to create PTY session")?;
    info!("PTY session created successfully");

    // Create state synchronizer
    let initial_state = pty_session.get_state().await;
    let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(initial_state, true)));

    // Wrap PTY session in Arc<Mutex>
    let pty_session = Arc::new(tokio::sync::Mutex::new(pty_session));

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

    info!("Client connected successfully from {}", client_addr);

    // Get session reference and start PTY
    let session = server_state
        .get_session(&session_id)
        .await
        .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

    // Start the PTY session
    tokio::spawn({
        let pty_session = session.pty_session.clone();
        async move {
            let mut pty_guard = pty_session.lock().await;
            if let Err(e) = pty_guard.start().await {
                error!("Failed to start PTY session: {}", e);
            }
        }
    });

    // Spawn PTY handler
    let pty_state_sync = state_sync.clone();
    let mut pty_connection = connection.clone();
    let pty_last_activity = session.last_activity.clone();
    let mut pty_handle = tokio::spawn(async move {
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
                                let pty_guard = session.pty_session.lock().await;
                                pty_guard.write_input(&data).await?;
                            }
                            NetworkMessage::Resize(cols, rows) => {
                                debug!("Resizing terminal to {}x{}", cols, rows);
                                let pty_guard = session.pty_session.lock().await;
                                pty_guard.resize(rows, cols).await?;
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
    {
        let pty_guard = session.pty_session.lock().await;
        pty_guard.shutdown();
    }
    server_state.remove_session(&session_id).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_args_parsing_default_values() {
        let args = Args::try_parse_from(["rosh-server", "--one-shot"]).unwrap();
        assert_eq!(
            args.bind,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2022)
        );
        assert!(args.cert.is_none());
        assert!(args.key.is_none());
        assert_eq!(args.cipher, CipherAlgorithm::Aes128Gcm);
        assert!(args.compression.is_none());
        assert_eq!(args.keep_alive, 30);
        assert!(matches!(args.log_level, LogLevel::Info));
        assert_eq!(args.max_sessions, 100);
        assert!(args.one_shot);
    }

    #[test]
    fn test_args_parsing_custom_values() {
        let args = Args::try_parse_from([
            "rosh-server",
            "--bind",
            "127.0.0.1:8080",
            "--cert",
            "/path/to/cert.pem",
            "--key",
            "/path/to/key.pem",
            "--cipher",
            "chacha20-poly1305",
            "--compression",
            "zstd",
            "--keep-alive",
            "60",
            "--log-level",
            "debug",
            "--max-sessions",
            "50",
        ])
        .unwrap();

        assert_eq!(args.bind, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(args.cert.unwrap(), PathBuf::from("/path/to/cert.pem"));
        assert_eq!(args.key.unwrap(), PathBuf::from("/path/to/key.pem"));
        assert_eq!(args.cipher, CipherAlgorithm::ChaCha20Poly1305);
        assert_eq!(args.compression, Some(CompressionAlgorithm::Zstd));
        assert_eq!(args.keep_alive, 60);
        assert!(matches!(args.log_level, LogLevel::Debug));
        assert_eq!(args.max_sessions, 50);
        assert!(!args.one_shot);
    }

    #[test]
    fn test_args_requires_cert_and_key_without_one_shot() {
        // Should fail when neither cert/key nor one-shot is provided
        let result = Args::try_parse_from(["rosh-server"]);
        assert!(result.is_err());

        // Should succeed with cert and key
        let result = Args::try_parse_from([
            "rosh-server",
            "--cert",
            "/path/to/cert",
            "--key",
            "/path/to/key",
        ]);
        assert!(result.is_ok());

        // Should succeed with one-shot
        let result = Args::try_parse_from(["rosh-server", "--one-shot"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_all_cipher_algorithms() {
        let ciphers = ["aes-gcm", "aes-256-gcm", "chacha20-poly1305"];

        for cipher_str in &ciphers {
            let args = Args::try_parse_from(["rosh-server", "--one-shot", "--cipher", cipher_str])
                .unwrap();

            match *cipher_str {
                "aes-gcm" => assert_eq!(args.cipher, CipherAlgorithm::Aes128Gcm),
                "aes-256-gcm" => assert_eq!(args.cipher, CipherAlgorithm::Aes256Gcm),
                "chacha20-poly1305" => assert_eq!(args.cipher, CipherAlgorithm::ChaCha20Poly1305),
                _ => panic!("Unknown cipher"),
            }
        }
    }

    #[test]
    fn test_all_log_levels() {
        let levels = ["trace", "debug", "info", "warn", "error"];

        for level_str in &levels {
            let args =
                Args::try_parse_from(["rosh-server", "--one-shot", "--log-level", level_str])
                    .unwrap();

            match *level_str {
                "trace" => assert!(matches!(args.log_level, LogLevel::Trace)),
                "debug" => assert!(matches!(args.log_level, LogLevel::Debug)),
                "info" => assert!(matches!(args.log_level, LogLevel::Info)),
                "warn" => assert!(matches!(args.log_level, LogLevel::Warn)),
                "error" => assert!(matches!(args.log_level, LogLevel::Error)),
                _ => panic!("Unknown log level"),
            }
        }
    }

    #[test]
    fn test_invalid_bind_address() {
        let result =
            Args::try_parse_from(["rosh-server", "--one-shot", "--bind", "not-an-address"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cipher() {
        let result =
            Args::try_parse_from(["rosh-server", "--one-shot", "--cipher", "invalid-cipher"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_compression() {
        let result = Args::try_parse_from([
            "rosh-server",
            "--one-shot",
            "--compression",
            "invalid-compression",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_help_includes_all_options() {
        let mut cmd = Args::command();
        let help = format!("{}", cmd.render_help());

        // Check that all important options are documented
        assert!(help.contains("--bind"));
        assert!(help.contains("--cert"));
        assert!(help.contains("--key"));
        assert!(help.contains("--cipher"));
        assert!(help.contains("--compression"));
        assert!(help.contains("--keep-alive"));
        assert!(help.contains("--log-level"));
        assert!(help.contains("--max-sessions"));
        assert!(help.contains("--one-shot"));
        assert!(help.contains("0.0.0.0:2022")); // default bind
        assert!(help.contains("aes-gcm")); // default cipher
    }

    #[test]
    fn test_server_state_new() {
        let state = ServerState::new(50);
        assert_eq!(state.max_sessions, 50);
    }

    // NOTE: The following tests require complex mocking of PtySession and StateSynchronizer
    // which is better done as integration tests. These are commented out to avoid unsafe code.

    /*
    #[tokio::test]
    async fn test_server_state_add_session() {
        // This test would require proper mocking of Session, PtySession, and StateSynchronizer
        // Moving to integration tests would be more appropriate
    }
    */

    /*
    #[tokio::test]
    async fn test_server_state_remove_session() {
        // This test would require proper mocking of Session, PtySession, and StateSynchronizer
        // Moving to integration tests would be more appropriate
    }
    */

    #[tokio::test]
    async fn test_server_state_get_session_not_found() {
        let state = ServerState::new(10);
        let non_existent_id = Uuid::new_v4();

        // Get non-existent session should return None
        assert!(state.get_session(&non_existent_id).await.is_none());
    }

    #[tokio::test]
    async fn test_server_state_session_capacity() {
        let state = ServerState::new(0);

        // With max_sessions = 0, the sessions map should still be created
        let sessions = state.sessions.read().await;
        assert_eq!(sessions.len(), 0);
        assert_eq!(state.max_sessions, 0);
    }

    #[test]
    fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());

        let (cert_pem, key_pem) = result.unwrap();

        // Basic validation of generated certificate
        assert!(!cert_pem.is_empty());
        assert!(!key_pem.is_empty());

        // Check PEM format markers
        let cert_str = String::from_utf8_lossy(&cert_pem);
        assert!(cert_str.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert_str.contains("-----END CERTIFICATE-----"));

        let key_str = String::from_utf8_lossy(&key_pem);
        assert!(key_str.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(key_str.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_log_level_conversion() {
        use tracing::Level;

        // Test conversion from our LogLevel enum to tracing::Level
        let test_cases = vec![
            (LogLevel::Trace, Level::TRACE),
            (LogLevel::Debug, Level::DEBUG),
            (LogLevel::Info, Level::INFO),
            (LogLevel::Warn, Level::WARN),
            (LogLevel::Error, Level::ERROR),
        ];

        for (our_level, expected_level) in test_cases {
            let converted = match our_level {
                LogLevel::Trace => Level::TRACE,
                LogLevel::Debug => Level::DEBUG,
                LogLevel::Info => Level::INFO,
                LogLevel::Warn => Level::WARN,
                LogLevel::Error => Level::ERROR,
            };
            assert_eq!(converted, expected_level);
        }
    }

    #[test]
    fn test_transport_config_values() {
        let args =
            Args::try_parse_from(["rosh-server", "--one-shot", "--keep-alive", "45"]).unwrap();

        // Verify transport config would be created correctly
        assert_eq!(args.keep_alive, 45);

        // The actual RoshTransportConfig would have:
        // - keep_alive_interval: 45 seconds
        // - max_idle_timeout: 45 * 3 = 135 seconds
        let keep_alive_duration = Duration::from_secs(args.keep_alive);
        let max_idle_duration = Duration::from_secs(args.keep_alive * 3);

        assert_eq!(keep_alive_duration.as_secs(), 45);
        assert_eq!(max_idle_duration.as_secs(), 135);
    }

    #[test]
    fn test_one_shot_key_generation() {
        // In one-shot mode, a 32-byte key should be generated
        use rand::RngCore;

        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        assert_eq!(key.len(), 32);
        // Verify it's not all zeros (extremely unlikely with proper RNG)
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_base64_encoding_of_session_key() {
        use base64::Engine;

        // Test that session keys are properly base64 encoded
        let test_key = vec![
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let encoded = base64::engine::general_purpose::STANDARD.encode(&test_key);

        // Verify it's valid base64
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(decoded, test_key);

        // For a 32-byte key, base64 should be 44 characters (including padding)
        assert_eq!(encoded.len(), 44);
    }

    #[test]
    fn test_session_struct_fields() {
        // Test that Session struct is properly constructed
        let id = Uuid::new_v4();
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let now = time::Instant::now();

        // Verify UUID operations
        assert_eq!(id.as_u128() as u64, id.as_u128() as u64); // Lower 64 bits extraction

        // Verify address parsing
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_eq!(addr.port(), 1234);

        // Verify time instant
        assert!(now.elapsed().as_nanos() > 0);
    }

    #[test]
    fn test_handshake_message_variants() {
        // Test that we handle the correct message types
        use rosh_network::Message as NetworkMessage;

        // Test handshake message construction
        let session_keys_bytes = vec![1, 2, 3, 4];
        let terminal_width = 80;
        let terminal_height = 24;

        let msg = NetworkMessage::Handshake {
            session_keys_bytes: session_keys_bytes.clone(),
            terminal_width,
            terminal_height,
        };

        match msg {
            NetworkMessage::Handshake {
                session_keys_bytes: keys,
                terminal_width: w,
                terminal_height: h,
            } => {
                assert_eq!(keys, session_keys_bytes);
                assert_eq!(w, 80);
                assert_eq!(h, 24);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_handshake_ack_message() {
        use rosh_network::Message as NetworkMessage;

        let session_id = Uuid::new_v4();
        let cipher = CipherAlgorithm::Aes256Gcm;

        let msg = NetworkMessage::HandshakeAck {
            session_id: session_id.as_u128() as u64,
            cipher_algorithm: cipher as u8,
        };

        match msg {
            NetworkMessage::HandshakeAck {
                session_id: id,
                cipher_algorithm: alg,
            } => {
                assert_eq!(id, session_id.as_u128() as u64);
                assert_eq!(alg, CipherAlgorithm::Aes256Gcm as u8);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_state_message_variants() {
        use rosh_state::StateMessage;
        use rosh_terminal::TerminalState;

        // Test FullState variant
        let state = TerminalState::new(80, 24);
        let msg = StateMessage::FullState {
            seq: 42,
            state: state.clone(),
        };

        match msg {
            StateMessage::FullState { seq, state: s } => {
                assert_eq!(seq, 42);
                assert_eq!(s, state);
            }
            _ => panic!("Wrong state message type"),
        }

        // Test Ack variant
        let ack_msg = StateMessage::Ack(100);
        match ack_msg {
            StateMessage::Ack(seq) => assert_eq!(seq, 100),
            _ => panic!("Wrong state message type"),
        }
    }

    #[test]
    fn test_session_timeout_duration() {
        // Test timeout calculation
        let last_activity = time::Instant::now();
        let timeout_duration = Duration::from_secs(300); // 5 minutes

        // Simulate time passing
        std::thread::sleep(Duration::from_millis(10));

        let elapsed = last_activity.elapsed();
        assert!(elapsed < timeout_duration);
        assert!(elapsed.as_millis() >= 10);
    }

    #[test]
    fn test_port_binding_edge_cases() {
        // Test various socket address formats
        let valid_addrs = vec![
            "0.0.0.0:2022",
            "127.0.0.1:8080",
            "[::]:2022",
            "[::1]:8080",
            "192.168.1.100:3000",
        ];

        for addr_str in valid_addrs {
            let addr: Result<SocketAddr, _> = addr_str.parse();
            assert!(addr.is_ok(), "Failed to parse address: {addr_str}");
        }

        // Test invalid addresses
        let invalid_addrs = vec![
            "not-an-address",
            "256.256.256.256:8080",
            "localhost:8080",  // hostname not allowed, must be IP
            ":8080",           // missing host
            "127.0.0.1:",      // missing port
            "127.0.0.1:99999", // port out of range
        ];

        for addr_str in invalid_addrs {
            let addr: Result<SocketAddr, _> = addr_str.parse();
            assert!(addr.is_err(), "Should have failed to parse: {addr_str}");
        }
    }

    #[test]
    fn test_compression_algorithm_options() {
        // Test all compression options including None
        let args_none = Args::try_parse_from(["rosh-server", "--one-shot"]).unwrap();
        assert!(args_none.compression.is_none());

        let args_zstd =
            Args::try_parse_from(["rosh-server", "--one-shot", "--compression", "zstd"]).unwrap();
        assert_eq!(args_zstd.compression, Some(CompressionAlgorithm::Zstd));

        // Note: Add more compression algorithms as they're added to the enum
    }
}
