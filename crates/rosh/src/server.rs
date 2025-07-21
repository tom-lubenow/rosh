//! Rosh server implementation

use crate::bootstrap;
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

// Helper to append debug messages to file
fn debug_log(msg: &str) {
    use std::io::Write as IoWrite;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/rosh-server-debug.log")
    {
        let _ = writeln!(f, "{msg}");
        let _ = f.flush();
    }
}

/// Run a simple UDP echo server for testing connectivity
async fn run_udp_test_server(
    bound_addr: SocketAddr,
    socket: Option<std::net::UdpSocket>,
) -> Result<()> {
    println!("UDP_TEST_SERVER {bound_addr}");

    let socket = if let Some(s) = socket {
        s
    } else {
        std::net::UdpSocket::bind(bound_addr)?
    };

    // Convert to tokio UdpSocket
    socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;

    println!("UDP test server listening on {}", socket.local_addr()?);

    let mut buf = vec![0u8; 1024];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                println!("Received {n} bytes from {peer}");
                let response = format!("ECHO: {}", String::from_utf8_lossy(&buf[..n]));
                socket.send_to(response.as_bytes(), peer).await?;
            }
            Err(e) => {
                eprintln!("UDP receive error: {e}");
            }
        }
    }
}

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
    #[arg(short = 'a', long, value_enum, default_value = "aes-256-gcm")]
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

    /// UDP test mode - just echo packets
    #[arg(long, hide = true)]
    udp_test: bool,
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

/// Run the server after forking has already happened
async fn run_server_after_fork(
    args: Args,
    bound_addr: SocketAddr,
    session_key: Option<Vec<u8>>,
    log_file_path: PathBuf,
    socket: Option<std::net::UdpSocket>,
) -> Result<()> {
    // Write debug output to file instead of stderr
    debug_log("DEBUG: run_server_after_fork called");
    debug_log(&format!("DEBUG: bound_addr = {bound_addr}"));
    debug_log(&format!(
        "DEBUG: log_file_path = {}",
        log_file_path.display()
    ));

    // Set up logging
    let log_level = tracing::Level::INFO;
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)
        .with_context(|| format!("Failed to open log file: {}", log_file_path.display()))?;

    debug_log("DEBUG: Log file opened successfully");

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(log_file)
        .with_ansi(false)
        .init();

    debug_log("DEBUG: Logging initialized");

    info!(
        "Rosh server starting up (after fork), log file: {}",
        log_file_path.display()
    );
    info!("Server args: {:?}", args);

    // Check if we're in UDP test mode
    if args.udp_test {
        run_udp_test_server(bound_addr, socket).await
    } else {
        // Continue with the actual server logic
        run_server(args, bound_addr, session_key, log_file_path, socket).await
    }
}

/// Run the actual server after forking/detaching
async fn run_server(
    args: Args,
    bound_addr: SocketAddr,
    session_key: Option<Vec<u8>>,
    _log_file_path: PathBuf,
    socket: Option<std::net::UdpSocket>,
) -> Result<()> {
    info!("Starting server main loop on {}", bound_addr);

    // Load certificates
    let (cert_chain, private_key) = if args.one_shot {
        // Generate self-signed certificate for one-shot mode
        bootstrap::server::generate_self_signed_cert()?
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

    // Create a channel to signal when QUIC is ready
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

    // Consume ready channel since we're not using hole punch responder
    drop(ready_rx);

    // Create network transport
    // HACK: If we have a socket from hole punching, we need to close it and let QUIC
    // recreate it on the same port. This is because Quinn needs specific socket options
    // that we can't easily set on a pre-existing socket.
    let transport = if let Some(socket) = socket {
        info!(
            "Closing hole-punch socket and recreating for QUIC on {}",
            bound_addr
        );
        // Close the hole punching socket
        drop(socket);

        // Small delay to ensure socket is fully closed
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create new QUIC transport on the same address
        info!(
            "Creating NetworkTransport on {} (after hole punch)",
            bound_addr
        );

        let t = NetworkTransport::new_server(bound_addr, cert_chain, private_key, transport_config)
            .await?;
        match t.local_addr() {
            Ok(addr) => info!("QUIC endpoint listening on: {}", addr),
            Err(e) => error!("Failed to get QUIC endpoint address: {}", e),
        }
        // In one-shot mode, set the session key
        if let Some(ref key) = session_key {
            t.with_encryption(key.clone(), args.cipher)
        } else {
            t
        }
    } else {
        info!("Creating NetworkTransport on {}", bound_addr);
        let t = NetworkTransport::new_server(bound_addr, cert_chain, private_key, transport_config)
            .await?;
        match t.local_addr() {
            Ok(addr) => info!("QUIC endpoint listening on: {}", addr),
            Err(e) => error!("Failed to get QUIC endpoint address: {}", e),
        }
        // In one-shot mode, set the session key
        if let Some(ref key) = session_key {
            t.with_encryption(key.clone(), args.cipher)
        } else {
            t
        }
    };

    // Signal that QUIC is ready (not used anymore)
    let _ = ready_tx.send(());

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

/// Main entry point that handles forking before creating tokio runtime
pub fn main() -> Result<()> {
    // Parse args early to determine if we need to fork
    let args = Args::parse();

    // Handle the forking/detaching logic BEFORE creating tokio runtime
    if args.detach && args.one_shot {
        // We need to handle the bootstrap sequence before forking
        // This includes binding the port and printing connection params

        // Generate session key for one-shot mode
        use rand::RngCore;
        let mut session_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);

        // Bind port synchronously BEFORE forking
        let (socket, bound_addr) = bootstrap::server::bind_available_port(args.bind)?;

        // Set up log file
        let log_file_path = if let Some(path) = &args.log_file {
            path.clone()
        } else {
            // Generate a temporary log file
            let temp_file = tempfile::Builder::new()
                .prefix("rosh-server-")
                .suffix(".log")
                .tempfile()
                .context("Failed to create temporary log file")?;
            let (_, path) = temp_file
                .keep()
                .map_err(|e| anyhow::anyhow!("Failed to persist temp log file: {}", e))?;
            path
        };

        // Print log file path to stdout for the client to capture
        println!("SERVER_LOG_FILE: {}", log_file_path.display());

        // Generate bootstrap params
        let params =
            bootstrap::server::generate_bootstrap_params(bound_addr, &session_key, &log_file_path);

        // Print connection params BEFORE detaching (like mosh)
        if unsafe { libc::isatty(0) } == 1 {
            println!("\r");
        }
        println!("ROSH CONNECT {} {}", params.port, params.session_key);
        std::io::stdout().flush()?;

        // NOW detach
        // Don't print to stderr before fork - it interferes with SSH ProxyCommand
        std::fs::write("/tmp/rosh-pre-fork.txt", "About to fork\n").ok();

        // Close the socket before forking - we'll recreate it after
        drop(socket);

        bootstrap::server::detach_without_params()?;

        // After forking, we're in the child process
        debug_log("DEBUG: Child process alive after detach_without_params");

        // Try creating a single-threaded runtime which might work better after fork
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => {
                debug_log("DEBUG: Tokio runtime created successfully");
                rt
            }
            Err(e) => {
                debug_log(&format!("ERROR: Failed to create tokio runtime: {e}"));
                debug_log(&format!("ERROR: Details: {e:?}"));
                // Try multi-threaded as fallback
                match tokio::runtime::Runtime::new() {
                    Ok(rt) => {
                        debug_log("DEBUG: Fallback to multi-threaded runtime succeeded");
                        rt
                    }
                    Err(e2) => {
                        debug_log(&format!("ERROR: Fallback also failed: {e2}"));
                        return Err(e.into());
                    }
                }
            }
        };
        debug_log("DEBUG: About to run server");

        // Wrap in catch_unwind to catch panics
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(run_server_after_fork(
                args,
                bound_addr,
                Some(session_key),
                log_file_path,
                None, // Socket was closed before fork, will be recreated
            ))
        }));

        match result {
            Ok(inner_result) => {
                debug_log(&format!(
                    "DEBUG: Server finished with result: {:?}",
                    inner_result.is_ok()
                ));
                if let Err(ref e) = inner_result {
                    debug_log(&format!("ERROR: Server failed: {e}"));
                }
                inner_result
            }
            Err(panic) => {
                debug_log("ERROR: Server panicked!");
                if let Some(s) = panic.downcast_ref::<&str>() {
                    debug_log(&format!("ERROR: Panic message: {s}"));
                } else if let Some(s) = panic.downcast_ref::<String>() {
                    debug_log(&format!("ERROR: Panic message: {s}"));
                } else {
                    debug_log("ERROR: Unknown panic type");
                }
                Err(anyhow::anyhow!("Server panicked"))
            }
        }
    } else {
        // Normal case - create runtime and run
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(run())
    }
}

/// The original async run function
async fn run() -> Result<()> {
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
    let (socket, bound_addr) = if args.one_shot {
        // For one-shot mode, always bind before forking to get the port
        let (socket, addr) = bootstrap::server::bind_available_port(args.bind)?;
        (Some(socket), addr)
    } else {
        // For non-one-shot mode, let NetworkTransport handle binding
        (None, args.bind)
    };

    // Prepare connection parameters if in one-shot mode
    let params = if args.one_shot {
        Some(bootstrap::server::generate_bootstrap_params(
            bound_addr,
            session_key.as_ref().unwrap(),
            &log_file_path,
        ))
    } else {
        None
    };

    // In one-shot mode, print connection params BEFORE detaching (like mosh)
    if let Some(ref params) = params {
        // Like mosh, print newline if on a tty to avoid echo issues
        if unsafe { libc::isatty(0) } == 1 {
            println!("\r");
        }
        // Print connection params in mosh format: ROSH CONNECT <port> <key>
        println!("ROSH CONNECT {} {}", params.port, params.session_key);
        std::io::stdout().flush()?;
        info!("Printed connection params to stdout");
    }

    // NOW detach if requested (after printing, like mosh)
    if args.detach {
        info!("About to detach as daemon process");
        // We already printed params, so pass None to avoid double printing
        bootstrap::server::detach_without_params()?;
    }

    info!("Detach complete, continuing server initialization");

    // Check if we're in UDP test mode
    if args.udp_test {
        run_udp_test_server(bound_addr, socket).await
    } else {
        // Now run the actual server with the bound address
        run_server(args, bound_addr, session_key, log_file_path, socket).await
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
