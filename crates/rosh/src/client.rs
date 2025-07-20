//! Rosh client implementation

use crate::bootstrap::{
    client::bootstrap_via_ssh, BootstrapOptions, NetworkFamily, RemoteIpStrategy,
};
use crate::terminal_guard::TerminalGuard;
use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    style::{self, Attribute, Color},
    terminal::{self, ClearType},
};
use rkyv::Deserialize;
use rosh_crypto::{CipherAlgorithm, KeyDerivation, SessionKeys};
use rosh_network::{Message as NetworkMessage, NetworkTransport, RoshTransportConfig, VarInt};
use rosh_state::{CompressionAlgorithm, StateMessage, StateSynchronizer};
use rosh_terminal::{state_to_framebuffer, Terminal, TerminalState};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, ValueEnum)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Rosh client - Modern mobile shell client")]
struct Args {
    /// Server address to connect to (host:port or user@host for SSH)
    server: String,

    /// Command to execute (optional)
    command: Option<String>,

    /// Session key (base64 encoded) - for direct connection only
    #[arg(short, long)]
    key: Option<String>,

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
    #[arg(long, value_enum, default_value = "warn")]
    log_level: LogLevel,

    /// Alias for --log-level debug
    #[arg(long, short, conflicts_with = "log_leveL")]
    debug: bool,

    /// Enable predictive echo
    #[arg(long)]
    predict: bool,

    /// SSH port (for SSH connections)
    #[arg(long)]
    ssh_port: Option<u16>,

    /// Remote command to start server (for SSH connections)
    #[arg(long, default_value = "rosh-server")]
    remote_command: String,

    /// Path to rosh-server binary on remote host
    #[arg(long)]
    rosh_server_bin: Option<String>,

    /// Additional SSH options
    #[arg(long)]
    ssh_options: Vec<String>,

    /// Method for discovering remote IP address (local|remote|proxy)
    #[arg(long, default_value = "proxy")]
    experimental_remote_ip: String,

    /// Network family preference
    #[arg(long = "family", default_value = "prefer-inet")]
    family: String,

    /// Use IPv4 only
    #[arg(short = '4', long = "ipv4", conflicts_with = "ipv6")]
    ipv4: bool,

    /// Use IPv6 only
    #[arg(short = '6', long = "ipv6", conflicts_with = "ipv4")]
    ipv6: bool,

    /// Act as a fake proxy for SSH ProxyCommand (internal use)
    #[arg(long, hide = true)]
    fake_proxy: bool,
}

/// Terminal UI state
pub struct TerminalUI {
    pub terminal: Terminal,
    pub state_sync: Arc<RwLock<StateSynchronizer>>,
    pub prediction_enabled: bool,
    stdout: io::Stdout,
    terminal_guard: Option<TerminalGuard>,
}

impl TerminalUI {
    pub fn new(
        cols: u16,
        rows: u16,
        state_sync: Arc<RwLock<StateSynchronizer>>,
        prediction_enabled: bool,
    ) -> Self {
        Self {
            terminal: Terminal::new(cols, rows),
            state_sync,
            prediction_enabled,
            stdout: io::stdout(),
            terminal_guard: None,
        }
    }

    /// Initialize terminal for raw mode, taking ownership of terminal and disabling logging
    fn init(&mut self) -> Result<()> {
        // Acquire terminal guard, which disables all logging
        let mut guard = TerminalGuard::acquire()?;
        guard.enable_raw_mode()?;
        self.terminal_guard = Some(guard);

        execute!(
            self.stdout,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0),
            cursor::Show,
        )?;
        Ok(())
    }

    /// Restore terminal to normal mode
    fn cleanup(&mut self) -> Result<()> {
        if let Some(mut guard) = self.terminal_guard.take() {
            guard.disable_raw_mode()?;
        }
        execute!(
            self.stdout,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0),
            cursor::Show,
        )?;
        Ok(())
    }

    /// Render the current state to the terminal
    async fn render(&mut self) -> Result<()> {
        let state = self.state_sync.read().await.current_state().clone();

        // Update terminal from state
        state_to_framebuffer(&state, self.terminal.framebuffer_mut());
        self.terminal.set_title(state.title.clone());

        // Clear screen and render
        execute!(self.stdout, terminal::Clear(ClearType::All))?;

        let fb = self.terminal.framebuffer();
        for y in 0..fb.height() {
            execute!(self.stdout, cursor::MoveTo(0, y))?;

            for x in 0..fb.width() {
                if let Some(cell) = fb.cell_at(x, y) {
                    // Set colors
                    let fg_color = match cell.fg {
                        rosh_terminal::Color::Default => Color::Reset,
                        rosh_terminal::Color::Indexed(idx) => match idx {
                            0 => Color::Black,
                            1 => Color::DarkRed,
                            2 => Color::DarkGreen,
                            3 => Color::DarkYellow,
                            4 => Color::DarkBlue,
                            5 => Color::DarkMagenta,
                            6 => Color::DarkCyan,
                            7 => Color::Grey,
                            8 => Color::DarkGrey,
                            9 => Color::Red,
                            10 => Color::Green,
                            11 => Color::Yellow,
                            12 => Color::Blue,
                            13 => Color::Magenta,
                            14 => Color::Cyan,
                            15 => Color::White,
                            _ => Color::Reset,
                        },
                        rosh_terminal::Color::Rgb(r, g, b) => Color::Rgb { r, g, b },
                    };

                    let bg_color = match cell.bg {
                        rosh_terminal::Color::Default => Color::Reset,
                        rosh_terminal::Color::Indexed(idx) => match idx {
                            0 => Color::Black,
                            1 => Color::DarkRed,
                            2 => Color::DarkGreen,
                            3 => Color::DarkYellow,
                            4 => Color::DarkBlue,
                            5 => Color::DarkMagenta,
                            6 => Color::DarkCyan,
                            7 => Color::Grey,
                            _ => Color::Reset,
                        },
                        rosh_terminal::Color::Rgb(r, g, b) => Color::Rgb { r, g, b },
                    };

                    execute!(
                        self.stdout,
                        style::SetForegroundColor(fg_color),
                        style::SetBackgroundColor(bg_color),
                    )?;

                    // Set attributes
                    if cell.attrs.bold {
                        execute!(self.stdout, style::SetAttribute(Attribute::Bold))?;
                    }
                    if cell.attrs.italic {
                        execute!(self.stdout, style::SetAttribute(Attribute::Italic))?;
                    }
                    if cell.attrs.underline {
                        execute!(self.stdout, style::SetAttribute(Attribute::Underlined))?;
                    }

                    // Write character
                    write!(self.stdout, "{}", cell.c)?;

                    // Reset attributes
                    execute!(self.stdout, style::SetAttribute(Attribute::Reset))?;
                }
            }
        }

        // Set cursor position
        execute!(
            self.stdout,
            cursor::MoveTo(state.cursor_x as u16, state.cursor_y as u16)
        )?;

        // Set cursor visibility
        if state.cursor_visible {
            execute!(self.stdout, cursor::Show)?;
        } else {
            execute!(self.stdout, cursor::Hide)?;
        }

        self.stdout.flush()?;
        Ok(())
    }

    /// Process local input with optional prediction
    fn process_input(&mut self, input: &[u8]) -> Result<()> {
        if self.prediction_enabled {
            // Apply input prediction locally
            self.terminal.process(input);
        }
        Ok(())
    }
}

impl Drop for TerminalUI {
    fn drop(&mut self) {
        // The terminal guard will handle cleanup when dropped
        if self.terminal_guard.is_some() {
            let _ = execute!(
                self.stdout,
                cursor::Show,
                style::SetAttribute(Attribute::Reset)
            );
        }
    }
}

/// Retrieve server logs via SSH
async fn retrieve_server_logs(host: &str, log_path: &str) {
    info!("Attempting to retrieve server logs from {}", log_path);

    // Build SSH command to cat the log file
    let mut cmd = tokio::process::Command::new("ssh");
    cmd.arg("-n"); // No stdin
    cmd.arg("-T"); // No PTY
    cmd.arg(host);
    cmd.arg(format!("cat {log_path}"));

    match cmd.output().await {
        Ok(output) => {
            if output.status.success() {
                let logs = String::from_utf8_lossy(&output.stdout);
                if !logs.trim().is_empty() {
                    error!("Server logs from {}:", log_path);
                    for line in logs.lines() {
                        error!("  {}", line);
                    }
                } else {
                    warn!("Server log file {} is empty", log_path);
                }
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to retrieve server logs: {}", stderr.trim());
            }
        }
        Err(e) => {
            warn!("Failed to execute SSH command to retrieve logs: {}", e);
        }
    }
}

/// Parse server argument to determine connection type
pub fn parse_server_arg(server: &str) -> (bool, Option<String>, String) {
    if server.contains('@') {
        // SSH format: user@host
        let parts: Vec<&str> = server.split('@').collect();
        if parts.len() == 2 {
            return (true, Some(parts[0].to_string()), parts[1].to_string());
        }
    } else if !server.contains(':') {
        // Just hostname, assume SSH
        return (true, None, server.to_string());
    }

    // Direct connection format: host:port
    (false, None, server.to_string())
}

/// Run fake proxy mode for SSH ProxyCommand
async fn run_fake_proxy(host: &str, port: &str, family: NetworkFamily) -> Result<()> {
    use std::io::{self, Read, Write as IoWrite};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::os::unix::io::AsRawFd;
    use std::thread;

    // Resolve hostname according to family preference
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {host}"))?
        .collect();

    if addrs.is_empty() {
        anyhow::bail!("No addresses found for {}", host);
    }

    // Try to connect to each address until one succeeds (like mosh)
    let mut last_err = None;
    let mut connected_stream = None;
    let mut connected_addr = None;

    for addr in &addrs {
        // Filter by family preference
        match family {
            NetworkFamily::Inet if !addr.is_ipv4() => continue,
            NetworkFamily::Inet6 if !addr.is_ipv6() => continue,
            NetworkFamily::PreferInet => {
                // Try IPv4 first
                if !addr.is_ipv4() && addrs.iter().any(|a| a.is_ipv4()) {
                    continue;
                }
            }
            NetworkFamily::PreferInet6 => {
                // Try IPv6 first
                if !addr.is_ipv6() && addrs.iter().any(|a| a.is_ipv6()) {
                    continue;
                }
            }
            _ => {}
        }

        match TcpStream::connect(addr) {
            Ok(stream) => {
                connected_stream = Some(stream);
                connected_addr = Some(*addr);
                break;
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    let (mut stream, addr) = match (connected_stream, connected_addr) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            let err_msg = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No suitable address found".to_string());
            anyhow::bail!("Could not connect to {}: {}", host, err_msg);
        }
    };

    // Print the resolved and connected IP to stderr for the parent process
    eprintln!("ROSH IP {}", addr.ip());

    // Set up non-blocking I/O
    stream.set_nonblocking(true)?;
    let _stream_fd = stream.as_raw_fd();

    // Spawn thread to copy from stdin to socket
    let stream_clone = stream.try_clone()?;
    let stdin_thread = thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut stream = stream_clone;
        let mut buffer = [0u8; 8192];

        loop {
            match stdin.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if stream.write_all(&buffer[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Copy from socket to stdout in main thread
    let mut stdout = io::stdout();
    let mut buffer = [0u8; 8192];

    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                if stdout.write_all(&buffer[..n]).is_err() {
                    break;
                }
                stdout.flush()?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(_) => break,
        }
    }

    // Wait for stdin thread to finish
    let _ = stdin_thread.join();

    Ok(())
}

pub async fn run() -> Result<()> {
    let args = Args::parse();

    // Handle fake proxy mode
    if args.fake_proxy {
        // In fake proxy mode, we expect the arguments to be:
        // rosh --fake-proxy -- host port
        // The server field will contain "host" and command will contain "port"
        let host = &args.server;
        let port = args
            .command
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing port argument for fake proxy mode"))?;

        // Determine network family
        let family = if args.ipv4 {
            NetworkFamily::Inet
        } else if args.ipv6 {
            NetworkFamily::Inet6
        } else {
            NetworkFamily::parse(&args.family)?
        };

        return run_fake_proxy(host, port, family).await;
    }

    // Ensure terminal is in a clean state before we start
    // This helps if a previous run left the terminal in raw mode
    let _ = terminal::disable_raw_mode();

    // Initialize logging
    let log_level = if args.debug {
        tracing::Level::DEBUG
    } else {
        match args.log_level {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(io::stderr)
        .with_line_number(false)
        .with_file(false)
        .with_target(false)
        .init();

    // Parse server argument
    let (is_ssh, user, host) = parse_server_arg(&args.server);

    // Determine network family from args
    let network_family = if args.ipv4 {
        NetworkFamily::Inet
    } else if args.ipv6 {
        NetworkFamily::Inet6
    } else {
        NetworkFamily::parse(&args.family)?
    };

    // Parse remote IP strategy
    let remote_ip_strategy = RemoteIpStrategy::parse(&args.experimental_remote_ip)?;

    // Get connection info
    let (server_addr, session_key_str, log_file) = if is_ssh {
        // SSH connection
        if args.key.is_some() {
            anyhow::bail!("Cannot specify --key with SSH connection");
        }

        info!(
            "Bootstrapping Rosh connection via SSH to {}@{}",
            user.as_deref().unwrap_or("<default>"),
            host
        );
        let connect_params = bootstrap_via_ssh(BootstrapOptions {
            user: user.as_deref(),
            host: &host,
            ssh_port: args.ssh_port,
            remote_command: &args.remote_command,
            rosh_server_bin: args.rosh_server_bin.as_deref(),
            ssh_options: &args.ssh_options,
            cipher: args.cipher,
            compression: args.compression,
            remote_ip_strategy,
            family: network_family,
        })
        .await?;

        // Log connection parameters
        info!(
            "Bootstrap complete. Connection parameters: {}",
            serde_json::to_string(&connect_params).unwrap_or_else(|_| "<error>".to_string())
        );

        // Parse IP address - handle the case where proxy strategy fills it in
        let ip: IpAddr = if connect_params.ip.is_empty() {
            // This shouldn't happen with proxy strategy, but provide a helpful error
            anyhow::bail!("Server did not provide IP address. This may be a bootstrap error.");
        } else {
            connect_params
                .ip
                .parse()
                .with_context(|| format!("Failed to parse server IP: {}", connect_params.ip))?
        };
        let server_addr = SocketAddr::new(ip, connect_params.port);
        let log_file = connect_params.log_file.clone();

        (server_addr, connect_params.session_key, log_file)
    } else {
        // Direct connection
        let session_key = args
            .key
            .ok_or_else(|| anyhow::anyhow!("--key required for direct connection"))?;

        let server_addr: SocketAddr = args
            .server
            .parse()
            .with_context(|| format!("Failed to parse server address: {}", args.server))?;

        info!("Using direct connection to {}", server_addr);
        (server_addr, session_key, None)
    };

    info!("Connecting to Rosh server via QUIC at {}", server_addr);

    // Decode session key
    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&session_key_str)
        .context("Failed to decode session key")?;

    // Skip hole punching - QUIC handles NAT traversal through its own mechanisms
    // The initial QUIC handshake packets will punch through NAT naturally
    if is_ssh {
        info!("Skipping explicit UDP hole punch - QUIC will handle NAT traversal");
        // Give server a moment to fully initialize after detaching
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Derive session keys
    let mut key_derivation = KeyDerivation::new(&key_bytes);
    let session_keys = SessionKeys {
        client_write_key: key_derivation
            .derive_key(b"client write")
            .context("Failed to derive client write key")?,
        server_write_key: key_derivation
            .derive_key(b"server write")
            .context("Failed to derive server write key")?,
    };

    // Get terminal dimensions
    let (cols, rows) = terminal::size()?;
    debug!("Local terminal dimensions: {}x{}", cols, rows);

    // Create transport config
    let transport_config = RoshTransportConfig {
        keep_alive_interval: Duration::from_secs(args.keep_alive),
        max_idle_timeout: Duration::from_secs(args.keep_alive * 3),
        initial_window: 256 * 1024,
        stream_receive_window: VarInt::from_u32(256 * 1024),
        cert_validation: rosh_network::CertValidationMode::default(),
    };

    // Connect to server
    debug!("Creating QUIC network transport");

    // Create transport
    let mut transport = NetworkTransport::new_client(transport_config).await?;

    info!("Establishing QUIC connection to {}", server_addr);
    let mut connection =
        match time::timeout(Duration::from_secs(5), transport.connect(server_addr)).await {
            Ok(Ok(conn)) => {
                info!("QUIC connection established successfully");
                conn
            }
            Ok(Err(e)) => {
                if let Some(ref log_path) = log_file {
                    retrieve_server_logs(&host, log_path).await;
                }
                anyhow::bail!("Failed to connect to Rosh server: {}", e)
            }
            Err(_) => {
                if let Some(ref log_path) = log_file {
                    retrieve_server_logs(&host, log_path).await;
                }
                anyhow::bail!("QUIC connection timeout after 5 seconds")
            }
        };

    // Send handshake
    let session_keys_bytes = rkyv::to_bytes::<_, 256>(&session_keys)
        .context("Failed to serialize session keys")?
        .to_vec();
    debug!(
        "Sending handshake with terminal dimensions: {}x{}",
        cols, rows
    );
    connection
        .send(NetworkMessage::Handshake {
            session_keys_bytes,
            terminal_width: cols,
            terminal_height: rows,
        })
        .await?;

    // Receive handshake acknowledgment
    debug!("Waiting for handshake acknowledgment");
    let (session_id, cipher_algorithm_u8) = match connection.receive().await? {
        NetworkMessage::HandshakeAck {
            session_id,
            cipher_algorithm,
        } => {
            debug!(
                "Received handshake ack: session_id={}, cipher={}",
                session_id, cipher_algorithm
            );
            (session_id, cipher_algorithm)
        }
        msg => anyhow::bail!("Expected handshake acknowledgment, got: {:?}", msg),
    };

    info!("Connected to session {}", session_id);

    // Convert cipher algorithm from u8
    let cipher_algorithm = match cipher_algorithm_u8 {
        0 => CipherAlgorithm::Aes128Gcm,
        1 => CipherAlgorithm::Aes256Gcm,
        2 => CipherAlgorithm::ChaCha20Poly1305,
        _ => anyhow::bail!("Unknown cipher algorithm: {}", cipher_algorithm_u8),
    };

    // Verify cipher algorithm matches
    if cipher_algorithm != args.cipher {
        anyhow::bail!("Server cipher algorithm mismatch");
    }

    // Create initial terminal state
    debug!("Creating initial terminal state");
    let initial_state = TerminalState::new(cols, rows);

    // Create state synchronizer
    let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(initial_state, false)));

    // Create channels
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Send command if provided (before entering raw mode)
    if let Some(cmd) = &args.command {
        debug!("Sending command: {}", cmd);
        // Send the command followed by newline
        let mut cmd_bytes = cmd.as_bytes().to_vec();
        cmd_bytes.push(b'\n');
        connection.send(NetworkMessage::Input(cmd_bytes)).await?;

        // Wait a bit for command to execute
        time::sleep(Duration::from_millis(100)).await;

        // Send exit command to close the shell after the command completes
        debug!("Sending exit command");
        connection
            .send(NetworkMessage::Input(b"exit\n".to_vec()))
            .await?;
    }

    // Now that all debug logging is done, create and initialize terminal UI
    info!("Bootstrap complete, switching to terminal mode");
    let mut ui = TerminalUI::new(cols, rows, state_sync.clone(), args.predict);
    ui.init()?; // This disables logging and enables raw mode

    // Spawn input handler (only if no command provided)
    let input_handle = if args.command.is_none() {
        Some(tokio::task::spawn_blocking({
            let input_tx = input_tx.clone();
            let mut shutdown_rx = shutdown_tx.subscribe();

            move || {
                loop {
                    // Check for shutdown
                    if shutdown_rx.try_recv().is_ok() {
                        break;
                    }

                    // Read input with timeout
                    if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                        match event::read() {
                            Ok(Event::Key(key_event)) => {
                                let bytes = key_to_bytes(key_event);
                                if !bytes.is_empty() {
                                    let _ = input_tx.send(bytes);
                                }
                            }
                            Ok(Event::Resize(cols, rows)) => {
                                let _ = input_tx.send(vec![0xFF, 0xFF, cols as u8, rows as u8]);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }))
    } else {
        None
    };

    // Main event loop
    let result = run_client_loop(
        &mut connection,
        &mut ui,
        state_sync,
        &mut input_rx,
        shutdown_tx.clone(),
    )
    .await;

    // Cleanup
    let _ = shutdown_tx.send(());
    if let Some(handle) = input_handle {
        let _ = handle.await;
    }
    ui.cleanup()?;

    result
}

async fn run_client_loop(
    connection: &mut Box<dyn rosh_network::Connection>,
    ui: &mut TerminalUI,
    state_sync: Arc<RwLock<StateSynchronizer>>,
    input_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    _shutdown_tx: tokio::sync::broadcast::Sender<()>,
) -> Result<()> {
    let mut ping_interval = time::interval(Duration::from_secs(30));
    let mut last_render = time::Instant::now();
    let mut last_output_time = time::Instant::now();
    let is_command_mode = input_rx.is_closed(); // If input channel is closed, we're in command mode

    loop {
        tokio::select! {
            // Handle input
            Some(input) = input_rx.recv() => {
                // Check for resize
                if input.len() == 4 && input[0] == 0xFF && input[1] == 0xFF {
                    let cols = input[2] as u16;
                    let rows = input[3] as u16;

                    connection.send(NetworkMessage::Resize(cols, rows)).await?;
                    ui.terminal.resize(cols, rows)?;
                } else {
                    // Process input locally if prediction is enabled
                    if ui.prediction_enabled {
                        ui.process_input(&input)?;
                        ui.render().await?;
                    }

                    // Send input to server
                    connection.send(NetworkMessage::Input(input)).await?;
                }
            }

            // Handle server messages
            result = connection.receive() => {
                match result? {
                    NetworkMessage::State(state_bytes) => {
                        // Deserialize state message
                        let state_msg: StateMessage = match rkyv::check_archived_root::<StateMessage>(&state_bytes) {
                            Ok(archived) => archived.deserialize(&mut rkyv::de::deserializers::SharedDeserializeMap::new())
                                .map_err(|e| anyhow::anyhow!("Failed to deserialize state message: {:?}", e))?,
                            Err(e) => anyhow::bail!("Failed to validate state message: {:?}", e),
                        };
                        match state_msg {
                            StateMessage::FullState { seq, state } => {
                                // For full state, create a new synchronizer with the received state
                                let new_sync = StateSynchronizer::new(state, false);
                                *state_sync.write().await = new_sync;

                                // Send acknowledgment
                                connection.send(NetworkMessage::StateAck(seq)).await?;
                            }
                            StateMessage::Delta { seq, delta } => {
                                // Apply delta to current state
                                let mut sync = state_sync.write().await;
                                match delta.apply(sync.current_state()) {
                                    Ok(new_state) => {
                                        // Update the synchronizer with the new state
                                        *sync = StateSynchronizer::new(new_state, false);

                                        // Send acknowledgment
                                        drop(sync); // Release the write lock before sending
                                        connection.send(NetworkMessage::StateAck(seq)).await?;

                                        debug!("Applied delta update seq={}", seq);
                                    }
                                    Err(e) => {
                                        warn!("Failed to apply delta: {}, requesting full state", e);
                                        drop(sync); // Release the write lock before sending
                                        connection.send(NetworkMessage::StateRequest).await?;
                                    }
                                }
                            }
                            StateMessage::Ack(seq) => {
                                let mut sync = state_sync.write().await;
                                sync.process_ack(seq);
                            }
                        }

                        // Render update
                        debug!("Rendering state update");
                        ui.render().await?;
                        last_render = time::Instant::now();
                        last_output_time = time::Instant::now();
                    }
                    NetworkMessage::Pong => {
                        debug!("Received pong");
                    }
                    _ => {
                        warn!("Unexpected message from server");
                    }
                }
            }

            // Send periodic ping
            _ = ping_interval.tick() => {
                connection.send(NetworkMessage::Ping).await?;
            }

            // Periodic render to handle blinking cursor
            _ = time::sleep(Duration::from_millis(500)) => {
                if last_render.elapsed() > Duration::from_millis(500) {
                    ui.render().await?;
                    last_render = time::Instant::now();
                }

                // In command mode, exit if no output for 2 seconds
                if is_command_mode && last_output_time.elapsed() > Duration::from_secs(2) {
                    debug!("No output for 2 seconds in command mode, exiting");
                    return Ok(());
                }
            }
        }
    }
}

/// Convert key event to bytes
pub fn key_to_bytes(key: KeyEvent) -> Vec<u8> {
    match key.code {
        KeyCode::Char(c) => {
            if key.modifiers.contains(KeyModifiers::CONTROL) {
                // Control sequences
                match c {
                    'a'..='z' => vec![(c as u8) - b'a' + 1],
                    'A'..='Z' => vec![(c.to_ascii_lowercase() as u8) - b'a' + 1],
                    '[' => vec![0x1B], // Escape
                    '\\' => vec![0x1C],
                    ']' => vec![0x1D],
                    '^' => vec![0x1E],
                    '_' => vec![0x1F],
                    _ => vec![],
                }
            } else {
                c.to_string().into_bytes()
            }
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::Backspace => vec![0x7F],
        KeyCode::Esc => vec![0x1B],
        KeyCode::Left => vec![0x1B, b'[', b'D'],
        KeyCode::Right => vec![0x1B, b'[', b'C'],
        KeyCode::Up => vec![0x1B, b'[', b'A'],
        KeyCode::Down => vec![0x1B, b'[', b'B'],
        KeyCode::Home => vec![0x1B, b'[', b'H'],
        KeyCode::End => vec![0x1B, b'[', b'F'],
        KeyCode::PageUp => vec![0x1B, b'[', b'5', b'~'],
        KeyCode::PageDown => vec![0x1B, b'[', b'6', b'~'],
        KeyCode::Delete => vec![0x1B, b'[', b'3', b'~'],
        KeyCode::Insert => vec![0x1B, b'[', b'2', b'~'],
        KeyCode::F(n) => match n {
            1 => vec![0x1B, b'O', b'P'],
            2 => vec![0x1B, b'O', b'Q'],
            3 => vec![0x1B, b'O', b'R'],
            4 => vec![0x1B, b'O', b'S'],
            5 => vec![0x1B, b'[', b'1', b'5', b'~'],
            6 => vec![0x1B, b'[', b'1', b'7', b'~'],
            7 => vec![0x1B, b'[', b'1', b'8', b'~'],
            8 => vec![0x1B, b'[', b'1', b'9', b'~'],
            9 => vec![0x1B, b'[', b'2', b'0', b'~'],
            10 => vec![0x1B, b'[', b'2', b'1', b'~'],
            11 => vec![0x1B, b'[', b'2', b'3', b'~'],
            12 => vec![0x1B, b'[', b'2', b'4', b'~'],
            _ => vec![],
        },
        _ => vec![],
    }
}
