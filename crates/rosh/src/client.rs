//! Rosh client implementation

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
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use tracing::{debug, info, warn};

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

    /// Enable predictive echo
    #[arg(long)]
    predict: bool,

    /// SSH port (for SSH connections)
    #[arg(long, default_value = "22")]
    ssh_port: u16,

    /// Remote command to start server (for SSH connections)
    #[arg(long, default_value = "rosh-server")]
    remote_command: String,

    /// Additional SSH options
    #[arg(long)]
    ssh_options: Vec<String>,
}

/// Terminal UI state
struct TerminalUI {
    terminal: Terminal,
    state_sync: Arc<RwLock<StateSynchronizer>>,
    prediction_enabled: bool,
    stdout: io::Stdout,
}

impl TerminalUI {
    fn new(
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
        }
    }

    /// Initialize terminal for raw mode
    fn init(&mut self) -> Result<()> {
        terminal::enable_raw_mode()?;
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
        terminal::disable_raw_mode()?;
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

/// Connection info returned from SSH
#[derive(Debug)]
struct ConnectionInfo {
    host: String,
    port: u16,
    session_key: String,
}

/// Parse server argument to determine connection type
fn parse_server_arg(server: &str) -> (bool, Option<String>, String) {
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

/// Start server via SSH and get connection info
async fn start_server_via_ssh(
    user: Option<&str>,
    host: &str,
    ssh_port: u16,
    remote_command: &str,
    ssh_options: &[String],
    cipher: CipherAlgorithm,
    compression: Option<CompressionAlgorithm>,
) -> Result<ConnectionInfo> {
    info!("Starting server on {} via SSH", host);

    // Build SSH command
    let mut ssh_cmd = Command::new("ssh");

    // Add SSH options
    ssh_cmd.arg("-p").arg(ssh_port.to_string());
    ssh_cmd.arg("-o").arg("ControlMaster=no");
    ssh_cmd.arg("-o").arg("ControlPath=none");

    for opt in ssh_options {
        ssh_cmd.arg("-o").arg(opt);
    }

    // Add user@host or just host
    if let Some(user) = user {
        ssh_cmd.arg(format!("{user}@{host}"));
    } else {
        ssh_cmd.arg(host);
    }

    // Build remote command
    let mut remote_args = vec![
        remote_command.to_string(),
        "--bind".to_string(),
        "127.0.0.1:0".to_string(), // Bind to random port
        "--one-shot".to_string(),  // Exit after one connection
    ];

    // Add cipher and compression options
    match cipher {
        CipherAlgorithm::Aes128Gcm => {
            remote_args.extend(["--cipher".to_string(), "aes128-gcm".to_string()])
        }
        CipherAlgorithm::Aes256Gcm => {
            remote_args.extend(["--cipher".to_string(), "aes256-gcm".to_string()])
        }
        CipherAlgorithm::ChaCha20Poly1305 => {
            remote_args.extend(["--cipher".to_string(), "chacha20-poly1305".to_string()])
        }
    }

    if let Some(comp) = compression {
        match comp {
            CompressionAlgorithm::Zstd => {
                remote_args.extend(["--compression".to_string(), "zstd".to_string()])
            }
            CompressionAlgorithm::Lz4 => {
                remote_args.extend(["--compression".to_string(), "lz4".to_string()])
            }
        }
    }

    // Join args with proper escaping
    let remote_cmd_str = remote_args.join(" ");
    ssh_cmd.arg(remote_cmd_str);

    // Set up process
    ssh_cmd.stdout(Stdio::piped());
    ssh_cmd.stderr(Stdio::piped());

    let mut child = ssh_cmd.spawn().context("Failed to spawn SSH process")?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stdout from SSH"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stderr from SSH"))?;

    let mut stdout_reader = BufReader::new(stdout);
    let mut stderr_reader = BufReader::new(stderr);

    // Read output looking for connection info
    let mut session_key = None;
    let mut port = None;

    // We expect output like:
    // ROSH_PORT=12345
    // ROSH_KEY=base64encodedkey

    let timeout = Duration::from_secs(10);
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("Timeout waiting for server to start");
        }

        // Try to read from stdout and stderr
        let mut stdout_line = String::new();
        let mut stderr_line = String::new();

        tokio::select! {
            result = stdout_reader.read_line(&mut stdout_line) => {
                if result? == 0 {
                    break; // EOF
                }

                let line = stdout_line.trim();
                if line.starts_with("ROSH_PORT=") {
                    port = Some(line.strip_prefix("ROSH_PORT=").unwrap().parse::<u16>()
                        .context("Failed to parse port")?);
                } else if line.starts_with("ROSH_KEY=") {
                    session_key = Some(line.strip_prefix("ROSH_KEY=").unwrap().to_string());
                }
            }

            result = stderr_reader.read_line(&mut stderr_line) => {
                if result? > 0 {
                    debug!("SSH stderr: {}", stderr_line.trim());
                }
            }

            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Check if we have all info
                if session_key.is_some() && port.is_some() {
                    break;
                }
            }
        }

        if session_key.is_some() && port.is_some() {
            break;
        }
    }

    // Kill SSH process once we have the info
    let _ = child.kill().await;

    let session_key =
        session_key.ok_or_else(|| anyhow::anyhow!("Server did not provide session key"))?;
    let port = port.ok_or_else(|| anyhow::anyhow!("Server did not provide port"))?;

    Ok(ConnectionInfo {
        host: host.to_string(),
        port,
        session_key,
    })
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

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_writer(io::stderr)
        .init();

    // Parse server argument
    let (is_ssh, user, host) = parse_server_arg(&args.server);

    // Get connection info
    let (server_addr, session_key_str) = if is_ssh {
        // SSH connection
        if args.key.is_some() {
            anyhow::bail!("Cannot specify --key with SSH connection");
        }

        let conn_info = start_server_via_ssh(
            user.as_deref(),
            &host,
            args.ssh_port,
            &args.remote_command,
            &args.ssh_options,
            args.cipher,
            args.compression,
        )
        .await?;

        // Resolve hostname to IP
        let addr_str = format!("{}:{}", conn_info.host, conn_info.port);
        let mut addrs = addr_str
            .to_socket_addrs()
            .with_context(|| format!("Failed to resolve {addr_str}"))?;
        let server_addr = addrs
            .next()
            .ok_or_else(|| anyhow::anyhow!("No addresses found for {}", addr_str))?;

        (server_addr, conn_info.session_key)
    } else {
        // Direct connection
        let session_key = args
            .key
            .ok_or_else(|| anyhow::anyhow!("--key required for direct connection"))?;

        let server_addr: SocketAddr = args
            .server
            .parse()
            .with_context(|| format!("Failed to parse server address: {}", args.server))?;

        (server_addr, session_key)
    };

    info!("Connecting to Rosh server at {}", server_addr);

    // Decode session key
    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&session_key_str)
        .context("Failed to decode session key")?;

    // Derive session keys
    let mut key_derivation = KeyDerivation::new(&key_bytes);
    let session_keys = SessionKeys {
        client_write_key: key_derivation.derive_key(b"client write"),
        server_write_key: key_derivation.derive_key(b"server write"),
    };

    // Get terminal dimensions
    let (cols, rows) = terminal::size()?;

    // Create transport config
    let transport_config = RoshTransportConfig {
        keep_alive_interval: Duration::from_secs(args.keep_alive),
        max_idle_timeout: Duration::from_secs(args.keep_alive * 3),
        initial_window: 256 * 1024,
        stream_receive_window: VarInt::from_u32(256 * 1024),
    };

    // Connect to server
    let mut transport = NetworkTransport::new_client(transport_config).await?;
    let mut connection = transport.connect(server_addr).await?;

    // Send handshake
    let session_keys_bytes = rkyv::to_bytes::<_, 256>(&session_keys)
        .context("Failed to serialize session keys")?
        .to_vec();
    connection
        .send(NetworkMessage::Handshake {
            session_keys_bytes,
            terminal_width: cols,
            terminal_height: rows,
        })
        .await?;

    // Receive handshake acknowledgment
    let (session_id, cipher_algorithm_u8) = match connection.receive().await? {
        NetworkMessage::HandshakeAck {
            session_id,
            cipher_algorithm,
        } => (session_id, cipher_algorithm),
        _ => anyhow::bail!("Expected handshake acknowledgment"),
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
    let initial_state = TerminalState::new(cols, rows);

    // Create state synchronizer
    let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(initial_state, false)));

    // Create terminal UI
    let mut ui = TerminalUI::new(cols, rows, state_sync.clone(), args.predict);
    ui.init()?;

    // Create channels
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Spawn input handler
    let input_handle = tokio::task::spawn_blocking({
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
    });

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
    let _ = input_handle.await;
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
                        ui.render().await?;
                        last_render = time::Instant::now();
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
            }
        }
    }
}

/// Convert key event to bytes
fn key_to_bytes(key: KeyEvent) -> Vec<u8> {
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
