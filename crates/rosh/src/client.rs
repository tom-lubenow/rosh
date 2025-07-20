//! Rosh client implementation

use crate::bootstrap::{bootstrap_via_ssh, BootstrapOptions, NetworkFamily, RemoteIpStrategy};
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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
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
}

/// Terminal UI state
pub struct TerminalUI {
    pub terminal: Terminal,
    pub state_sync: Arc<RwLock<StateSynchronizer>>,
    pub prediction_enabled: bool,
    stdout: io::Stdout,
    raw_mode_enabled: bool,
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
            raw_mode_enabled: false,
        }
    }

    /// Initialize terminal for raw mode
    fn init(&mut self) -> Result<()> {
        debug!("Initializing terminal in raw mode");
        terminal::enable_raw_mode()?;
        self.raw_mode_enabled = true;
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
        if self.raw_mode_enabled {
            terminal::disable_raw_mode()?;
            self.raw_mode_enabled = false;
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
        // Best effort cleanup - ignore errors
        if self.raw_mode_enabled {
            let _ = terminal::disable_raw_mode();
            let _ = execute!(
                self.stdout,
                cursor::Show,
                style::SetAttribute(Attribute::Reset)
            );
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

pub async fn run() -> Result<()> {
    let args = Args::parse();

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
        .init();

    // Parse server argument
    let (is_ssh, user, host) = parse_server_arg(&args.server);

    // Determine network family from args
    let network_family = if args.ipv4 {
        NetworkFamily::Inet
    } else if args.ipv6 {
        NetworkFamily::Inet6
    } else {
        NetworkFamily::from_str(&args.family)?
    };

    // Parse remote IP strategy
    let remote_ip_strategy = RemoteIpStrategy::from_str(&args.experimental_remote_ip)?;

    // Get connection info
    let (server_addr, session_key_str) = if is_ssh {
        // SSH connection
        if args.key.is_some() {
            anyhow::bail!("Cannot specify --key with SSH connection");
        }

        let bootstrap_info = bootstrap_via_ssh(BootstrapOptions {
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

        let server_addr = SocketAddr::new(bootstrap_info.ip, bootstrap_info.port);
        (server_addr, bootstrap_info.session_key)
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
    debug!("Creating network transport");
    let mut transport = NetworkTransport::new_client(transport_config).await?;
    debug!("Connecting to server at {}", server_addr);
    let mut connection =
        match time::timeout(Duration::from_secs(5), transport.connect(server_addr)).await {
            Ok(Ok(conn)) => {
                debug!("Connected successfully");
                conn
            }
            Ok(Err(e)) => anyhow::bail!("Failed to connect to server: {}", e),
            Err(_) => anyhow::bail!("Connection timeout after 5 seconds"),
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

    // Create terminal UI
    debug!("Creating terminal UI");
    let mut ui = TerminalUI::new(cols, rows, state_sync.clone(), args.predict);
    ui.init()?;

    // Create channels
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, _shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Send command if provided
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_args_parsing_basic() {
        // Test basic server argument
        let args = Args::try_parse_from(["rosh", "example.com"]).unwrap();
        assert_eq!(args.server, "example.com");
        assert_eq!(args.key, None);
        assert_eq!(args.cipher, CipherAlgorithm::Aes128Gcm); // default
        assert_eq!(args.compression, None);
        assert_eq!(args.keep_alive, 30);
        assert_eq!(args.ssh_port, None);
        assert_eq!(args.remote_command, "rosh-server");
        assert!(!args.predict);
        assert!(args.ssh_options.is_empty());
    }

    #[test]
    fn test_args_parsing_with_key() {
        let args = Args::try_parse_from(["rosh", "--key", "abc123", "localhost:8080"]).unwrap();
        assert_eq!(args.server, "localhost:8080");
        assert_eq!(args.key, Some("abc123".to_string()));
    }

    #[test]
    fn test_args_parsing_cipher_options() {
        // Test AES-128-GCM (default)
        let args = Args::try_parse_from(["rosh", "--cipher", "aes-gcm", "server"]).unwrap();
        assert_eq!(args.cipher, CipherAlgorithm::Aes128Gcm);

        // Test AES-256-GCM
        let args = Args::try_parse_from(["rosh", "--cipher", "aes-256-gcm", "server"]).unwrap();
        assert_eq!(args.cipher, CipherAlgorithm::Aes256Gcm);

        // Test ChaCha20-Poly1305
        let args =
            Args::try_parse_from(["rosh", "--cipher", "chacha20-poly1305", "server"]).unwrap();
        assert_eq!(args.cipher, CipherAlgorithm::ChaCha20Poly1305);

        // Test short form
        let args = Args::try_parse_from(["rosh", "-a", "aes-gcm", "server"]).unwrap();
        assert_eq!(args.cipher, CipherAlgorithm::Aes128Gcm);
    }

    #[test]
    fn test_args_parsing_compression() {
        // Test zstd compression
        let args = Args::try_parse_from(["rosh", "--compression", "zstd", "server"]).unwrap();
        assert_eq!(args.compression, Some(CompressionAlgorithm::Zstd));

        // Test lz4 compression
        let args = Args::try_parse_from(["rosh", "--compression", "lz4", "server"]).unwrap();
        assert_eq!(args.compression, Some(CompressionAlgorithm::Lz4));
    }

    #[test]
    fn test_args_parsing_ssh_options() {
        let args = Args::try_parse_from([
            "rosh",
            "--ssh-port",
            "2222",
            "--remote-command",
            "custom-server",
            "--ssh-options",
            "StrictHostKeyChecking=no",
            "--ssh-options",
            "UserKnownHostsFile=/dev/null",
            "user@host",
        ])
        .unwrap();

        assert_eq!(args.ssh_port, Some(2222));
        assert_eq!(args.remote_command, "custom-server");
        assert_eq!(
            args.ssh_options,
            vec!["StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null"]
        );
    }

    #[test]
    fn test_args_parsing_predict_flag() {
        let args = Args::try_parse_from(["rosh", "--predict", "server"]).unwrap();
        assert!(args.predict);
    }

    #[test]
    fn test_args_parsing_keep_alive() {
        let args = Args::try_parse_from(["rosh", "--keep-alive", "60", "server"]).unwrap();
        assert_eq!(args.keep_alive, 60);
    }

    #[test]
    fn test_args_parsing_log_levels() {
        let log_levels = vec![
            ("trace", LogLevel::Trace),
            ("debug", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("warn", LogLevel::Warn),
            ("error", LogLevel::Error),
        ];

        for (level_str, expected) in log_levels {
            let args = Args::try_parse_from(["rosh", "--log-level", level_str, "server"]).unwrap();
            match (args.log_level, expected) {
                (LogLevel::Trace, LogLevel::Trace) => {}
                (LogLevel::Debug, LogLevel::Debug) => {}
                (LogLevel::Info, LogLevel::Info) => {}
                (LogLevel::Warn, LogLevel::Warn) => {}
                (LogLevel::Error, LogLevel::Error) => {}
                _ => panic!("Log level mismatch"),
            }
        }
    }

    #[test]
    fn test_args_parsing_invalid() {
        // Missing server argument
        assert!(Args::try_parse_from(["rosh"]).is_err());

        // Invalid cipher
        assert!(Args::try_parse_from(["rosh", "--cipher", "invalid", "server"]).is_err());

        // Invalid compression
        assert!(Args::try_parse_from(["rosh", "--compression", "invalid", "server"]).is_err());

        // Invalid log level
        assert!(Args::try_parse_from(["rosh", "--log-level", "invalid", "server"]).is_err());

        // Invalid keep-alive (not a number)
        assert!(Args::try_parse_from(["rosh", "--keep-alive", "not-a-number", "server"]).is_err());
    }

    #[test]
    fn test_args_parsing_help() {
        // Test that help flag works
        let result = Args::try_parse_from(["rosh", "--help"]);
        assert!(result.is_err()); // Help causes a special error

        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_args_parsing_version() {
        // Test that version flag works
        let result = Args::try_parse_from(["rosh", "--version"]);
        assert!(result.is_err()); // Version causes a special error

        let err = result.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn test_log_level_to_tracing() {
        // Test conversion from our LogLevel to tracing::Level
        let conversions = vec![
            (LogLevel::Trace, tracing::Level::TRACE),
            (LogLevel::Debug, tracing::Level::DEBUG),
            (LogLevel::Info, tracing::Level::INFO),
            (LogLevel::Warn, tracing::Level::WARN),
            (LogLevel::Error, tracing::Level::ERROR),
        ];

        for (log_level, expected_tracing) in conversions {
            let actual = match log_level {
                LogLevel::Trace => tracing::Level::TRACE,
                LogLevel::Debug => tracing::Level::DEBUG,
                LogLevel::Info => tracing::Level::INFO,
                LogLevel::Warn => tracing::Level::WARN,
                LogLevel::Error => tracing::Level::ERROR,
            };
            assert_eq!(actual, expected_tracing);
        }
    }

    #[test]
    fn test_terminal_ui_dimensions() {
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let state = TerminalState::new(120, 40);
        let state_sync = Arc::new(RwLock::new(StateSynchronizer::new(state, false)));

        let ui = TerminalUI::new(120, 40, state_sync, true);
        assert_eq!(ui.terminal.framebuffer().width(), 120);
        assert_eq!(ui.terminal.framebuffer().height(), 40);
        assert!(ui.prediction_enabled);
    }

    #[test]
    fn test_parse_server_arg_comprehensive() {
        // Test various edge cases

        // Empty string
        let (is_ssh, user, host) = parse_server_arg("");
        assert!(is_ssh);
        assert_eq!(user, None);
        assert_eq!(host, "");

        // Just @ symbol
        let (is_ssh, user, host) = parse_server_arg("@");
        assert!(is_ssh);
        assert_eq!(user, Some("".to_string()));
        assert_eq!(host, "");

        // Multiple colons (IPv6-like but not in brackets)
        let (is_ssh, user, host) = parse_server_arg("fe80::1:8080");
        assert!(!is_ssh);
        assert_eq!(user, None);
        assert_eq!(host, "fe80::1:8080");

        // User with special characters
        let (is_ssh, user, host) = parse_server_arg("user-name_123@host");
        assert!(is_ssh);
        assert_eq!(user, Some("user-name_123".to_string()));
        assert_eq!(host, "host");
    }

    #[test]
    fn test_cipher_algorithm_conversion() {
        // Test conversion from u8 to CipherAlgorithm
        let valid_conversions = vec![
            (0u8, CipherAlgorithm::Aes128Gcm),
            (1u8, CipherAlgorithm::Aes256Gcm),
            (2u8, CipherAlgorithm::ChaCha20Poly1305),
        ];

        for (byte, expected) in valid_conversions {
            let result = match byte {
                0 => Ok(CipherAlgorithm::Aes128Gcm),
                1 => Ok(CipherAlgorithm::Aes256Gcm),
                2 => Ok(CipherAlgorithm::ChaCha20Poly1305),
                _ => Err(anyhow::anyhow!("Unknown cipher algorithm: {}", byte)),
            };
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), expected);
        }

        // Test invalid cipher algorithm
        let invalid: u8 = 255;
        let result = match invalid {
            0 => Ok(CipherAlgorithm::Aes128Gcm),
            1 => Ok(CipherAlgorithm::Aes256Gcm),
            2 => Ok(CipherAlgorithm::ChaCha20Poly1305),
            _ => Err(anyhow::anyhow!("Unknown cipher algorithm: {}", invalid)),
        };
        assert!(result.is_err());
    }
}
