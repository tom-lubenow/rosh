//! Rosh client implementation

use anyhow::{Context, Result};
use rkyv::Deserialize;
use clap::{Parser, ValueEnum};
use rosh_crypto::{CipherAlgorithm, SessionKeys, KeyDerivation};
use rosh_network::{NetworkTransport, RoshTransportConfig, Message as NetworkMessage, VarInt};
use rosh_state::{StateSynchronizer, StateMessage, StateUpdate, CompressionAlgorithm};
use rosh_terminal::{Terminal, TerminalState, state_to_framebuffer};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self, ClearType},
    cursor,
    style::{self, Color, Attribute},
};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time;
use tracing::{info, warn, debug};

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
    /// Server address to connect to
    server: SocketAddr,
    
    /// Session key (base64 encoded)
    #[arg(short, long)]
    key: String,
    
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
    
    info!("Connecting to Rosh server at {}", args.server);
    
    // Decode session key
    use base64::Engine;
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&args.key)
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
    let mut connection = transport.connect(args.server).await?;
    
    // Send handshake
    let session_keys_bytes = rkyv::to_bytes::<_, 256>(&session_keys)
        .context("Failed to serialize session keys")?
        .to_vec();
    connection.send(NetworkMessage::Handshake {
        session_keys_bytes,
        terminal_width: cols,
        terminal_height: rows,
    }).await?;
    
    // Receive handshake acknowledgment
    let (session_id, cipher_algorithm_u8) = match connection.receive().await? {
        NetworkMessage::HandshakeAck { session_id, cipher_algorithm } => {
            (session_id, cipher_algorithm)
        }
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
    let state_sync = Arc::new(RwLock::new(
        StateSynchronizer::new(initial_state, false)
    ));
    
    // Create terminal UI
    let mut ui = TerminalUI::new(cols, rows, state_sync.clone(), args.predict);
    ui.init()?;
    
    // Create channels
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    
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
    ).await;
    
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
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
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
                                // For now, just request full state on delta
                                // TODO: Implement proper delta handling
                                warn!("Delta updates not yet implemented, requesting full state");
                                connection.send(NetworkMessage::StateRequest).await?;
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
                    '[' => vec![0x1B],  // Escape
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
        KeyCode::F(n) => {
            match n {
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
            }
        }
        _ => vec![],
    }
}