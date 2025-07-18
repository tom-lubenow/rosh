//! High-level PTY session management
//!
//! Provides session handling with terminal emulation integration

use crate::{
    pty::{AsyncPtyMaster, Pty, PtyProcess},
    PtyError,
};
use rosh_terminal::{framebuffer_to_state, Terminal, TerminalState};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error};

/// Events that can occur in a PTY session
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Terminal state has changed
    StateChanged(TerminalState),

    /// Process has exited
    ProcessExited(i32),

    /// Error occurred
    Error(String),
}

/// A PTY session with terminal emulation
pub struct PtySession {
    /// The PTY process
    process: PtyProcess,

    /// Terminal emulator
    terminal: Arc<Mutex<Terminal>>,

    /// Event sender
    event_tx: mpsc::UnboundedSender<SessionEvent>,

    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,

    /// Write half of the PTY (set after start)
    write_half: Option<Arc<Mutex<tokio::io::WriteHalf<AsyncPtyMaster>>>>,
}

impl PtySession {
    /// Create a new PTY session with the given command
    pub async fn new(
        command: Command,
        rows: u16,
        cols: u16,
    ) -> Result<(Self, mpsc::UnboundedReceiver<SessionEvent>), PtyError> {
        // Allocate PTY
        let mut pty = Pty::new()?;
        pty.resize(rows, cols)?;

        // Spawn process
        let process = pty.spawn(command)?;

        // Create terminal emulator
        let terminal = Arc::new(Mutex::new(Terminal::new(cols, rows)));

        // Create event channel
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        // Create shutdown channel
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);

        let session = Self {
            process,
            terminal,
            event_tx,
            shutdown_tx: Some(shutdown_tx),
            write_half: None,
        };

        Ok((session, event_rx))
    }

    /// Start the session I/O loop
    pub async fn start(mut self) -> Result<(), PtyError> {
        let pid = self.process.pid();
        let master = self.process.take_master();
        let async_master = AsyncPtyMaster::new(master)?;

        let (read_half, write_half) = tokio::io::split(async_master);
        let read_half = Arc::new(Mutex::new(read_half));
        let write_half = Arc::new(Mutex::new(write_half));

        let terminal = self.terminal.clone();
        let event_tx = self.event_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        // Store write half for input handling
        self.write_half = Some(write_half.clone());

        // Spawn read task
        let read_terminal = terminal.clone();
        let read_tx = event_tx.clone();
        let read_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];

            loop {
                tokio::select! {
                    // Read from PTY
                    result = async {
                        let mut read_guard = read_half.lock().await;
                        read_guard.read(&mut buffer).await
                    } => {
                        match result {
                            Ok(0) => {
                                debug!("PTY closed");
                                break;
                            }
                            Ok(n) => {
                                // Process data through terminal emulator
                                let mut term = read_terminal.lock().await;
                                term.process(&buffer[..n]);

                                // Send state update
                                let state = framebuffer_to_state(term.framebuffer(), term.title());
                                if read_tx.send(SessionEvent::StateChanged(state)).is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("PTY read error: {}", e);
                                let _ = read_tx.send(SessionEvent::Error(e.to_string()));
                                break;
                            }
                        }
                    }

                    // Shutdown signal
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("Session shutdown requested");
                            break;
                        }
                    }
                }
            }
        });

        // Wait for process exit
        let exit_tx = event_tx.clone();
        let wait_task = tokio::task::spawn_blocking(move || {
            use nix::sys::wait::{waitpid, WaitStatus};

            match waitpid(pid, None) {
                Ok(WaitStatus::Exited(_, code)) => {
                    let _ = exit_tx.send(SessionEvent::ProcessExited(code));
                    code
                }
                Ok(WaitStatus::Signaled(_, signal, _)) => {
                    let code = 128 + signal as i32;
                    let _ = exit_tx.send(SessionEvent::ProcessExited(code));
                    code
                }
                _ => -1,
            }
        });

        // Wait for tasks to complete
        let _ = tokio::join!(read_task, wait_task);

        Ok(())
    }

    /// Send input to the PTY
    pub async fn write_input(&self, data: &[u8]) -> Result<(), PtyError> {
        if let Some(write_half) = &self.write_half {
            write_half.lock().await.write_all(data).await?;
            write_half.lock().await.flush().await?;
        }
        Ok(())
    }

    /// Resize the terminal
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<(), PtyError> {
        // Resize PTY
        let winsize = nix::pty::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let fd = self.process.master().as_raw_fd();
        unsafe {
            let ret = libc::ioctl(fd, libc::TIOCSWINSZ, &winsize as *const _);
            if ret < 0 {
                return Err(PtyError::IoError(std::io::Error::last_os_error()));
            }
        }

        // Resize terminal emulator
        let mut term = self.terminal.lock().await;
        term.resize(cols, rows)?;

        // Send updated state
        let state = framebuffer_to_state(term.framebuffer(), term.title());
        let _ = self.event_tx.send(SessionEvent::StateChanged(state));

        Ok(())
    }

    /// Get current terminal state
    pub async fn get_state(&self) -> TerminalState {
        let term = self.terminal.lock().await;
        framebuffer_to_state(term.framebuffer(), term.title())
    }

    /// Kill the process
    pub fn kill(&self) -> Result<(), PtyError> {
        self.process.kill()
    }

    /// Shutdown the session
    pub fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(true);
        }
    }
}

/// Builder for creating PTY sessions
pub struct SessionBuilder {
    command: Option<Command>,
    rows: u16,
    cols: u16,
    env_vars: Vec<(String, String)>,
}

impl SessionBuilder {
    /// Create a new session builder
    pub fn new() -> Self {
        Self {
            command: None,
            rows: 24,
            cols: 80,
            env_vars: Vec::new(),
        }
    }

    /// Set the command to run
    pub fn command(mut self, command: Command) -> Self {
        self.command = Some(command);
        self
    }

    /// Set terminal dimensions
    pub fn dimensions(mut self, rows: u16, cols: u16) -> Self {
        self.rows = rows;
        self.cols = cols;
        self
    }

    /// Add an environment variable
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.push((key.into(), value.into()));
        self
    }

    /// Build and start the session
    pub async fn build(
        self,
    ) -> Result<(PtySession, mpsc::UnboundedReceiver<SessionEvent>), PtyError> {
        let mut command = self.command.unwrap_or_else(|| {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            Command::new(shell)
        });

        // Apply environment variables
        for (key, value) in self.env_vars {
            command.env(key, value);
        }

        // Set TERM environment variable
        command.env("TERM", "xterm-256color");

        PtySession::new(command, self.rows, self.cols).await
    }
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {}
