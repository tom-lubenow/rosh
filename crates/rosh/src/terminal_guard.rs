//! RAII guard for terminal ownership during raw mode operations

use anyhow::Result;
use crossterm::terminal;
use tracing::subscriber::NoSubscriber;
use tracing_subscriber::util::SubscriberInitExt;

/// RAII guard that ensures exclusive ownership of terminal for raw mode operations.
/// This guard disables logging when created and restores terminal state when dropped.
pub struct TerminalGuard {
    raw_mode_enabled: bool,
    // Marker to ensure this type is !Send and !Sync
    _marker: std::marker::PhantomData<*const ()>,
}

impl TerminalGuard {
    /// Acquire exclusive access to the terminal and disable all logging.
    /// This ensures no tracing output can corrupt the terminal while in raw mode.
    pub fn acquire() -> Result<Self> {
        // Install a no-op subscriber to disable all tracing
        let _ = NoSubscriber::default().try_init();

        Ok(Self {
            raw_mode_enabled: false,
            _marker: std::marker::PhantomData,
        })
    }

    /// Enable raw mode on the terminal.
    pub fn enable_raw_mode(&mut self) -> Result<()> {
        if !self.raw_mode_enabled {
            terminal::enable_raw_mode()?;
            self.raw_mode_enabled = true;
        }
        Ok(())
    }

    /// Disable raw mode on the terminal.
    pub fn disable_raw_mode(&mut self) -> Result<()> {
        if self.raw_mode_enabled {
            terminal::disable_raw_mode()?;
            self.raw_mode_enabled = false;
        }
        Ok(())
    }

    /// Check if raw mode is currently enabled
    pub fn is_raw_mode(&self) -> bool {
        self.raw_mode_enabled
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Always try to restore terminal state
        if self.raw_mode_enabled {
            let _ = terminal::disable_raw_mode();
        }
    }
}
