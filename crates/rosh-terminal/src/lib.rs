//! Terminal emulation for Rosh
//!
//! Provides VT100/xterm compatible terminal emulation with support for
//! modern terminal features including true color, unicode, and advanced cursor control.

pub mod display;
pub mod emulator;
pub mod framebuffer;
pub mod parser;
pub mod state;

pub use display::{framebuffer_to_state, render_row_ansi, state_to_cells, state_to_framebuffer};
pub use emulator::{Terminal, TerminalSnapshot};
pub use framebuffer::{Attributes, Cell, Color, FrameBuffer};
pub use parser::Parser;
pub use state::TerminalState;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TerminalError {
    #[error("Invalid escape sequence")]
    InvalidEscapeSequence,

    #[error("Unsupported terminal capability: {0}")]
    UnsupportedCapability(String),

    #[error("Terminal size error: {0}")]
    SizeError(String),

    #[error("UTF-8 decoding error")]
    Utf8Error(#[from] std::str::Utf8Error),
}
