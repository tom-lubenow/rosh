//! Terminal emulation for Rosh
//! 
//! Provides VT100/xterm compatible terminal emulation with support for
//! modern terminal features including true color, unicode, and advanced cursor control.

pub mod emulator;
pub mod parser;
pub mod framebuffer;
pub mod display;
pub mod state;

pub use emulator::{Terminal, TerminalSnapshot};
pub use framebuffer::{FrameBuffer, Cell, Color, Attributes};
pub use parser::Parser;
pub use display::{framebuffer_to_state, state_to_cells, render_row_ansi, state_to_framebuffer};
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