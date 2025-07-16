//! PTY (Pseudo-Terminal) handling for Rosh
//! 
//! Provides cross-platform PTY allocation and management for running
//! shell sessions and terminal applications.

pub mod pty;
pub mod session;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PtyError {
    #[error("Failed to allocate PTY: {0}")]
    AllocationFailed(String),
    
    #[error("Failed to spawn process: {0}")]
    SpawnFailed(String),
    
    #[error("PTY I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Unsupported platform")]
    UnsupportedPlatform,
}