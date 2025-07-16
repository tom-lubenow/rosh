//! State synchronization for Rosh
//! 
//! Implements efficient state synchronization between client and server
//! using rkyv for zero-copy serialization and compression for bandwidth efficiency.

pub mod sync;
pub mod diff;
pub mod compress;
pub mod predictor;

pub use sync::{StateSynchronizer, StateUpdate};
pub use diff::StateDiff;
pub use compress::{Compressor, CompressionAlgorithm, AdaptiveCompressor};
pub use predictor::{Predictor, UserInput, KeyCode};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("State divergence detected")]
    StateDivergence,
    
    #[error("Compression error: {0}")]
    CompressionError(String),
}