//! State synchronization for Rosh
//!
//! Implements efficient state synchronization between client and server
//! using rkyv for zero-copy serialization and compression for bandwidth efficiency.

pub mod compress;
pub mod diff;
pub mod predictor;
pub mod sync;

pub use compress::{AdaptiveCompressor, CompressionAlgorithm, Compressor};
pub use diff::StateDiff;
pub use predictor::{KeyCode, Predictor, UserInput};
pub use sync::{StateMessage, StateSynchronizer, StateUpdate};

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
