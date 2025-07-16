//! Network transport layer for Rosh
//!
//! Provides reliable, encrypted communication over UDP using QUIC protocol.
//! Falls back to custom UDP protocol if QUIC is not available.

pub mod connection;
pub mod protocol;
pub mod transport;

pub use connection::{ClientConnection, Connection, QuicConnection, ServerConnection};
pub use protocol::{FramedCodec, Message, MessageStats, PROTOCOL_VERSION};
pub use quinn::VarInt;
pub use transport::{
    ClientTransportWrapper, NetworkTransport, RoshTransportConfig, ServerTransportWrapper,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Timeout")]
    Timeout,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] rosh_crypto::CryptoError),
}
