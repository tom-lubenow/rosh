//! Protocol message definitions and framing for Rosh
//!
//! Uses rkyv for zero-copy serialization of messages

use crate::NetworkError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rkyv::{Archive, Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Message types in the Rosh protocol
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[archive(check_bytes)]
pub enum Message {
    /// Initial handshake from client
    Handshake {
        /// Serialized session keys
        session_keys_bytes: Vec<u8>,
        terminal_width: u16,
        terminal_height: u16,
    },

    /// Server response to handshake
    HandshakeAck {
        session_id: u64,
        /// Cipher algorithm as u8 (0=AES128GCM, 1=AES256GCM, 2=ChaCha20Poly1305)
        cipher_algorithm: u8,
    },

    /// Initial handshake from client (legacy)
    ClientHello {
        version: u32,
        session_id: Option<u64>, // For resumption
    },

    /// Server response to handshake (legacy)
    ServerHello { version: u32, session_id: u64 },

    /// User input from client
    Input(Vec<u8>),

    /// Terminal resize notification
    Resize(u16, u16),

    /// State message wrapper (serialized)
    State(Vec<u8>),

    /// State acknowledgment
    StateAck(u64),

    /// Request full state
    StateRequest,

    /// Terminal state update (legacy)
    StateUpdate {
        /// Sequence number of this state
        seq_num: u64,
        /// Acknowledgment of received state
        ack_num: u64,
        /// Compressed state diff
        diff: Vec<u8>,
        /// Timestamp for RTT calculation
        timestamp: u64,
    },

    /// Acknowledgment without state update (legacy)
    Ack { ack_num: u64, timestamp: u64 },

    /// User input from client (legacy)
    UserInput {
        seq_num: u64,
        ack_num: u64,
        /// Serialized user input events
        input: Vec<u8>,
        timestamp: u64,
    },

    /// Heartbeat/keepalive
    Ping,

    /// Response to ping
    Pong,

    /// Request full state sync (legacy)
    SyncRequest { last_known_seq: u64 },

    /// Full state for sync (legacy)
    SyncResponse {
        seq_num: u64,
        /// Compressed full state
        state: Vec<u8>,
    },
}

impl Message {
    /// Get current timestamp in microseconds
    pub fn timestamp_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Bytes, NetworkError> {
        let bytes = rkyv::to_bytes::<_, 256>(self)
            .map_err(|e| NetworkError::ProtocolError(format!("Serialization failed: {e}")))?;
        Ok(Bytes::from(bytes.to_vec()))
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetworkError> {
        let archived = rkyv::check_archived_root::<Self>(bytes)
            .map_err(|e| NetworkError::ProtocolError(format!("Validation failed: {e}")))?;

        let deserialized: Self = archived
            .deserialize(&mut rkyv::Infallible)
            .map_err(|e| NetworkError::ProtocolError(format!("Deserialization failed: {e}")))?;

        Ok(deserialized)
    }
}

/// Frame encoder/decoder for message stream
pub struct FramedCodec;

impl FramedCodec {
    /// Encode a message with length prefix
    pub fn encode(msg: &Message, buf: &mut BytesMut) -> Result<(), NetworkError> {
        let payload = msg.to_bytes()?;

        // Write 4-byte length prefix (big-endian)
        if payload.len() > u32::MAX as usize {
            return Err(NetworkError::ProtocolError("Message too large".to_string()));
        }

        buf.put_u32(payload.len() as u32);
        buf.extend_from_slice(&payload);

        Ok(())
    }

    /// Decode a message from buffer
    /// Returns Some(message) if a complete message is available, None if more data needed
    pub fn decode(buf: &mut BytesMut) -> Result<Option<Message>, NetworkError> {
        if buf.len() < 4 {
            return Ok(None); // Need more data for length prefix
        }

        // Peek at length without consuming
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&buf[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if buf.len() < 4 + length {
            return Ok(None); // Need more data for complete message
        }

        // Consume length prefix
        buf.advance(4);

        // Extract message bytes into a properly aligned vector
        let msg_bytes = buf.split_to(length).to_vec();

        // Deserialize message
        Message::from_bytes(&msg_bytes).map(Some)
    }
}

/// Message statistics for debugging/monitoring
#[derive(Debug, Default, Clone)]
pub struct MessageStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_rtt_micros: Option<u64>,
}

impl MessageStats {
    /// Update RTT based on timestamp echo
    pub fn update_rtt(&mut self, sent_timestamp: u64) {
        let now = Message::timestamp_now();
        if now > sent_timestamp {
            self.last_rtt_micros = Some(now - sent_timestamp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = Message::Ping { timestamp: 12345 };

        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();

        match decoded {
            Message::Ping { timestamp } => assert_eq!(timestamp, 12345),
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_framed_codec() {
        let msg1 = Message::Ack {
            ack_num: 42,
            timestamp: 1000,
        };

        let msg2 = Message::Ping { timestamp: 2000 };

        let mut buf = BytesMut::new();

        // Encode two messages
        FramedCodec::encode(&msg1, &mut buf).unwrap();
        FramedCodec::encode(&msg2, &mut buf).unwrap();

        // Decode first message
        let decoded1 = FramedCodec::decode(&mut buf).unwrap().unwrap();
        match decoded1 {
            Message::Ack { ack_num, timestamp } => {
                assert_eq!(ack_num, 42);
                assert_eq!(timestamp, 1000);
            }
            _ => panic!("Wrong message type"),
        }

        // Decode second message
        let decoded2 = FramedCodec::decode(&mut buf).unwrap().unwrap();
        match decoded2 {
            Message::Ping { timestamp } => assert_eq!(timestamp, 2000),
            _ => panic!("Wrong message type"),
        }

        // Buffer should be empty
        assert_eq!(buf.len(), 0);
    }
}
