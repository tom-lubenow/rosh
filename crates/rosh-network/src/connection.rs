//! High-level connection management for Rosh
//!
//! Provides encrypted, reliable message exchange over QUIC

use crate::transport::{ClientTransport, IncomingConnection, RoshTransportConfig, ServerTransport};
use crate::{
    protocol::{FramedCodec, Message, MessageStats},
    NetworkError,
};
use async_trait::async_trait;
use bytes::BytesMut;
use quinn::{RecvStream, SendStream};
use rosh_crypto::{create_cipher, Cipher, CipherAlgorithm, NonceGenerator};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Trait for network connections
#[async_trait]
pub trait Connection: Send + Sync {
    /// Send a message
    async fn send(&mut self, msg: Message) -> Result<(), NetworkError>;

    /// Receive a message
    async fn receive(&mut self) -> Result<Message, NetworkError>;

    /// Clone the connection
    fn clone_box(&self) -> Box<dyn Connection>;
}

impl Clone for Box<dyn Connection> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Simple connection wrapper that handles encryption/decryption internally
#[derive(Clone)]
pub struct QuicConnection {
    send_stream: Arc<Mutex<SendStream>>,
    recv_stream: Arc<Mutex<RecvStream>>,
    cipher: Arc<Box<dyn Cipher>>,
    nonce_gen: Arc<Mutex<NonceGenerator>>,
    stats: Arc<Mutex<MessageStats>>,
}

impl QuicConnection {
    /// Create a new QUIC connection wrapper
    pub fn new(
        send_stream: SendStream,
        recv_stream: RecvStream,
        cipher: Arc<Box<dyn Cipher>>,
        is_server: bool,
    ) -> Self {
        Self {
            send_stream: Arc::new(Mutex::new(send_stream)),
            recv_stream: Arc::new(Mutex::new(recv_stream)),
            cipher,
            nonce_gen: Arc::new(Mutex::new(NonceGenerator::new(is_server))),
            stats: Arc::new(Mutex::new(MessageStats::default())),
        }
    }

    /// Send a message on the stream
    async fn send_message(&self, msg: &Message) -> Result<(), NetworkError> {
        let mut buf = BytesMut::new();
        FramedCodec::encode(msg, &mut buf)?;

        // Encrypt the message
        let nonce = {
            let mut gen = self.nonce_gen.lock().await;
            gen.next_nonce()
        };

        let ciphertext = self.cipher.encrypt(&nonce, &buf, &[])?;

        // Write nonce + length + ciphertext
        let mut stream = self.send_stream.lock().await;
        stream
            .write_all(&nonce)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;
        stream
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;
        stream
            .write_all(&ciphertext)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.messages_sent += 1;
            stats.bytes_sent += (nonce.len() + ciphertext.len()) as u64;
        }

        Ok(())
    }

    /// Receive a message from the stream
    async fn receive_message(&self) -> Result<Message, NetworkError> {
        let mut stream = self.recv_stream.lock().await;

        // Read nonce
        let mut nonce = [0u8; 12];
        stream
            .read_exact(&mut nonce)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {e}")))?;

        // Read length prefix for ciphertext
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Read ciphertext
        let mut ciphertext = vec![0u8; len];
        stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {e}")))?;

        // Decrypt
        let plaintext = self.cipher.decrypt(&nonce, &ciphertext, &[])?;

        // Decode message
        let mut buf = BytesMut::from(&plaintext[..]);
        let msg = FramedCodec::decode(&mut buf)?
            .ok_or_else(|| NetworkError::ProtocolError("Incomplete message".to_string()))?;

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.messages_received += 1;
            stats.bytes_received += (nonce.len() + 4 + ciphertext.len()) as u64;

            // Update RTT if applicable
            match &msg {
                Message::Pong => stats.update_rtt(Message::timestamp_now()),
                Message::Ack { timestamp, .. } => stats.update_rtt(*timestamp),
                Message::StateUpdate { timestamp, .. } => stats.update_rtt(*timestamp),
                _ => {}
            }
        }

        Ok(msg)
    }
}

#[async_trait]
impl Connection for QuicConnection {
    async fn send(&mut self, msg: Message) -> Result<(), NetworkError> {
        self.send_message(&msg).await
    }

    async fn receive(&mut self) -> Result<Message, NetworkError> {
        self.receive_message().await
    }

    fn clone_box(&self) -> Box<dyn Connection> {
        Box::new(self.clone())
    }
}

/// Client connection manager
pub struct ClientConnection {
    transport: ClientTransport,
    cipher: Arc<Box<dyn Cipher>>,
    nonce_gen: Arc<Mutex<NonceGenerator>>,
    stats: Arc<Mutex<MessageStats>>,
}

impl ClientConnection {
    /// Create a new client connection
    pub async fn new(
        key: &[u8],
        algorithm: CipherAlgorithm,
        config: RoshTransportConfig,
    ) -> Result<Self, NetworkError> {
        let transport = ClientTransport::new(config).await?;
        let cipher = Arc::new(create_cipher(algorithm, key)?);
        let nonce_gen = Arc::new(Mutex::new(NonceGenerator::new(false))); // false = client
        let stats = Arc::new(Mutex::new(MessageStats::default()));

        Ok(Self {
            transport,
            cipher,
            nonce_gen,
            stats,
        })
    }

    /// Connect to server and perform handshake
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<u64, NetworkError> {
        self.transport.connect(addr).await?;

        let (_send, _recv) = self.transport.open_stream().await?;

        // For now, skip the handshake and return a dummy session ID
        // The actual handshake will be done at a higher level
        Ok(0)
    }

    /// Send a message on a stream
    pub async fn send_message(
        &self,
        stream: &mut SendStream,
        msg: &Message,
    ) -> Result<(), NetworkError> {
        let mut buf = BytesMut::new();
        FramedCodec::encode(msg, &mut buf)?;

        // Encrypt the message
        let nonce = {
            let mut gen = self.nonce_gen.lock().await;
            gen.next_nonce()
        };

        let ciphertext = self.cipher.encrypt(&nonce, &buf, &[])?;

        // Write nonce + length + ciphertext
        stream
            .write_all(&nonce)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;
        stream
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;
        stream
            .write_all(&ciphertext)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.messages_sent += 1;
            stats.bytes_sent += (nonce.len() + ciphertext.len()) as u64;
        }

        Ok(())
    }

    /// Receive a message from a stream
    pub async fn receive_message(&self, stream: &mut RecvStream) -> Result<Message, NetworkError> {
        // Read nonce
        let mut nonce = [0u8; 12];
        stream
            .read_exact(&mut nonce)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {e}")))?;

        // Read length prefix for ciphertext
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        // Read ciphertext
        let mut ciphertext = vec![0u8; len];
        stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {e}")))?;

        // Decrypt
        let plaintext = self.cipher.decrypt(&nonce, &ciphertext, &[])?;

        // Decode message
        let mut buf = BytesMut::from(&plaintext[..]);
        let msg = FramedCodec::decode(&mut buf)?
            .ok_or_else(|| NetworkError::ProtocolError("Incomplete message".to_string()))?;

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.messages_received += 1;
            stats.bytes_received += (nonce.len() + 4 + ciphertext.len()) as u64;

            // Update RTT if applicable
            match &msg {
                Message::Pong => stats.update_rtt(Message::timestamp_now()),
                Message::Ack { timestamp, .. } => stats.update_rtt(*timestamp),
                Message::StateUpdate { timestamp, .. } => stats.update_rtt(*timestamp),
                _ => {}
            }
        }

        Ok(msg)
    }

    /// Open a new stream for communication
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream), NetworkError> {
        self.transport.open_stream().await
    }

    /// Get connection statistics
    pub async fn stats(&self) -> MessageStats {
        self.stats.lock().await.clone()
    }
}

/// Server connection manager
pub struct ServerConnection {
    incoming: IncomingConnection,
    cipher: Arc<Box<dyn Cipher>>,
    nonce_gen: Arc<Mutex<NonceGenerator>>,
    stats: Arc<Mutex<MessageStats>>,
    _session_id: u64,
}

impl ServerConnection {
    /// Accept a new connection and perform handshake
    pub async fn accept(
        transport: &ServerTransport,
        key: &[u8],
        algorithm: CipherAlgorithm,
    ) -> Result<Self, NetworkError> {
        let incoming = transport.accept_raw().await?;
        let cipher = Arc::new(create_cipher(algorithm, key)?);
        let nonce_gen = Arc::new(Mutex::new(NonceGenerator::new(true))); // true = server
        let stats = Arc::new(Mutex::new(MessageStats::default()));
        let session_id = rand::random();

        let mut conn = Self {
            incoming,
            cipher,
            nonce_gen,
            stats,
            _session_id: session_id,
        };

        // Perform handshake
        conn.handshake().await?;

        Ok(conn)
    }

    /// Perform server-side handshake
    async fn handshake(&mut self) -> Result<(), NetworkError> {
        let (_send, _recv) = self.incoming.accept_stream().await?;

        // For now, skip the handshake
        // The actual handshake will be done at a higher level
        Ok(())
    }

    /// Send a message (same implementation as client)
    pub async fn send_message(
        &self,
        stream: &mut SendStream,
        msg: &Message,
    ) -> Result<(), NetworkError> {
        let mut buf = BytesMut::new();
        FramedCodec::encode(msg, &mut buf)?;

        let nonce = {
            let mut gen = self.nonce_gen.lock().await;
            gen.next_nonce()
        };

        let ciphertext = self.cipher.encrypt(&nonce, &buf, &[])?;

        stream
            .write_all(&nonce)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;
        stream
            .write_all(&(ciphertext.len() as u32).to_be_bytes())
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;
        stream
            .write_all(&ciphertext)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;

        {
            let mut stats = self.stats.lock().await;
            stats.messages_sent += 1;
            stats.bytes_sent += (nonce.len() + ciphertext.len()) as u64;
        }

        Ok(())
    }

    /// Receive a message (same implementation as client)
    pub async fn receive_message(&self, stream: &mut RecvStream) -> Result<Message, NetworkError> {
        let mut nonce = [0u8; 12];
        stream
            .read_exact(&mut nonce)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut ciphertext = vec![0u8; len];
        stream
            .read_exact(&mut ciphertext)
            .await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {e}")))?;

        let plaintext = self.cipher.decrypt(&nonce, &ciphertext, &[])?;

        let mut buf = BytesMut::from(&plaintext[..]);
        let msg = FramedCodec::decode(&mut buf)?
            .ok_or_else(|| NetworkError::ProtocolError("Incomplete message".to_string()))?;

        {
            let mut stats = self.stats.lock().await;
            stats.messages_received += 1;
            stats.bytes_received += (nonce.len() + 4 + ciphertext.len()) as u64;

            match &msg {
                Message::Pong => stats.update_rtt(Message::timestamp_now()),
                Message::Ack { timestamp, .. } => stats.update_rtt(*timestamp),
                Message::StateUpdate { timestamp, .. } => stats.update_rtt(*timestamp),
                _ => {}
            }
        }

        Ok(msg)
    }

    /// Accept a new stream
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream), NetworkError> {
        self.incoming.accept_stream().await
    }

    /// Get remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }

    /// Get connection statistics
    pub async fn stats(&self) -> MessageStats {
        self.stats.lock().await.clone()
    }
}
