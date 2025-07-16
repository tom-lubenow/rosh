//! High-level connection management for Rosh
//! 
//! Provides encrypted, reliable message exchange over QUIC

use crate::{NetworkError, protocol::{Message, FramedCodec, MessageStats, PROTOCOL_VERSION}};
use crate::transport::{ClientTransport, ServerTransport, IncomingConnection, RoshTransportConfig};
use rosh_crypto::{Cipher, CipherAlgorithm, NonceGenerator, create_cipher};
use bytes::BytesMut;
use quinn::{RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

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
        
        let (mut send, mut recv) = self.transport.open_stream().await?;
        
        // Send client hello
        let hello = Message::ClientHello {
            version: PROTOCOL_VERSION,
            session_id: None,
        };
        
        self.send_message(&mut send, &hello).await?;
        
        // Receive server hello
        let response = self.receive_message(&mut recv).await?;
        
        match response {
            Message::ServerHello { version, session_id } => {
                if version != PROTOCOL_VERSION {
                    return Err(NetworkError::ProtocolError(
                        format!("Protocol version mismatch: got {}, expected {}", version, PROTOCOL_VERSION)
                    ));
                }
                Ok(session_id)
            }
            _ => Err(NetworkError::ProtocolError("Expected ServerHello".to_string())),
        }
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
        stream.write_all(&nonce).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
        stream.write_all(&(ciphertext.len() as u32).to_be_bytes()).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
        stream.write_all(&ciphertext).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
            
        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.messages_sent += 1;
            stats.bytes_sent += (nonce.len() + ciphertext.len()) as u64;
        }
        
        Ok(())
    }
    
    /// Receive a message from a stream
    pub async fn receive_message(
        &self,
        stream: &mut RecvStream,
    ) -> Result<Message, NetworkError> {
        // Read nonce
        let mut nonce = [0u8; 12];
        stream.read_exact(&mut nonce).await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {}", e)))?;
            
        // Read length prefix for ciphertext
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {}", e)))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read ciphertext
        let mut ciphertext = vec![0u8; len];
        stream.read_exact(&mut ciphertext).await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {}", e)))?;
            
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
                Message::Pong { timestamp } => stats.update_rtt(*timestamp),
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
    session_id: u64,
}

impl ServerConnection {
    /// Accept a new connection and perform handshake
    pub async fn accept(
        transport: &ServerTransport,
        key: &[u8],
        algorithm: CipherAlgorithm,
    ) -> Result<Self, NetworkError> {
        let incoming = transport.accept().await?;
        let cipher = Arc::new(create_cipher(algorithm, key)?);
        let nonce_gen = Arc::new(Mutex::new(NonceGenerator::new(true))); // true = server
        let stats = Arc::new(Mutex::new(MessageStats::default()));
        let session_id = rand::random();
        
        let mut conn = Self {
            incoming,
            cipher,
            nonce_gen,
            stats,
            session_id,
        };
        
        // Perform handshake
        conn.handshake().await?;
        
        Ok(conn)
    }
    
    /// Perform server-side handshake
    async fn handshake(&mut self) -> Result<(), NetworkError> {
        let (mut send, mut recv) = self.incoming.accept_stream().await?;
        
        // Receive client hello
        let hello = self.receive_message(&mut recv).await?;
        
        match hello {
            Message::ClientHello { version, .. } => {
                if version != PROTOCOL_VERSION {
                    return Err(NetworkError::ProtocolError(
                        format!("Protocol version mismatch: got {}, expected {}", version, PROTOCOL_VERSION)
                    ));
                }
            }
            _ => return Err(NetworkError::ProtocolError("Expected ClientHello".to_string())),
        }
        
        // Send server hello
        let response = Message::ServerHello {
            version: PROTOCOL_VERSION,
            session_id: self.session_id,
        };
        
        self.send_message(&mut send, &response).await?;
        
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
        
        stream.write_all(&nonce).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
        stream.write_all(&(ciphertext.len() as u32).to_be_bytes()).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
        stream.write_all(&ciphertext).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
            
        {
            let mut stats = self.stats.lock().await;
            stats.messages_sent += 1;
            stats.bytes_sent += (nonce.len() + ciphertext.len()) as u64;
        }
        
        Ok(())
    }
    
    /// Receive a message (same implementation as client)
    pub async fn receive_message(
        &self,
        stream: &mut RecvStream,
    ) -> Result<Message, NetworkError> {
        let mut nonce = [0u8; 12];
        stream.read_exact(&mut nonce).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
            
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await
            .map_err(|e| NetworkError::TransportError(format!("Write failed: {}", e)))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        let mut ciphertext = vec![0u8; len];
        stream.read_exact(&mut ciphertext).await
            .map_err(|e| NetworkError::TransportError(format!("Read failed: {}", e)))?;
            
        let plaintext = self.cipher.decrypt(&nonce, &ciphertext, &[])?;
        
        let mut buf = BytesMut::from(&plaintext[..]);
        let msg = FramedCodec::decode(&mut buf)?
            .ok_or_else(|| NetworkError::ProtocolError("Incomplete message".to_string()))?;
            
        {
            let mut stats = self.stats.lock().await;
            stats.messages_received += 1;
            stats.bytes_received += (nonce.len() + 4 + ciphertext.len()) as u64;
            
            match &msg {
                Message::Pong { timestamp } => stats.update_rtt(*timestamp),
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