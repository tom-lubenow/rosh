//! QUIC transport implementation for Rosh
//!
//! Uses Quinn for QUIC protocol support, providing:
//! - Automatic connection migration (roaming)
//! - Built-in congestion control
//! - Stream multiplexing
//! - 0-RTT resumption

use crate::{
    cert_validation::{create_cert_verifier, CertValidationMode},
    connection::{Connection as ConnectionTrait, QuicConnection},
    NetworkError,
};
use quinn::{
    congestion, ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, VarInt,
};
use rosh_crypto::{create_cipher, CipherAlgorithm};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// ALPN protocol identifier for Rosh
const ALPN_ROSH: &[u8] = b"rosh/1";

/// High-level network transport abstraction
pub struct NetworkTransport;

impl NetworkTransport {
    /// Create a new client transport
    pub async fn new_client(
        config: RoshTransportConfig,
    ) -> Result<ClientTransportWrapper, NetworkError> {
        let transport = ClientTransport::new(config).await?;
        Ok(ClientTransportWrapper {
            transport,
            key: None,
            algorithm: None,
        })
    }

    /// Create a new server transport  
    pub async fn new_server(
        bind_addr: SocketAddr,
        _cert_chain: Vec<u8>,  // Ignored, we use self-signed certs internally
        _private_key: Vec<u8>, // Ignored, we use self-signed certs internally
        config: RoshTransportConfig,
    ) -> Result<ServerTransportWrapper, NetworkError> {
        let transport = ServerTransport::new(bind_addr, config).await?;
        Ok(ServerTransportWrapper {
            transport,
            key: None,
            algorithm: None,
        })
    }
}

/// Configuration for transport layer
#[derive(Debug, Clone)]
pub struct RoshTransportConfig {
    /// Keep-alive interval (0 to disable)
    pub keep_alive_interval: Duration,
    /// Maximum idle timeout before closing connection
    pub max_idle_timeout: Duration,
    /// Initial congestion window in packets
    pub initial_window: u32,
    /// Stream receive window
    pub stream_receive_window: VarInt,
    /// Certificate validation mode
    pub cert_validation: CertValidationMode,
}

impl Default for RoshTransportConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: Duration::from_secs(5),
            max_idle_timeout: Duration::from_secs(30),
            initial_window: 20,                                   // packets
            stream_receive_window: VarInt::from_u32(1024 * 1024), // 1 MB
            cert_validation: CertValidationMode::default(),
        }
    }
}

/// Client transport endpoint
pub struct ClientTransport {
    endpoint: Endpoint,
    connection: Option<Connection>,
}

impl ClientTransport {
    /// Create a new client transport
    pub async fn new(config: RoshTransportConfig) -> Result<Self, NetworkError> {
        let _client_config = create_client_config(config)?;

        // Bind to any available port
        let endpoint = Endpoint::client("[::]:0".parse().unwrap())
            .map_err(|e| NetworkError::TransportError(format!("Failed to create endpoint: {e}")))?;

        Ok(Self {
            endpoint,
            connection: None,
        })
    }

    /// Connect to a server
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        let client_config = create_client_config(RoshTransportConfig::default())?;

        let connection = self
            .endpoint
            .connect_with(client_config, addr, "localhost")
            .map_err(|e| {
                NetworkError::ConnectionFailed(format!("Failed to initiate connection: {e}"))
            })?
            .await
            .map_err(|e| NetworkError::ConnectionFailed(format!("Connection failed: {e}")))?;

        self.connection = Some(connection);
        Ok(())
    }

    /// Open a new bidirectional stream
    pub async fn open_stream(&self) -> Result<(SendStream, RecvStream), NetworkError> {
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| NetworkError::ConnectionFailed("Not connected".to_string()))?;

        connection
            .open_bi()
            .await
            .map_err(|e| NetworkError::TransportError(format!("Failed to open stream: {e}")))
    }

    /// Get the current connection state
    pub fn is_connected(&self) -> bool {
        self.connection
            .as_ref()
            .map(|c| c.close_reason().is_none())
            .unwrap_or(false)
    }

    /// Get connection statistics
    pub fn stats(&self) -> Option<quinn::ConnectionStats> {
        self.connection.as_ref().map(|c| c.stats())
    }
}

/// Server transport endpoint
pub struct ServerTransport {
    endpoint: Endpoint,
}

impl ServerTransport {
    /// Create a new server transport
    pub async fn new(
        bind_addr: SocketAddr,
        config: RoshTransportConfig,
    ) -> Result<Self, NetworkError> {
        let (server_config, _) = create_server_config(config)?;

        let endpoint = Endpoint::server(server_config, bind_addr).map_err(|e| {
            NetworkError::TransportError(format!("Failed to create server endpoint: {e}"))
        })?;

        Ok(Self { endpoint })
    }

    /// Accept incoming connections (raw)
    pub async fn accept_raw(&self) -> Result<IncomingConnection, NetworkError> {
        let connecting =
            self.endpoint.accept().await.ok_or_else(|| {
                NetworkError::TransportError("Server endpoint closed".to_string())
            })?;

        let connection = connecting.await.map_err(|e| {
            NetworkError::ConnectionFailed(format!("Failed to accept connection: {e}"))
        })?;

        Ok(IncomingConnection { connection })
    }

    /// Accept incoming connection and return wrapped connection
    pub async fn accept(
        &self,
        key: &[u8],
        algorithm: CipherAlgorithm,
    ) -> Result<(Box<dyn ConnectionTrait>, SocketAddr), NetworkError> {
        let incoming = self.accept_raw().await?;
        let remote_addr = incoming.remote_address();

        // Accept a stream from the client
        let (send, recv) = incoming.accept_stream().await?;

        // Create cipher
        let cipher = Arc::new(create_cipher(algorithm, key)?);

        // Create the connection wrapper
        let connection = QuicConnection::new(send, recv, cipher, true);

        Ok((Box::new(connection), remote_addr))
    }

    /// Get the server's bound address
    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        self.endpoint
            .local_addr()
            .map_err(|e| NetworkError::TransportError(format!("Failed to get local address: {e}")))
    }
}

/// An accepted incoming connection
pub struct IncomingConnection {
    connection: Connection,
}

impl IncomingConnection {
    /// Accept a bidirectional stream
    pub async fn accept_stream(&self) -> Result<(SendStream, RecvStream), NetworkError> {
        self.connection
            .accept_bi()
            .await
            .map_err(|e| NetworkError::TransportError(format!("Failed to accept stream: {e}")))
    }

    /// Get the remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Get connection statistics
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }
}

/// Create client configuration
fn create_client_config(config: RoshTransportConfig) -> Result<ClientConfig, NetworkError> {
    // Create certificate verifier based on config
    let cert_verifier = create_cert_verifier(config.cert_validation.clone()).map_err(|e| {
        NetworkError::TransportError(format!("Failed to create cert verifier: {e}"))
    })?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(cert_verifier)
        .with_no_client_auth();

    client_crypto.alpn_protocols = vec![ALPN_ROSH.to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).map_err(|e| {
            NetworkError::TransportError(format!("Failed to create QUIC client config: {e}"))
        })?,
    ));

    client_config.transport_config(Arc::new(create_transport_config(config)));

    Ok(client_config)
}

/// Create server configuration with self-signed certificate
fn create_server_config(
    config: RoshTransportConfig,
) -> Result<(ServerConfig, CertificateDer<'static>), NetworkError> {
    // Generate self-signed certificate
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).map_err(|e| {
        NetworkError::TransportError(format!("Failed to generate certificate: {e}"))
    })?;

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .map_err(|e| {
            NetworkError::TransportError(format!("Failed to create server crypto config: {e}"))
        })?;

    server_crypto.alpn_protocols = vec![ALPN_ROSH.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).map_err(|e| {
            NetworkError::TransportError(format!("Failed to create QUIC server config: {e}"))
        })?,
    ));

    server_config.transport_config(Arc::new(create_transport_config(config)));

    Ok((server_config, cert_der))
}

/// Create QUIC transport configuration
fn create_transport_config(config: RoshTransportConfig) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();

    transport.max_idle_timeout(Some(config.max_idle_timeout.try_into().unwrap()));
    transport.keep_alive_interval(Some(config.keep_alive_interval));

    // Set congestion control parameters
    transport.initial_rtt(Duration::from_millis(100));
    transport.congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

    // Set flow control windows
    transport.stream_receive_window(config.stream_receive_window);
    transport.receive_window(config.stream_receive_window);

    // Set initial congestion window
    let mut cc_config = congestion::BbrConfig::default();
    cc_config.initial_window(config.initial_window as u64);
    transport.congestion_controller_factory(Arc::new(cc_config));

    transport
}

/// Wrapper for client transport that provides connection method
pub struct ClientTransportWrapper {
    transport: ClientTransport,
    key: Option<Vec<u8>>,
    algorithm: Option<CipherAlgorithm>,
}

impl ClientTransportWrapper {
    /// Set encryption key and algorithm
    pub fn with_encryption(mut self, key: Vec<u8>, algorithm: CipherAlgorithm) -> Self {
        self.key = Some(key);
        self.algorithm = Some(algorithm);
        self
    }

    /// Connect to server and return a connection
    pub async fn connect(
        &mut self,
        server_addr: SocketAddr,
    ) -> Result<Box<dyn ConnectionTrait>, NetworkError> {
        // Use default key and algorithm if not set
        let key = self.key.as_deref().unwrap_or(&[0u8; 32]);
        let algorithm = self.algorithm.unwrap_or(CipherAlgorithm::Aes128Gcm);

        self.transport.connect(server_addr).await?;

        // Open a stream for the connection
        let (send, recv) = self.transport.open_stream().await?;

        // Create cipher
        let cipher = Arc::new(create_cipher(algorithm, key)?);

        // Create the connection wrapper
        let connection = QuicConnection::new(send, recv, cipher, false);

        Ok(Box::new(connection))
    }
}

/// Wrapper for server transport that provides accept method
pub struct ServerTransportWrapper {
    transport: ServerTransport,
    key: Option<Vec<u8>>,
    algorithm: Option<CipherAlgorithm>,
}

impl ServerTransportWrapper {
    /// Set encryption key and algorithm  
    pub fn with_encryption(mut self, key: Vec<u8>, algorithm: CipherAlgorithm) -> Self {
        self.key = Some(key);
        self.algorithm = Some(algorithm);
        self
    }

    /// Accept incoming connection and return wrapped connection
    pub async fn accept(&self) -> Result<(Box<dyn ConnectionTrait>, SocketAddr), NetworkError> {
        // Use default key and algorithm if not set
        let key = self.key.as_deref().unwrap_or(&[0u8; 32]);
        let algorithm = self.algorithm.unwrap_or(CipherAlgorithm::Aes128Gcm);

        self.transport.accept(key, algorithm).await
    }

    /// Get the server's bound address
    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        self.transport.local_addr()
    }
}

#[cfg(test)]
#[path = "transport_test.rs"]
mod transport_test;
