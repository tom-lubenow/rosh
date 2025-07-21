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
use std::net::{SocketAddr, UdpSocket};
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

    /// Create a new client transport bound to a specific local address
    /// This is used after hole punching to reuse the same port
    pub async fn new_client_at_address(
        local_addr: SocketAddr,
        config: RoshTransportConfig,
    ) -> Result<ClientTransportWrapper, NetworkError> {
        let transport = ClientTransport::new_at_address(local_addr, config).await?;
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

    /// Create a new client transport from an existing socket (e.g., after hole punching)
    pub async fn new_client_from_socket(
        socket: UdpSocket,
        config: RoshTransportConfig,
    ) -> Result<ClientTransportWrapper, NetworkError> {
        let transport = ClientTransport::new_from_socket(socket, config).await?;
        Ok(ClientTransportWrapper {
            transport,
            key: None,
            algorithm: None,
        })
    }

    /// Create a new server transport from an existing socket (e.g., after hole punching)
    pub async fn new_server_from_socket(
        socket: UdpSocket,
        config: RoshTransportConfig,
    ) -> Result<ServerTransportWrapper, NetworkError> {
        let transport = ServerTransport::new_from_socket(socket, config).await?;
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
        let client_config = create_client_config(config)?;

        // Bind to any available port on both IPv4 and IPv6
        // Use 0.0.0.0:0 instead of [::]:0 to ensure IPv4 compatibility
        let addr = "0.0.0.0:0"
            .parse()
            .map_err(|e| NetworkError::TransportError(format!("Failed to parse address: {e}")))?;
        let mut endpoint = Endpoint::client(addr)
            .map_err(|e| NetworkError::TransportError(format!("Failed to create endpoint: {e}")))?;

        // Set the default client configuration
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connection: None,
        })
    }

    /// Create a new client transport at a specific address
    /// Used after hole punching to reuse the same port
    pub async fn new_at_address(
        local_addr: SocketAddr,
        config: RoshTransportConfig,
    ) -> Result<Self, NetworkError> {
        let client_config = create_client_config(config)?;

        tracing::info!(
            "Creating client endpoint at specific address: {}",
            local_addr
        );
        let mut endpoint = Endpoint::client(local_addr).map_err(|e| {
            NetworkError::TransportError(format!("Failed to create endpoint at {local_addr}: {e}"))
        })?;

        // Set the default client configuration
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connection: None,
        })
    }

    /// Create a new client transport from an existing socket
    pub async fn new_from_socket(
        socket: UdpSocket,
        config: RoshTransportConfig,
    ) -> Result<Self, NetworkError> {
        let client_config = create_client_config(config.clone())?;
        let endpoint_config = quinn::EndpointConfig::default();

        // Get the default runtime
        let runtime = quinn::default_runtime()
            .ok_or_else(|| NetworkError::TransportError("No async runtime found".to_string()))?;

        let endpoint = Endpoint::new(
            endpoint_config,
            None, // No server config for client
            socket,
            runtime,
        )
        .map_err(|e| {
            NetworkError::TransportError(format!("Failed to create endpoint from socket: {e}"))
        })?;

        // Set the default client config
        let mut endpoint = endpoint;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            connection: None,
        })
    }

    /// Connect to a server
    pub async fn connect(&mut self, addr: SocketAddr) -> Result<(), NetworkError> {
        tracing::info!("Initiating QUIC connection to {}", addr);
        tracing::info!(
            "Client endpoint local address: {:?}",
            self.endpoint.local_addr()
        );

        // Use the endpoint's default config instead of creating a new one
        let connecting = self.endpoint.connect(addr, "localhost").map_err(|e| {
            tracing::error!("Failed to initiate QUIC connection: {}", e);
            NetworkError::ConnectionFailed(format!("Failed to initiate connection: {e}"))
        })?;

        tracing::info!("QUIC handshake in progress...");
        let connection = connecting.await.map_err(|e| {
            tracing::error!("QUIC handshake failed: {}", e);
            tracing::error!("Error details: {:?}", e);
            NetworkError::ConnectionFailed(format!("Connection failed: {e}"))
        })?;

        tracing::info!("QUIC connection established");
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
        tracing::info!("Creating server transport at {}", bind_addr);
        let (server_config, _) = create_server_config(config)?;
        tracing::info!("Server config created successfully");

        let endpoint = Endpoint::server(server_config, bind_addr).map_err(|e| {
            tracing::error!("Failed to create server endpoint at {}: {}", bind_addr, e);
            NetworkError::TransportError(format!("Failed to create server endpoint: {e}"))
        })?;

        let local_addr = endpoint.local_addr().map_err(|e| {
            NetworkError::TransportError(format!("Failed to get local address: {e}"))
        })?;
        tracing::info!(
            "QUIC server endpoint created successfully at {}",
            local_addr
        );

        Ok(Self { endpoint })
    }

    /// Create a new server transport from an existing socket
    pub async fn new_from_socket(
        socket: UdpSocket,
        config: RoshTransportConfig,
    ) -> Result<Self, NetworkError> {
        tracing::info!("Creating server transport from socket");
        let (server_config, _) = create_server_config(config)?;
        let endpoint_config = quinn::EndpointConfig::default();

        // Get the default runtime
        let runtime = quinn::default_runtime()
            .ok_or_else(|| NetworkError::TransportError("No async runtime found".to_string()))?;

        let local_addr = socket.local_addr().map_err(|e| {
            NetworkError::TransportError(format!("Failed to get socket address: {e}"))
        })?;
        tracing::info!("Socket bound to: {}", local_addr);

        let endpoint = Endpoint::new(endpoint_config, Some(server_config), socket, runtime)
            .map_err(|e| {
                NetworkError::TransportError(format!("Failed to create endpoint from socket: {e}"))
            })?;

        tracing::info!("QUIC endpoint created successfully");
        Ok(Self { endpoint })
    }

    /// Accept incoming connections (raw)
    pub async fn accept_raw(&self) -> Result<IncomingConnection, NetworkError> {
        tracing::info!("Waiting for incoming QUIC connection...");
        let connecting = self.endpoint.accept().await.ok_or_else(|| {
            tracing::error!("Server endpoint closed");
            NetworkError::TransportError("Server endpoint closed".to_string())
        })?;

        tracing::info!("QUIC connection incoming, performing handshake...");
        let connection = connecting.await.map_err(|e| {
            tracing::error!("Failed to complete QUIC handshake: {}", e);
            NetworkError::ConnectionFailed(format!("Failed to accept connection: {e}"))
        })?;

        tracing::info!("QUIC connection accepted successfully");
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

    client_config.transport_config(Arc::new(create_transport_config(config)?));

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

    server_config.transport_config(Arc::new(create_transport_config(config)?));

    Ok((server_config, cert_der))
}

/// Create QUIC transport configuration
fn create_transport_config(
    config: RoshTransportConfig,
) -> Result<quinn::TransportConfig, NetworkError> {
    let mut transport = quinn::TransportConfig::default();

    let idle_timeout = config.max_idle_timeout.try_into().map_err(|_| {
        NetworkError::TransportError("max_idle_timeout value too large for VarInt".to_string())
    })?;
    transport.max_idle_timeout(Some(idle_timeout));
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

    Ok(transport)
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
        let algorithm = self.algorithm.unwrap_or(CipherAlgorithm::Aes256Gcm); // Changed to match 32-byte key

        // First establish the QUIC connection
        self.transport.connect(server_addr).await?;

        // Now open a bidirectional stream - this is what the server is waiting for
        tracing::info!("Opening bidirectional stream for encrypted communication");
        let (send, recv) = self.transport.open_stream().await?;
        tracing::info!("Stream opened successfully");

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
        let algorithm = self.algorithm.unwrap_or(CipherAlgorithm::Aes256Gcm); // Changed to match 32-byte key

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
