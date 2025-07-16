# Rosh - A Modern Mobile Shell

Rosh is a Rust implementation of a mobile shell, inspired by Mosh but built from the ground up with modern technologies and security practices. It provides robust remote terminal access over unstable networks with automatic reconnection, predictive echo, and efficient state synchronization.

## Key Features

- **Network Resilience**: Built on QUIC protocol for automatic connection migration and improved performance over lossy networks
- **Modern Encryption**: Supports AES-GCM and ChaCha20-Poly1305 authenticated encryption
- **Efficient State Synchronization**: Uses zero-copy serialization with rkyv and intelligent compression
- **Predictive Echo**: Provides immediate local feedback for better responsiveness
- **Terminal Compatibility**: Full VT100/xterm emulation with 256-color and true color support
- **Cross-Platform**: Unix/Linux support with modular architecture for future platform expansion

## Architecture

Rosh is built as a modular workspace with the following components:

- **rosh-crypto**: Cryptographic primitives using the ring library
- **rosh-network**: QUIC-based network transport with automatic reconnection
- **rosh-terminal**: Terminal emulation and escape sequence parsing
- **rosh-state**: State synchronization with compression and delta encoding
- **rosh-pty**: Platform-specific PTY allocation and process management
- **rosh**: Client and server binaries

## Building from Source

### Prerequisites

- Rust 1.70 or later
- Cargo build system
- OpenSSL development libraries (for certificate generation)

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/yourusername/rosh.git
cd rosh

# Build all components
cargo build --release

# Run tests
cargo test
```

## Usage

### Starting the Server

```bash
rosh-server --cert server.crt --key server.key --bind 0.0.0.0:2022
```

Server options:
- `--bind`: Address to bind to (default: 0.0.0.0:2022)
- `--cert`: Path to TLS certificate
- `--key`: Path to TLS private key
- `--cipher`: Cipher algorithm (aes-gcm, chacha20-poly1305)
- `--compression`: Enable compression (zstd, lz4)
- `--log-level`: Logging verbosity (trace, debug, info, warn, error)

### Connecting with the Client

```bash
rosh --key <base64-session-key> server.example.com:2022
```

Client options:
- `--key`: Base64-encoded session key (required)
- `--cipher`: Cipher algorithm (must match server)
- `--compression`: Enable compression
- `--predict`: Enable predictive echo
- `--log-level`: Logging verbosity

## Security Considerations

Rosh implements several security measures:

1. **Pre-shared Keys**: Session keys are transmitted out-of-band (typically via SSH)
2. **Authenticated Encryption**: All traffic is encrypted using AEAD ciphers
3. **Nonce Management**: Directional nonces prevent replay attacks
4. **Certificate Validation**: TLS certificates secure the QUIC transport

## Performance

Rosh is designed for efficiency:

- **Zero-Copy Serialization**: Using rkyv for minimal overhead
- **Compression**: Adaptive compression with Zstandard and LZ4
- **Delta Synchronization**: Only transmits changes, not full states
- **QUIC Transport**: Built-in congestion control and multiplexing

## Technical Details

### Protocol

Rosh uses a custom protocol over QUIC streams:

1. **Handshake**: Client sends session keys and terminal dimensions
2. **State Synchronization**: Server sends terminal state updates
3. **Input Forwarding**: Client sends keystrokes to server
4. **Acknowledgments**: Both sides acknowledge received states

### Encryption

- **Algorithms**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Key Derivation**: HKDF-SHA256 for deriving directional keys
- **Nonce Generation**: 96-bit nonces with direction bit and counter

### Terminal Emulation

- **Parser**: Complete VT100/xterm escape sequence support
- **Colors**: 8-bit indexed colors and 24-bit true color
- **Features**: Scrollback, alternate screen, cursor control

## Development

### Project Structure

```
rosh/
├── Cargo.toml              # Workspace configuration
├── crates/
│   ├── rosh/              # Main client/server binaries
│   ├── rosh-crypto/       # Encryption layer
│   ├── rosh-network/      # Network transport
│   ├── rosh-terminal/     # Terminal emulation
│   ├── rosh-state/        # State synchronization
│   └── rosh-pty/          # PTY management
└── mosh/                  # Original Mosh reference
```

### Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `cargo test`
2. Code is formatted: `cargo fmt`
3. No clippy warnings: `cargo clippy`
4. Documentation is updated

## Comparison with Mosh

While inspired by Mosh, Rosh makes different architectural choices:

| Feature | Mosh | Rosh |
|---------|------|------|
| Transport | Custom UDP | QUIC |
| Encryption | AES-OCB | AES-GCM/ChaCha20 |
| Serialization | Protocol Buffers | rkyv |
| Language | C++ | Rust |
| Compression | None | Zstandard/LZ4 |

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Acknowledgments

- The Mosh project for pioneering mobile shell technology
- The Rust community for excellent libraries and tooling
- Contributors and testers who help improve Rosh