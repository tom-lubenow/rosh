# Rosh End-to-End Testing

This directory contains comprehensive end-to-end tests for the Rosh mobile shell implementation.

## Test Structure

```
tests/
├── e2e/                      # End-to-end test files
│   ├── basic_connection.rs   # Basic client-server connection tests
│   ├── terminal_emulation.rs # Terminal emulation accuracy tests
│   ├── network_resilience.rs # Network condition handling tests
│   ├── security_tests.rs     # Security and encryption tests
│   ├── performance_tests.rs  # Performance benchmarks
│   └── stress_tests.rs       # Stress and chaos testing
└── README.md                 # This file
```

## Running Tests

### Run all E2E tests:
```bash
./scripts/test-e2e.sh
```

### Run specific test:
```bash
./scripts/test-e2e.sh --test test_echo_command
```

### Run tests without output capture (for debugging):
```bash
./scripts/test-e2e.sh --nocapture
```

### Run tests serially (useful for resource-intensive tests):
```bash
./scripts/test-e2e.sh --serial
```

### Using cargo directly:
```bash
# Build binaries first
cargo build --release --bin rosh --bin rosh-server

# Set required environment variables
export CARGO_BIN_EXE_rosh=$PWD/target/release/rosh
export CARGO_BIN_EXE_rosh_server=$PWD/target/release/rosh-server

# Run tests
cargo test --test '*'
```

## Test Categories

### 1. Basic Connection Tests
- Server startup and shutdown
- Client connection establishment
- Multiple client connections
- Reconnection after disconnect

### 2. Terminal Emulation Tests
- Echo command functionality
- Unicode character handling
- ANSI color preservation
- Terminal resizing
- Large paste operations

### 3. Network Resilience Tests
- Perfect network conditions
- Packet loss simulation
- High latency handling
- Mobile network conditions
- Poor network conditions
- Dynamic network changes

### 4. Security Tests
- Unauthorized connection rejection
- Encryption verification
- Session key rotation
- Connection limits
- Input sanitization

### 5. Performance Tests
- Typing latency measurement
- Throughput benchmarks
- Memory usage monitoring
- CPU usage monitoring
- Startup time measurement

### 6. Stress Tests
- Rapid reconnections
- Concurrent operations
- Network chaos simulation
- Resource exhaustion
- Long-running sessions

## Test Utilities

The `rosh-test-utils` crate provides:

- **TestHarness**: Spawns and manages server/client processes
- **NetworkSimulator**: Simulates various network conditions
- **TerminalCapture**: Captures and analyzes terminal output
- **TerminalComparator**: Compares expected vs actual output
- **TestFixtures**: Generates test data and files

## CI/CD Integration

Tests are automatically run on:
- Push to main/develop branches
- Pull requests
- Multiple OS (Ubuntu, macOS)
- Multiple Rust versions (stable, beta, nightly)

See `.github/workflows/ci.yml` for the complete CI configuration.

## Writing New Tests

1. Add test file to appropriate category in `tests/e2e/`
2. Use the test utilities from `rosh_test_utils`
3. Follow existing patterns for consistency
4. Add to `mod.rs` to include in test suite
5. Document any special requirements

Example test structure:
```rust
use rosh_test_utils::{init_test_logging, TestConfig, TestHarness};
use anyhow::Result;

#[tokio::test]
async fn test_my_feature() -> Result<()> {
    init_test_logging();
    
    let config = TestConfig::default();
    let harness = TestHarness::new(config)?;
    
    let mut server = harness.spawn_server().await?;
    server.wait_for_ready().await?;
    
    let mut client = harness.spawn_client(server.address()).await?;
    
    // Test logic here
    
    client.kill()?;
    server.kill()?;
    Ok(())
}
```

## Debugging Failed Tests

1. Run with `--nocapture` to see all output
2. Check log files in test temp directories
3. Enable debug logging: `RUST_LOG=debug`
4. Use `init_test_logging()` in tests
5. Add custom logging/assertions as needed

## Network Simulation

The test suite includes network simulation capabilities:

```rust
let mut conditions = NetworkConditions {
    packet_loss: 0.1,        // 10% packet loss
    latency_ms: 200,         // 200ms latency
    jitter_ms: 50,           // 50ms jitter
    bandwidth_bps: 1_000_000, // 1 Mbps
    reorder_probability: 0.05,
    max_reorder_distance: 3,
    duplicate_probability: 0.01,
};
```

Pre-configured conditions:
- `NetworkConditions::perfect()`
- `NetworkConditions::mobile()`
- `NetworkConditions::poor()`
- `NetworkConditions::satellite()`