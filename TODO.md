# Rosh Production Readiness TODO

This document outlines the practical tasks needed to make Rosh a production-ready mosh replacement.

## 🚨 Critical Issues to Fix

### Certificate Validation
- [ ] **CRITICAL**: Remove default `SkipValidation` mode in cert_validation.rs
- [ ] Implement proper system root certificate validation using rustls-platform-verifier
- [ ] Since we use SSH bootstrap, consider if we even need TLS (mosh uses its own crypto)

### Code Quality & Error Handling
- [ ] **HIGH PRIORITY**: Replace all 264 `unwrap()` calls with proper error handling
- [ ] Replace all 68 `expect()` calls with `?` or context-aware errors
- [ ] Remove or properly handle all 21 `panic!` calls
- [ ] Add `#![forbid(unsafe_code)]` to all crates (verify we don't need unsafe anywhere)

### Logging & Debugging
- [ ] **CRITICAL**: Add proper logging throughout (only 3 tracing calls found!)
- [ ] Add debug mode with verbose packet logging
- [ ] Add connection diagnostics command
- [ ] Log all errors with context

## 🧪 Testing & Reliability

### Test Coverage
- [ ] Increase test coverage to >70% (currently only 115 test functions)
- [ ] Add integration tests for common failure scenarios:
  - Network disconnection/reconnection
  - High packet loss
  - Connection migration (IP change)
  - Server restart
- [ ] Add stress tests for many concurrent connections

### Benchmarking
- [ ] **MISSING**: Create benchmark suite
- [ ] Benchmark vs original mosh for:
  - Latency
  - Bandwidth usage
  - CPU usage
  - Memory usage
- [ ] Add benchmarks for critical paths:
  - State synchronization
  - Terminal rendering
  - Encryption/decryption

### Fuzzing
- [ ] Continue fuzzing terminal parser
- [ ] Add fuzzing for network protocol messages
- [ ] Fuzz state synchronization logic

## 🔧 Core Features to Complete

### Essential Functionality
- [ ] Fix terminal resizing during active sessions
- [ ] Handle SSH agent forwarding properly
- [ ] Add `--server` flag to specify custom server binary path (like mosh)
- [ ] Implement proper locale/UTF-8 handling
- [ ] Add `--predict` flag for predictive echo (currently always on?)

### Robustness
- [ ] Handle server binary not found gracefully
- [ ] Detect and handle version mismatches
- [ ] Add connection timeout handling
- [ ] Implement graceful shutdown
- [ ] Handle partial writes/reads properly

### Compatibility
- [ ] Test with common terminal emulators
- [ ] Verify tmux/screen compatibility
- [ ] Test with various shells (bash, zsh, fish)
- [ ] Ensure vim/emacs work properly

## 🚀 Performance & Efficiency

### Network Optimization
- [ ] Tune QUIC parameters for mobile/wifi networks
- [ ] Implement intelligent state diff compression
- [ ] Add bandwidth usage monitoring
- [ ] Optimize for high-latency connections

### Terminal Performance
- [ ] Optimize for large scrollback buffers
- [ ] Handle rapid output efficiently (e.g., `cat large_file`)
- [ ] Minimize redraws

### Memory Usage
- [ ] Profile memory usage under load
- [ ] Fix any memory leaks
- [ ] Optimize data structures

## 🎯 Missing Mosh Features

Review which mosh features we need to implement:
- [ ] `--ssh` flag to specify SSH command
- [ ] `--port` flag for server port range
- [ ] `--bind-server` flag for server IP binding  
- [ ] UDP hole punching (or QUIC equivalent)
- [ ] Roaming support verification
- [ ] Kill old sessions on reconnect

## Priority Order

1. Fix all tests, and keep all tests fixed, at all times.
2. Everything else on this list.
