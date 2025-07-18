.PHONY: all build test check clean doc fmt clippy release install help

# Default target
all: check test

# Build the project
build:
	@echo "Building project..."
	@cargo build --all-features

# Run tests
test:
	@echo "Running tests..."
	@cargo test --all-features

# Run all checks (fmt, clippy, test)
check: fmt clippy test
	@echo "All checks passed!"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@cargo clean

# Generate documentation
doc:
	@echo "Generating documentation..."
	@cargo doc --no-deps --all-features --open

# Format code
fmt:
	@echo "Formatting code..."
	@cargo fmt --all

# Run clippy
clippy:
	@echo "Running clippy..."
	@cargo clippy --all-targets --all-features -- -D warnings

# Build release binaries
release:
	@echo "Building release binaries..."
	@cargo build --release

# Install binaries
install:
	@echo "Installing binaries..."
	@cargo install --path crates/rosh
	@cargo install --path crates/rosh --bin rosh-server

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	@cargo bench

# Security audit
audit:
	@echo "Running security audit..."
	@cargo audit

# Update dependencies
update:
	@echo "Updating dependencies..."
	@cargo update

# Run the server in development mode
run-server:
	@echo "Starting server..."
	@cargo run --bin rosh-server -- --one-shot --bind 127.0.0.1:0

# Run the client in development mode
run-client:
	@echo "Starting client..."
	@cargo run --bin rosh -- localhost:2022

# Help target
help:
	@echo "Available targets:"
	@echo "  all       - Run checks and tests (default)"
	@echo "  build     - Build the project"
	@echo "  test      - Run tests"
	@echo "  check     - Run all checks (fmt, clippy, test)"
	@echo "  clean     - Clean build artifacts"
	@echo "  doc       - Generate and open documentation"
	@echo "  fmt       - Format code"
	@echo "  clippy    - Run clippy linter"
	@echo "  release   - Build release binaries"
	@echo "  install   - Install binaries"
	@echo "  bench     - Run benchmarks"
	@echo "  audit     - Run security audit"
	@echo "  update    - Update dependencies"
	@echo "  run-server - Run server in development mode"
	@echo "  run-client - Run client in development mode"
	@echo "  help      - Show this help message"