#!/bin/bash
set -euo pipefail

# E2E Test Runner for Rosh
# This script runs the end-to-end tests with proper configuration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "Building rosh binaries..."
cargo build --release --bin rosh --bin rosh-server

export CARGO_BIN_EXE_rosh="$PROJECT_ROOT/target/release/rosh"
export CARGO_BIN_EXE_rosh_server="$PROJECT_ROOT/target/release/rosh-server"

# Set test environment
export RUST_LOG="${RUST_LOG:-rosh=debug,rosh_test_utils=debug}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

# Parse arguments
TEST_FILTER=""
NOCAPTURE=""
PARALLEL=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --test)
            TEST_FILTER="$2"
            shift 2
            ;;
        --nocapture)
            NOCAPTURE="--nocapture"
            shift
            ;;
        --serial)
            PARALLEL="--test-threads=1"
            shift
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --test <name>    Run only tests matching name"
            echo "  --nocapture      Don't capture test output"
            echo "  --serial         Run tests serially"
            echo "  --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Running E2E tests..."
if [ -n "$TEST_FILTER" ]; then
    echo "Filter: $TEST_FILTER"
    cargo test --test '*' -- "$TEST_FILTER" $NOCAPTURE $PARALLEL
else
    cargo test --test '*' -- $NOCAPTURE $PARALLEL
fi