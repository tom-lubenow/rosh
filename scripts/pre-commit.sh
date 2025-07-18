#!/usr/bin/env bash
# Pre-commit hook script for Rosh
# 
# Install this as a git hook by running:
#   ln -s ../../scripts/pre-commit.sh .git/hooks/pre-commit

set -e

echo "Running pre-commit checks..."

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Not in project root directory"
    exit 1
fi

# Format check
echo "Checking formatting..."
if ! cargo fmt --all -- --check; then
    echo "Error: Code needs formatting. Run 'cargo fmt --all'"
    exit 1
fi

# Clippy
echo "Running clippy..."
if ! cargo clippy --all-targets --all-features -- -D warnings; then
    echo "Error: Clippy found issues"
    exit 1
fi

# Tests
echo "Running tests..."
if ! cargo test --quiet; then
    echo "Error: Tests failed"
    exit 1
fi

# Check for TODO comments in staged files
echo "Checking for TODO comments..."
if git diff --cached --name-only | xargs grep -l "TODO\|FIXME\|XXX" 2>/dev/null; then
    echo "Warning: Found TODO/FIXME/XXX comments in staged files"
    read -p "Continue with commit? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo "All pre-commit checks passed!"