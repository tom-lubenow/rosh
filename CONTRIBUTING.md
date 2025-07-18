# Contributing to Rosh

Thank you for your interest in contributing to Rosh! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct (to be added).

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/rosh.git`
3. Add upstream remote: `git remote add upstream https://github.com/original/rosh.git`
4. Create a feature branch: `git checkout -b feature/amazing-feature`

## Development Setup

### Prerequisites

- Rust 1.70 or later
- Git
- Make (optional, for convenience commands)

### Building

```bash
# Build the project
cargo build

# Build with all features
cargo build --all-features

# Build release binaries
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Code Quality

Before submitting a PR, ensure:

```bash
# Format your code
cargo fmt --all

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Run all checks
make check
```

### Pre-commit Hook

Install the pre-commit hook to automatically run checks:

```bash
ln -s ../../scripts/pre-commit.sh .git/hooks/pre-commit
```

## Project Structure

- `crates/rosh/` - Main client binary
- `crates/rosh-crypto/` - Cryptographic primitives
- `crates/rosh-network/` - Network transport layer
- `crates/rosh-terminal/` - Terminal emulation
- `crates/rosh-state/` - State synchronization
- `crates/rosh-pty/` - PTY management

## Making Changes

### Commit Messages

Follow conventional commit format:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Test additions or modifications
- `chore:` Maintenance tasks
- `perf:` Performance improvements

Example:
```
feat: add delta compression for state updates

Implemented delta compression using zstd to reduce bandwidth usage
when synchronizing terminal state between client and server.

Closes #123
```

### Pull Request Process

1. Update documentation for any changed functionality
2. Add tests for new features
3. Ensure all tests pass
4. Update CHANGELOG.md if applicable
5. Submit PR against the `develop` branch
6. Wait for code review

### Code Review

All PRs require at least one review before merging. Reviewers will check:

- Code quality and style
- Test coverage
- Documentation
- Performance implications
- Security considerations

## Testing Guidelines

### Unit Tests

- Place unit tests in the same file as the code being tested
- Use the `#[cfg(test)]` module pattern
- Test edge cases and error conditions

### Integration Tests

- Place integration tests in `tests/` directory
- Test interactions between components
- Use realistic scenarios

### Ignored Tests

Some tests may be marked with `#[ignore]` due to:
- Platform-specific issues
- Flaky behavior
- Long execution time

Document why a test is ignored with a comment.

## Documentation

- Add doc comments for all public APIs
- Include examples in doc comments
- Keep README files up to date
- Document breaking changes

## Performance

- Benchmark critical paths
- Avoid unnecessary allocations
- Use `cargo bench` to measure performance
- Document performance characteristics

## Security

- Never commit secrets or credentials
- Validate all inputs
- Use secure defaults
- Follow Rust security best practices
- Report security issues privately

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Create release PR
4. Tag release: `git tag -a v1.0.0 -m "Release version 1.0.0"`
5. Push tag: `git push upstream v1.0.0`
6. CI will automatically build and upload release artifacts

## Getting Help

- Open an issue for bugs or feature requests
- Join our community chat (to be added)
- Check existing issues and PRs before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (MIT OR Apache-2.0).