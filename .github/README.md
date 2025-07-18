# GitHub Actions CI/CD

This directory contains the CI/CD pipeline configuration for Rosh.

## Workflows

### CI (`ci.yml`)
Runs on every push and pull request to main/develop branches:
- **Test matrix**: Tests on Ubuntu and macOS with stable and beta Rust
- **Code quality**: Runs `cargo fmt` and `cargo clippy`
- **Documentation**: Builds documentation to ensure it compiles
- **Security audit**: Checks for known vulnerabilities in dependencies
- **Code coverage**: Generates and uploads coverage reports to Codecov
- **Build artifacts**: Builds release binaries for multiple platforms

### Release (`release.yml`)
Triggered when a new version tag is pushed (e.g., `v1.0.0`):
- Creates a draft GitHub release
- Builds release binaries for all supported platforms:
  - Linux x64 and ARM64
  - macOS x64 and ARM64 (Apple Silicon)
  - Windows x64
- Uploads binaries as release assets

### Benchmarks (`benchmark.yml`)
Runs on pushes and PRs to main:
- Executes performance benchmarks
- Tracks performance over time
- Alerts on significant performance regressions

## Dependabot

The `dependabot.yml` file configures automatic dependency updates:
- Checks for Cargo dependency updates weekly
- Checks for GitHub Actions updates weekly
- Creates PRs with proper labels and commit messages

## Local Development

Use the Makefile for common tasks:
```bash
make check      # Run all checks (fmt, clippy, test)
make test       # Run tests
make release    # Build release binaries
make help       # Show all available commands
```

## Adding New CI Jobs

When adding new CI jobs:
1. Use caching for cargo registry/index/build to speed up builds
2. Use matrix builds to test across multiple OS/Rust versions
3. Set `CARGO_TERM_COLOR: always` for colored output
4. Use `actions/checkout@v4` for consistency
5. Pin action versions for reproducibility