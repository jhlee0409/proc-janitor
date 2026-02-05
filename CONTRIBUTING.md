# Contributing to proc-janitor

Thank you for your interest in contributing to proc-janitor!

## Development Setup

```bash
git clone https://github.com/jhlee0409/proc-janitor.git
cd proc-janitor
cargo build
```

### Prerequisites

- Rust 1.70+
- macOS or Linux

## Making Changes

1. Fork the repository and create a feature branch from `main`
2. Make your changes
3. Ensure all checks pass:
   ```bash
   cargo fmt
   cargo clippy -- -D warnings
   cargo test
   ```
4. Commit your changes with a clear message
5. Open a pull request against `main`

## Code Style

- Follow standard Rust idioms and conventions
- Run `cargo fmt` before committing
- All `cargo clippy` warnings must be resolved
- Use `anyhow::Result` for error propagation in library code
- Avoid `unwrap()` and `panic!()` in production code (tests are fine)

## Testing

- Add unit tests for new functionality
- Integration tests go in `tests/`
- All existing tests must continue to pass
- Use `tempfile` for filesystem tests to avoid side effects

```bash
# Run all tests
cargo test

# Run a specific test
cargo test test_name
```

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include a description of what changed and why
- Reference any related issues
- Ensure CI passes before requesting review

## Reporting Bugs

Please open a GitHub issue with:
- OS and version (e.g., macOS 15.2, Ubuntu 24.04)
- Rust version (`rustc --version`)
- Steps to reproduce
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
