# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-05

### Added
- JSON output support for `status`, `config show`, `scan`, and `clean` commands via `--json` flag
- Global `--json` option for machine-readable output
- Documentation for JSON output in README

### Fixed
- Daemon startup error (errno 35 - EDEADLK) caused by duplicate PID file locking
- Session track command now returns proper error for invalid session IDs
- 3 clippy warnings (manual range contains, collapsible else-if)
- 100+ code formatting violations

### Changed
- Improved error handling for session commands
- Code now follows Rust best practices (clippy clean, rustfmt compliant)
- Updated README with JSON usage examples

## [0.1.0] - Initial Release

### Added
- Initial release of proc-janitor
- Automatic orphan process cleanup daemon
- Configurable target patterns and whitelist
- Session-based process tracking
- Process tree visualization
- Dashboard generation
- macOS LaunchAgent integration
- Shell and Claude Code integration scripts
