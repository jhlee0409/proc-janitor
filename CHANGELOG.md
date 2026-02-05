# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-02-06

### Added
- `doctor` command with 8-point health diagnostics (config, daemon, sessions, permissions)
- `completions` command for shell completion generation (bash, zsh, fish, powershell)
- `config init` with smart process detection and preset system (`claude`, `dev`, `minimal`)
- `config edit` command to edit config in `$EDITOR`
- `config env` command to show environment variable overrides
- `dashboard --live` mode with auto-refresh
- Short flags for common options (`-f`, `-d`, `-t`, `-e`, `-j`, `-n`, `-l`)
- `kill.rs` module with unified process termination logic, system PID guards, and PID reuse mitigation
- `util.rs` module with symlink-safe file writes (`O_NOFOLLOW`)
- Session tracking with `TrackedPid` (PID + start_time) for identity verification
- Environment variable overrides for all config options with bounds checking
- Path security validation (directory traversal and system path blocking)
- Subresource Integrity (SRI) hash verification for CDN scripts in dashboard
- GitHub Actions CI workflow (test, clippy, fmt on macOS + Linux)
- CONTRIBUTING.md, SECURITY.md, issue templates, and PR template
- 33 new unit tests across 6 modules (42 → 75 total)

### Security
- Eliminate TOCTOU race conditions in config writes, PID file creation, log redirection, and dashboard generation
- Add symlink attack prevention via `O_NOFOLLOW` atomic file operations
- Fix XSS vulnerability in HTML dashboard with proper HTML and JSON escaping
- Fix command injection in `$EDITOR` validation
- Add exclusive file locking across session store read-modify-write cycles
- Harden directory permissions to `0o700` (owner-only)
- Add CORS `crossorigin` attribute to external CDN scripts
- Protect system PIDs (0, 1, 2) from termination

### Changed
- Native Rust log tailing replaces external `tail` command dependency
- `System` instance reuse reduces redundant system calls in scan loop
- Targeted single-PID refresh via `ProcessesToUpdate` instead of full process table refresh
- Scanner preserves grace period state across scan cycles
- Daemon owns Scanner instance for persistent state
- Config loading uses safe fallback when `$HOME` is unavailable
- Improved error messages with `anyhow::context()` throughout

### Fixed
- Daemon startup race condition (EDEADLK from duplicate PID file locking)
- Session lock contention under concurrent access
- UTF-8 string truncation panic on multi-byte characters
- Dashboard rendering issues with process graph visualization
- Signal handler output redirected to stderr for safety

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
