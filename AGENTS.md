<!-- Generated: 2026-02-06 -->

# proc-janitor

## Purpose
Rust daemon + CLI that polls the process table to detect and kill orphaned processes (PPID=1) matching configurable regex patterns. Primarily targets macOS with experimental Linux support.

## Key Files
| File | Description |
|------|-------------|
| `Cargo.toml` | Crate manifest (edition 2021, MSRV 1.70+) |
| `Cargo.lock` | Locked dependency versions |
| `LICENSE` | MIT license |
| `README.md` | User-facing documentation |
| `CLAUDE.md` | AI agent instructions (build commands, architecture, design decisions) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `src/` | All Rust source code (see `src/AGENTS.md`) |
| `tests/` | Integration tests (see `tests/AGENTS.md`) |
| `scripts/` | Installation script (see `scripts/AGENTS.md`) |
| `resources/` | macOS LaunchAgent plist (see `resources/AGENTS.md`) |
| `integrations/` | Shell/editor integration helpers (see `integrations/AGENTS.md`) |
| `.github/` | CI workflows and issue templates (see `.github/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Read `CLAUDE.md` first for build commands and architecture overview
- `cargo build` must succeed before `cargo test` (integration tests invoke the binary)
- All fs2 calls use fully qualified syntax (`fs2::FileExt::lock_exclusive(...)`)
- Never introduce `unsafe` code or new `unwrap()` calls

### Testing Requirements
```bash
cargo build          # Must pass first
cargo test           # 70 tests (60 unit + 10 integration)
cargo clippy         # Must be warning-free
cargo fmt --check    # CI enforces formatting
```

### Common Patterns
- File locking: `set_len(0)` + `seek(0)` + `write_all` + `sync_all` under exclusive lock
- JSON in HTML: use `serde_json::json!()` and `escape_json_for_script()`
- Color output: `crate::util::use_color()` + `owo-colors` (conditional)
- Symlink protection: `util::check_not_symlink()` before writing predictable paths
- Config validation: boundary checks on all numeric values

### Key Design Decisions
- `scan` = detection only (never kills), `clean` = execution (always kills, with optional filters)
- Scanner is stateful in daemon mode (grace period tracking), stateless in CLI mode
- Two-phase kill: SIGTERM with 100ms polling, then SIGKILL after timeout
- Session subsystem is independent with its own JSON persistence + file locking

## Dependencies

### External (key crates)
- `sysinfo` - Process table access
- `clap` + `clap_complete` - CLI parsing and shell completions
- `regex` - Target/whitelist pattern matching
- `serde` + `serde_json` + `toml` - Serialization
- `nix` - Unix signal handling
- `fs2` - Cross-platform file locking
- `anyhow` - Error handling
- `tracing` + `tracing-subscriber` - Structured logging
- `owo-colors` + `supports-color` - Conditional terminal colors
- `indicatif` - Progress spinners

<!-- MANUAL: -->
