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
cargo test           # 119 tests (90 unit + 29 integration)
cargo check --target x86_64-unknown-linux-gnu --all-targets   # cfg-gated Linux path
cargo clippy         # Must be warning-free. Run on an up-to-date `stable`: CI uses
                     # dtolnay/rust-toolchain@stable, so an older local toolchain
                     # silently misses lints (e.g. collapsible_match landed in 1.98)
cargo fmt --check    # CI enforces formatting
```

### Common Patterns
- File locking: `set_len(0)` + `seek(0)` + `write_all` + `sync_all` under exclusive lock
- Log files: only `proc-janitor.<date>.log` is ours; supervisor redirect targets (`launchd.*`, `daemon.*`) must never be rotated or deleted
- Process table access: `util::process_snapshot()` / `process_snapshot_for(pid)`, never
  `ProcessRefreshKind::everything()` — it fetches cpu/disk/user/cwd/root/environ that nothing reads
- Target/whitelist matching: one function, `scanner::matches_any`; `visualize` must use it so
  `tree` cannot disagree with `scan`
- Color output: `crate::util::use_color()` + `owo-colors` (conditional)
- Symlink protection: `util::check_not_symlink()` before writing predictable paths
- Config validation: boundary checks on all numeric values

### Key Design Decisions
- `scan` = detection only (never kills), `clean` = execution (always kills, with optional filters)
- Scanner is stateful in daemon mode (grace period tracking), stateless in CLI mode. Config reload MUST go through `Scanner::reconfigure` — replacing the `Scanner` drops `tracked`/`first_seen` and restarts every orphan's grace period
- Two-phase kill: SIGTERM with 100ms polling, then SIGKILL after timeout
- Every kill path MUST verify `start_time` before signalling a PID (PID reuse); `exec::signal_tree` and `kill::kill_process_with_sys` both do
- `daemon`/`clean` = cleanup after the fact (pattern-based); `exec` = prevention (parent-death link, no patterns)
- The scan interval bounds *discovery* only; reacting to orphaning is event-driven (`watch::ExitWaiter`, kqueue NOTE_EXIT). Never reintroduce a plain `thread::sleep` in the daemon loop
- kqueue registration and waiting MUST be one `kevent` call: a separate registration call returns already-pending events in its own eventlist and silently drops them
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
