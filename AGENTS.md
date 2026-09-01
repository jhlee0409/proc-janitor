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

> Homebrew: the formula is NOT pushed from `release.yml`. The tap
> (`jhlee0409/homebrew-tap`) pulls this repo's latest release from its own
> `update-formula.yml`, so no cross-repo secret is involved. Do not reintroduce a
> push-based job — the token it needs expired once and failed five releases in a
> row unnoticed.

## For AI Agents

### Working In This Directory
- Read `CLAUDE.md` first for build commands and architecture overview
- `cargo build` must succeed before `cargo test` (integration tests invoke the binary)
- All fs2 calls use fully qualified syntax (`fs2::FileExt::lock_exclusive(...)`)
- Never introduce `unsafe` code or new `unwrap()` calls. The `unsafe` half is pinned by
  `test_src_contains_no_unsafe_code`; if a change genuinely needs it, update the rule and that test
  together with the justification rather than adding it quietly

### Testing Requirements
```bash
cargo build          # Must pass first
cargo test           # 117 tests (83 unit + 34 integration)
cargo check --target x86_64-unknown-linux-gnu --all-targets   # cfg-gated Linux path
cargo clippy --all-targets   # Must be warning-free, tests included. Run on an up-to-date `stable`: CI uses
                     # dtolnay/rust-toolchain@stable, so an older local toolchain
                     # silently misses lints (e.g. collapsible_match landed in 1.98)
cargo fmt --check    # CI enforces formatting
cargo audit          # CI fails on advisories; keep the lockfile current
```

### Common Patterns
- File locking: `set_len(0)` + `seek(0)` + `write_all` + `sync_all` under exclusive lock
- Log files: only `proc-janitor.<date>.log` is ours; supervisor redirect targets (`launchd.*`, `daemon.*`) must never be rotated or deleted
- Process table access: `util::process_snapshot()` / `process_snapshot_for(pid)`, never
  `ProcessRefreshKind::everything()` — it fetches cpu/disk/user/cwd/root/environ that nothing reads
- Target/whitelist matching: one function, `scanner::matches_any`; `visualize` must use it so
  `tree` cannot disagree with `scan`
- Color output: `crate::util::use_color()` + `owo-colors` (conditional)
- Any process-supplied text (name, cmdline) printed for humans MUST go through
  `util::sanitize_for_display`; a process controls its own argv and can otherwise inject terminal
  escapes and forge report lines. JSON output must NOT use it — serde escapes, and the value must
  stay the real command line
- Symlink protection: `util::check_not_symlink()` before writing predictable paths
- Config validation: boundary checks on all numeric values, pinned by the table in `test_validate_boundaries`
- Regex compilation: always `scanner::compile_pattern`, never `Regex::new`. Pattern count and length are
  bounded by the config, but only that helper bounds compiled SIZE — 100 patterns of 39 chars once cost
  1.5 GB and 7.5 s per scan
- A config that exists but fails to load MUST be fatal for `start`. `Config::load()` already returns empty
  targets when there is no file, so an Err means user intent that could not be honoured; falling back to
  `Config::default()` substitutes the built-in kill patterns
- Config path: always `config::config_path()`, which honours `$PROC_JANITOR_CONFIG`; never rebuild the path inline
- MSRV is a tested claim, not a preference: never lower it by pinning a dependency back without checking `cargo audit` first

### Key Design Decisions
- `scan` = detection only (never kills), `clean` = execution (always kills, with optional filters)
- Scanner is stateful in daemon mode (grace period tracking), stateless in CLI mode. Config reload MUST go through `Scanner::reconfigure` — replacing the `Scanner` drops `tracked`/`first_seen` and restarts every orphan's grace period
- Two-phase kill: SIGTERM with 100ms polling, then SIGKILL after timeout
- Every kill path MUST verify `start_time` before signalling a PID (PID reuse); `exec::signal_tree` and `kill::kill_process_with_sys` both do
- `daemon`/`clean` = cleanup after the fact (pattern-based); `exec` = prevention (parent-death link, no patterns)
- The scan interval bounds *discovery* only; reacting to orphaning is event-driven (`watch::ExitWaiter`, kqueue NOTE_EXIT). Never reintroduce a plain `thread::sleep` in the daemon loop
- kqueue registration and waiting MUST be one `kevent` call: a separate registration call returns already-pending events in its own eventlist and silently drops them
- Background daemonization stays on the `daemonize` crate even though it is unmaintained
  (RUSTSEC-2025-0069): hand-rolling it needs `nix::unistd::fork`, which is `unsafe fn`, so a
  replacement would trade a warning for a rule violation. The dependency-free option is to drop
  background mode entirely — every documented path (plist, systemd unit, brew services) already
  uses `--foreground` — but that changes `start`'s behaviour and is a product decision
- Session subsystem is independent with its own JSON persistence + file locking
- `session clean`: explicitly tracked PIDs are killed unfiltered (naming a PID is consent); with nothing
  tracked it falls back to the parent's descendants filtered by target/whitelist patterns. The fallback MUST
  stay pattern-gated — unfiltered it would kill every process in the terminal and bypass the safety model

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
