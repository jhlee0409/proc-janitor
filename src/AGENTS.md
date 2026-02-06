<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-06 -->

# src

## Purpose
All Rust source code for the proc-janitor daemon and CLI. Organized as a single-binary crate with module-per-file structure.

## Key Files
| File | Description |
|------|-------------|
| `main.rs` | Entry point, command dispatch (`run()` → match on `Commands`) |
| `cli.rs` | CLI argument definitions (clap derive: `Cli`, `Commands`, `ConfigCommands`, `SessionCommands`) |
| `daemon.rs` | Daemon lifecycle: start/stop/status, signal handling, PID file management |
| `scanner.rs` | Orphan process detection: 3-phase scan (build tree → find roots → collect descendants) |
| `cleaner.rs` | Process termination: `clean_filtered()` with PID/pattern filters, `clean_all()` for batch kills |
| `kill.rs` | Shared kill logic: system PID guard (0,1,2), PID reuse check via start_time, SIGTERM→SIGKILL polling |
| `config.rs` | Layered config: defaults < TOML < env vars. Validation, presets, editor support |
| `config_template.toml` | Commented TOML template embedded at compile time via `include_str!()` |
| `logger.rs` | Structured logging with daily rotation and retention cleanup |
| `session.rs` | Session-based process tracking: `TrackedPid`, file-locked JSON persistence, TOCTOU-safe |
| `visualize.rs` | ASCII process tree with colored output |
| `doctor.rs` | 8 health checks with colored pass/fail output |
| `util.rs` | Shared utilities: `use_color()`, `check_not_symlink()` |

## Module Dependency Graph
```
main.rs  →  cli.rs (types only)
   ├→  daemon.rs  →  config.rs, scanner.rs, cleaner.rs, logger.rs
   ├→  scanner.rs →  config.rs
   ├→  cleaner.rs →  config.rs, scanner.rs, kill.rs
   ├→  kill.rs    (standalone)
   ├→  config.rs  (foundation, depended on by most modules)
   ├→  logger.rs  →  config.rs
   ├→  session.rs →  kill.rs
   ├→  visualize.rs →  config.rs, session.rs
   ├→  doctor.rs  →  config.rs
   └→  util.rs    (standalone)
```

## For AI Agents

### Working In This Directory
- **scan vs clean**: Scanner NEVER kills. Cleaner ALWAYS kills. Keep this separation strict.
- **Scanner is stateful**: `Scanner` holds a `HashMap<u32, OrphanProcess>` tracking map. Daemon reuses one instance (`scan_with_scanner()`), CLI creates fresh ones (`scan()`).
- **File locking pattern**: Session uses `set_len(0)` → `seek(0)` → `write_all` → `sync_all` under exclusive lock. Never use rename (invalidates lock).
- **fs2 calls**: Always use fully qualified syntax: `fs2::FileExt::lock_exclusive(&file)`, not `file.lock_exclusive()`.
- **Color output**: Use `crate::util::use_color()` + owo-colors. Never hardcode ANSI escape sequences.
- **XSS prevention**: In visualize.rs, use `textContent`/`serde_json::json!()`, never `innerHTML` with user data.

### Testing Requirements
- Unit tests are `#[cfg(test)] mod tests` at the bottom of each file
- Tests using env vars must use `#[serial]` from `serial_test`
- `kill.rs` tests spawn real child processes for signal testing

### Common Patterns
- `Config::load()` at the start of public CLI functions
- `grace_period = 0` for CLI commands (only daemon uses grace period)
- `anyhow::Result<T>` as return type for all fallible functions
- `tracing::warn!()` for non-fatal issues, `eprintln!()` for user-visible warnings

## Dependencies

### Internal
- All modules depend on `config.rs` (except `kill.rs` and `util.rs`)
- `cleaner.rs` and `session.rs` both depend on `kill.rs`

### External
- `sysinfo` (scanner, kill, daemon, session, visualize)
- `clap` (cli.rs only)
- `regex` (scanner, cleaner, config)
- `fs2` (daemon, session)

<!-- MANUAL: -->
