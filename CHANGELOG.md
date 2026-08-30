# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-08-30

Two capability changes — prevention via `exec`, and event-driven reaction in the
daemon — plus the reliability and observability fixes found by re-auditing the
daemon loop, the logging pipeline and the test harness. Everything below is
reproduced by a test or measured on macOS 25.6 (~960 processes), not inferred.

### Fixed
- **A config reload no longer restarts every orphan's grace period.** The daemon
  replaced its whole `Scanner` on reload, discarding the `first_seen` timestamps
  with it. Any config file touched more often than `grace_period` — editor
  autosave, `config edit`, a `reload` loop — silently postponed cleanup forever
  (measured: `grace_period = 8`, config touched every 3s, orphan survived
  indefinitely). Reload now goes through `Scanner::reconfigure`, which recompiles
  the patterns before mutating anything and keeps the tracking map. Covered by
  `test_reload_preserves_grace_period`.
- **Terminations are now in the audit log.** Every kill was reported with
  `eprintln!`, which bypasses the logger, so the rotating log under
  `~/.proc-janitor/logs/` contained nothing but "Logger initialized" while the
  actual record went to the supervisor's stderr file. `cleaner` now emits a
  `tracing::info!` record (pid, signal, graceful/forced) alongside the progress
  output, and config reloads/failures are logged too.
- **Log retention no longer deletes the supervisor's files.** The cleanup pass
  removed any `*.log` older than `retention_days`, which included launchd's
  `StandardOutPath` (`launchd.log`). launchd holds that fd open for the daemon's
  whole lifetime, so unlinking it silently routed all further output to a deleted
  inode. Retention and `proc-janitor logs` now only consider this process's own
  `proc-janitor.<date>.log` files.
- **Integration tests are isolated from the developer's real `$HOME`.** Every
  test now runs the binary against a private temporary `$HOME`. Previously they
  read and wrote live state (`~/.config/proc-janitor/config.toml`,
  `~/.proc-janitor/{proc-janitor.pid,sessions.json,logs/}`) and raced each other:
  a test that started a daemon wrote the PID file that
  `test_reload_when_not_running` asserts is absent, so `cargo test` failed
  intermittently under the default parallelism (reproduced; passed with
  `--test-threads=1`).
- Shell integration registered a session from zsh's `precmd`, spawning a
  `proc-janitor` process and taking an exclusive lock on `sessions.json` **before
  every prompt** (~11 ms of added prompt latency, plus cross-terminal lock
  contention). Registration now happens once per shell and is guarded inside the
  function.

### Added
- **The daemon reacts to orphaning as an event instead of waiting for the next
  scan.** A process becoming an orphan is observable: kqueue
  `EVFILT_PROC`/`NOTE_EXIT` watches any PID unprivileged. Each scan now also
  registers the *parents* of target-matching processes that are not orphans yet
  (their exit is exactly the moment one becomes an orphan) plus the tracked
  orphans themselves, and the daemon sleeps on those notifications as well as the
  interval timer.

  Measured end-to-end, parent killed → orphan cleaned: **30 ms at
  `scan_interval = 5`, 31 ms at 30, 29 ms at 60** — reaction no longer depends on
  the interval at all, where previously it was bounded by it. The scan still
  bounds *discovery* (macOS has no unprivileged process-creation event:
  `EndpointSecurity` needs an entitlement and `NOTE_TRACK` returns `ENOTSUP`,
  verified), so raising `scan_interval` now trades discovery latency for CPU
  rather than responsiveness — 1,440 scans a day instead of 17,280 at 60s.

  The grace period is unchanged: it still runs from the first sighting of a
  process as an orphan. Watching the parent only makes that first sighting prompt.
  Watches are capped at 1,024 PIDs, and exceeding the cap is logged rather than
  absorbed. Platforms without kqueue keep the previous interval sleep.
- **`proc-janitor exec -- <command>`: prevention instead of cleanup.** The
  command's process tree is terminated the moment proc-janitor's own parent (the
  shell or terminal) exits, so nothing has to be pattern-matched after the fact
  and there is no false positive to guard against. Linux gets this from
  `prctl(PR_SET_PDEATHSIG)`; macOS has no equivalent — the root cause this
  project exists for — so the same guarantee is built on kqueue
  `EVFILT_PROC`/`NOTE_EXIT`, which can watch an arbitrary PID unprivileged
  (verified on macOS 25.6, including root-owned and other-user PIDs) and
  delivers in ~0.22 ms. No polling and no process-table scanning in this path.
  `exec` inherits stdio and propagates the command's exit code unchanged, so
  `alias claude='proc-janitor exec -- claude'` works.

  Signals go to each PID in the tree with the same `start_time` identity
  verification the daemon uses, deepest process first; a PID recycled between
  the tree snapshot and the signal is skipped rather than killed. The child is
  deliberately left in the terminal's process group — putting it in its own
  group would take it out of the foreground group and an interactive command
  would stop with SIGTTIN on its first terminal read.
- **Orphan evidence, and an option to require it.** `PPID == 1` turns out to be a
  weak signal: measured on macOS 25.6, 470 of the 654 processes owned by the
  logged-in user already have PPID 1, so the filter discards under 30% of
  candidates and safety rests almost entirely on the target regex. `scan` now
  reports *why* each process looks orphaned from its session id — session leader
  gone / own session leader / init session / session leader alive — and the new
  `require_dead_session` option (env: `PROC_JANITOR_REQUIRE_DEAD_SESSION`,
  default off) restricts cleanup to processes whose session leader has actually
  exited. On the same machine that is 8 of the 470. `getsid()` is one syscall and
  works across users, and it only runs for candidates that already matched a
  target pattern.
- `doctor` check for the supervisor's unrotated log files (`launchd.log`,
  `launchd.err`, `daemon.out`, `daemon.err`). They are deliberately outside the
  retention policy, so they grow without bound; the check warns past 10 MiB and
  prints the truncation command that keeps the supervisor's open fd valid.
- CI job verifying the declared MSRV (1.82) on macOS and Linux. It was previously
  an unchecked claim — only stable was built. Clippy now runs on both platforms
  too: the kqueue and `PR_SET_PDEATHSIG` paths are `cfg`-gated, so a single-OS
  lint job structurally cannot see dead code or lints in the other one.

### Changed
- **The daemon uses less than half the CPU per scan.** It built a whole new
  process table every cycle with `ProcessRefreshKind::everything()`, which also
  fetched cpu usage, disk usage, user ids, cwd, root and the full environment of
  every process — none of which is ever read. The daemon now keeps one long-lived
  `System` and refreshes only `memory` and `cmd`. Measured over 30 scans (~970
  processes, `getrusage`): **82.6 → 38.6 ms of CPU per scan** and peak RSS
  **16.8 → 12.7 MB**, reproduced across runs. At the default 5s interval that is
  ~12 minutes of CPU per day. The `everything()` pattern was copy-pasted at eight
  call sites; they now share `util::process_snapshot()` /
  `util::process_snapshot_for(pid)`, and single-PID identity lookups no longer
  refresh the whole table.
- `visualize` no longer has its own copy of target matching and descendant
  collection: `tree` and `scan` now classify through the same
  `scanner::matches_any` and `util::collect_descendants`, so the tree cannot
  disagree with what a scan would select. Dropped `ProcessNode::cpu_percent`,
  which was never displayed and was always 0.0 anyway (a single refresh cannot
  produce a CPU delta).
- **The declared MSRV is now actually verified — and it was wrong.** Adding the
  CI job revealed that `rust-version = "1.82"` could not be satisfied at all:
  `tracing-appender` pulled `time` 0.3.46 → `time-core` 0.1.8, which requires
  rustc 1.88. `time` is pinned to 0.3.41 in the committed lockfile (5 packages
  changed, all in the `time` family, used only for rolling log filenames), which
  restores a working 1.82 build and keeps `cargo install` viable on older
  toolchains. `Cargo.toml` records the constraint so a future dependency bump
  that breaks it is understood rather than silently reverted.

## [0.8.3] - 2026-06-17

Follow-up to the 0.8.2 audit fixes — closes the remaining medium/low items.

### Added
- **Container safety guard.** `clean` and the daemon refuse to act inside a
  container (where every process has PPID=1, so orphan detection is meaningless
  and would target the container's own workload). Override with
  `PROC_JANITOR_ALLOW_CONTAINER=1`. `scan` and `clean --dry-run` are unaffected.
- `--json` output for `version` and `session list`.
- Declared MSRV (`rust-version = "1.82"`).

### Fixed
- **proc-janitor refuses to kill its own process.** A daemonized instance has
  PPID=1, so a broad target pattern (e.g. matching `proc-janitor` or `.*`) could
  previously make the daemon SIGKILL itself.
- **`stats` no longer loses history on rotation.** It now reads both
  `stats.jsonl` and `stats.jsonl.old`, and timestamps are stored/compared as
  RFC3339 (timezone/DST-safe; legacy timestamps still parsed). Rotation is logged.
- `session track` warns when the PID isn't found (so PID-reuse protection is
  knowingly disabled for it) instead of silently recording it without a start_time.
- Config files missing keys now load with sensible defaults (`#[serde(default)]`)
  instead of failing to parse — protects existing configs from future fields.

### Changed
- CI and release builds use `--locked` for reproducibility.
- Removed the stale in-repo `Formula/proc-janitor.rb`; the Homebrew tap is the
  single source of truth.
- `scripts/uninstall.sh` is now a standalone, install-method-agnostic
  uninstaller (LaunchAgent, Homebrew `brew services`, Linux systemd `--user`,
  and the binary), replacing the previous macOS-only delegation to `install.sh`.

## [0.8.2] - 2026-06-17

User-perspective audit fixes. The low-level kill safety (system-PID guard,
start_time identity checks, file locking) was already solid; these fixes
address the policy/default/deployment layer where users actually got hurt.

### Fixed
- **`reload` no longer kills the daemon.** `ctrlc`'s `termination` feature
  routed SIGHUP to the shutdown handler, so `proc-janitor reload` terminated
  the daemon instead of reloading config (and stayed dead under systemd
  `Restart=on-failure`). Replaced `ctrlc` with `signal-hook`: SIGINT/SIGTERM
  shut down, SIGHUP reloads. Removing `ctrlc` also drops duplicate `nix 0.30`
  / `windows-sys` / `dispatch2` transitive dependencies.
- **`session auto-clean` no longer kills live sessions.** `register` recorded
  `parent_pid` as the short-lived CLI process (which exits immediately), so
  every default-registered session looked stale at once. It now records the
  invoking parent via `getppid()` and its `start_time`; staleness requires the
  parent to be gone or its PID reused (identity mismatch).
- A reloaded `sigterm_timeout` now takes effect on the next daemon cycle.
- systemd unit `ExecStart` was hardcoded to `/usr/local/bin`, which broke the
  documented `cargo install` flow (`~/.cargo/bin`); it is now templated
  (`__BIN__`, substituted at install time).

### Changed
- **Safe by default.** With no config file, targets are empty and nothing is
  killed; the daemon refuses to start until targets are configured (via
  `config init` or `PROC_JANITOR_TARGETS`). Previously a fresh install ran on
  built-in `claude`/`node.*mcp` targets and could kill a running Claude Code
  session on the first `clean`/`start`.
- **`clean` confirms before killing.** On an interactive terminal, `clean`
  now lists the targets and asks before sending signals. Non-TTY usage
  (scripts/cron/pipes) proceeds unprompted, so automation is unaffected.
- `config init --preset dev` now warns that its broad patterns (`node`,
  `python`, `cargo`, ...) can match your own running processes.

### Added
- `clean --dry-run` / `-d` — show what would be killed without sending signals.
- `clean --yes` / `-y` — skip the confirmation prompt.
- `clean --json` output now includes `dry_run` and `aborted` fields.
- `install-binary.sh` (curl|sh) verifies the downloaded tarball against its
  published SHA256 checksum before installing.
- README: `loginctl enable-linger` and data-dir pre-creation in the Linux
  (systemd) setup so the daemon survives reboot/logout.

## [0.5.1] - 2026-02-06

### Fixed
- `--quiet` flag now produces minimal output: PIDs only for `scan`, `successful/total` counts for `clean`

## [0.5.0] - 2026-02-06

### Added
- `version` command showing version, license, and repository info
- `--quiet` / `-q` global flag to suppress non-essential output (spinners, hints)
- `config validate` subcommand to validate configuration without running
- Man page auto-generation via `clap_mangen` in `build.rs`
- Homebrew formula (`Formula/proc-janitor.rb`) for `brew install` distribution
- systemd user service file (`resources/proc-janitor.service`) for Linux
- Standalone `scripts/uninstall.sh` convenience script

## [0.4.1] - 2026-02-06

### Improved
- Show helpful hint when no target patterns are configured and scan/clean finds nothing
- Guides users to run `proc-janitor config init` to set up targets
- No double config loading — uses `targets_configured` field on ScanResult/CleanSummary

## [0.4.0] - 2026-02-06

### Breaking Changes
- `scan --execute` flag removed — `scan` is now detection-only (never kills)
- `clean --dry-run` flag removed — use `scan` to preview, `clean` to execute
- JSON schema for `scan`: removed `cleaned_count` and `executed` fields
- JSON schema for `clean`: removed `dry_run` field

### Added
- `clean --pid` (`-p`) filter to kill only specific orphan PIDs
- `clean --pattern` (`-m`) filter to kill only orphans matching a regex pattern
- Filter intersection: when both `--pid` and `--pattern` are provided, only orphans matching both are killed
- Warning message when filters are specified but no orphans match
- 3 new integration tests for clean command variants (70 total: 60 unit + 10 integration)
- Hierarchical AGENTS.md documentation across all directories

### Changed
- `scan` and `clean` are now fully separated: scan detects, clean executes
- Daemon loop explicitly calls scan then clean as separate phases
- PID filter uses HashSet for O(1) lookup instead of linear Vec search
- `--pattern` input validated with 1024-character length limit (matches config pattern bounds)
- MSRV-compatible: uses `map_or` instead of `is_none_or` (Rust 1.70+ safe)

### Fixed
- Process tree box alignment and formatting
- Status command JSON output enriched with daemon metadata
- Session validation hardened for orphan tree detection
- 2 pre-existing clippy `uninlined_format_args` warnings in daemon.rs and visualize.rs

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
