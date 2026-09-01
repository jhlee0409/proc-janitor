# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **The Homebrew formula is no longer pushed from the release workflow.** That job
  cloned the tap and committed, which needs a cross-repo token
  (`HOMEBREW_TAP_TOKEN`). The token expired and the job failed with "Invalid
  username or token" on **every release from v0.8.3 through v0.10.1 — five in a
  row** — while the build and release jobs stayed green, so the failure was easy to
  miss and the formula was updated by hand each time.

  The tap pulls now: a workflow there reads this repo's latest release and commits
  with its own `GITHUB_TOKEN`, which is scoped to that repository and does not
  expire. There is no secret left to rotate, and it is self-healing — a missed or
  failed run is picked up by the next scheduled one instead of leaving the formula
  stale until someone notices. It runs daily; to publish immediately after a
  release:

  ```bash
  gh workflow run update-formula.yml -R jhlee0409/homebrew-tap
  ```

  Verified end to end on the tap: the no-op path makes no commit when the formula
  is current, and reverting the formula to 0.10.0 on purpose had it restored to
  0.10.1 within 6 s, with all four checksums matching the published release
  assets. `HOMEBREW_TAP_TOKEN` can be deleted from this repository's secrets.

## [0.10.1] - 2026-09-01

### Security
- **A config that cannot be loaded no longer starts the daemon with the built-in
  kill patterns.** `Config::load()` returns *empty* targets when there is no
  config file — the 0.8.2 "safe by default" behaviour — so an error means the user
  has a config expressing intent that could not be honoured. `daemon::start` was
  catching that error and substituting `Config::default()`, whose targets are
  `["node.*claude", "claude", "node.*mcp"]`. A single missing comma therefore
  turned "kill only `my_specific_marker`" into "kill Claude Code and MCP servers",
  after printing a warning most users would never see. Verified against a real
  malformed config before the fix: the daemon started and entered its scan loop.

  This is arguably worse than the original 0.8.2 bug, because the user *did*
  express intent and a typo silently replaced it with something destructive.
  `start` now refuses, naming the cause, the consequence and the fix. `scan` and
  `clean` already propagated the error correctly.

- **Process command lines can no longer inject terminal escapes or forge report
  lines.** A process controls its own `argv`, and `scan`/`clean` printed it
  verbatim. Verified with a probe whose command line carried `\x1b[2J` (clear
  screen), `\x1b[1;1H` (move cursor), `\x1b]0;…\x07` (rewrite the window title)
  and a newline: `scan` emitted all three escape bytes and an extra output line
  reading `FAKE INFO proc_janitor::cleaner: terminated orphaned process pid=1` —
  a fabricated entry indistinguishable from a real one.

  Human-readable output now goes through `util::sanitize_for_display`, which
  renders control characters as visible `\xNN` so nothing is dropped and nothing
  executes. `ps` sanitises for exactly this reason. JSON output deliberately does
  not: `serde_json` escapes control characters already, and the emitted value has
  to remain the real command line.

- **Pattern compilation is bounded.** The config limits how many patterns there
  are (100) and how long each is (1024 chars), but nothing bounded what a pattern
  costs to *compile*. Measured: 100 copies of a 39-character pattern
  (`(?i)(?:\p{L}|\p{N}|\p{P}){1,150}zzqq`) — a config `config validate`
  accepted — made a single scan take **7.5 s and 1,566 MB of peak RSS**, which the
  daemon then holds for its entire lifetime. Unicode case folding plus a bounded
  repetition is enough; no malice required, and a machine under memory pressure
  would simply OOM-kill the daemon.

  All 11 compilation sites now go through `scanner::compile_pattern`, which sets a
  1 MB compiled-size and DFA-cache budget per pattern (`regex`'s own default is
  10 MB, so 100 patterns could legitimately reach ~1 GB). The same config now
  fails in 0.01 s at 10 MB with `Compiled regex exceeds size limit of 1048576
  bytes` — fail-closed, since an invalid pattern already means the daemon refuses
  to start and a reload keeps the previous scanner.

### Changed
- **`exec` no longer uses `unsafe`.** `AGENTS.md` forbids introducing `unsafe`,
  and 0.9.1 shipped two blocks in `src/exec.rs` — the only ones in the crate —
  against that rule. Both are gone, and the code is simpler for it:
  - `SIGINT`/`SIGTERM` are now *caught* via `signal_hook::flag::register` (a safe
    API) instead of being set to `SIG_IGN` through `nix`'s unsafe `signal()`.
  - That removed the need for the `Command::pre_exec` hook as well. POSIX resets
    *caught* signals to their default action across `exec` while `SIG_IGN` is
    inherited, so the supervised command keeps normal signal behaviour with no
    work in the child at all.

  All four behaviours were re-verified against the release binary: a `SIGTERM`
  aimed at the wrapper still terminates the command (2/2), the command still dies
  from a `SIGTERM` of its own, parent death still cleans up, and a process-group
  `SIGINT` (what Ctrl-C sends) still takes both down.
- The no-`unsafe` rule is now pinned by `test_src_contains_no_unsafe_code`. It
  was broken silently once; a stated invariant that nothing checks is a
  preference, not a rule.

### Notes
- `daemonize` (RUSTSEC-2025-0069, unmaintained) is kept deliberately. Replacing
  it by hand needs `nix::unistd::fork`, which is `unsafe fn`, so a replacement
  would trade an advisory *warning* for an actual rule violation plus hand-rolled
  fork/dup2 logic. The dependency-free alternative is to drop background mode
  entirely — every documented path (LaunchAgent, systemd unit, `brew services`)
  already runs `start --foreground` — but that changes what `proc-janitor start`
  does and is a product decision, not a cleanup.

## [0.10.0] - 2026-09-01

### Security
- **A dependency pin was holding back a crate with a published advisory.** The
  1.82 MSRV was kept by pinning `time` to 0.3.41 in the lockfile; `cargo audit`
  showed 0.3.41 is affected by RUSTSEC-2026-0009 (denial of service via stack
  exhaustion, severity 6.8, fixed in 0.3.47). Trading that for a lower MSRV is
  the wrong way round — most users install a prebuilt binary or via Homebrew,
  where the MSRV never applies. `time` is current again (0.3.55), and
  `crossbeam-epoch` (RUSTSEC-2026-0204, invalid pointer dereference, via
  `sysinfo` → `rayon`) and `anyhow` were updated with it. `cargo audit` now
  reports no vulnerabilities.

  **MSRV is therefore now 1.88**, up from 1.82, which is what the current
  dependency set actually requires. It is verified in CI as before.

### Added
- CI runs `cargo audit`. This tool kills processes on the user's machine; a
  known-vulnerable dependency reaching a release is worth failing the build over.
  It is also what found the pin above.
- Three `doctor` checks for the "the install is silently broken" class of
  problem, each of which was previously invisible:
  - **Service definition** — the plist or systemd unit keeps the absolute path it
    was written with, so moving or reinstalling the binary elsewhere leaves the
    supervisor launching something that no longer exists (launchd retries forever,
    systemd fails 203/EXEC) and nothing gets cleaned up. Fails when the recorded
    path is missing; when it merely differs from the `proc-janitor` on `PATH`,
    that is reported without failing, since having both installed is legitimate.
  - **Self-match guard** — a target pattern that matches proc-janitor's own
    command line. The daemon refuses to signal itself, so this cannot cause
    suicide, but such a pattern will match *another* proc-janitor process and is
    almost always a `.*`-shaped mistake that takes unrelated processes with it.
  - **Env overrides** — `PROC_JANITOR_*` set in a shell profile applies to the
    CLI but not to a launchd or systemd service, which does not inherit the
    shell's environment. The result is `config env` showing one configuration
    while the daemon runs with another.
- `$PROC_JANITOR_CONFIG` overrides the config file path. Every caller already
  went through `config_path()`, so this works for the daemon, the CLI and
  `doctor` alike. It makes a second profile — or an isolated test run — possible
  without rewriting `$HOME`. Unlike `PROC_JANITOR_LOG_PATH` it is used as given:
  it names a file the invoking user explicitly chose, so there is no privilege
  boundary to defend, and writes still go through `open_nofollow_write`.

### Fixed
- `scan` details no longer freeze at first sighting. The daemon's tracking map
  kept the whole `OrphanProcess` from the moment a process was first seen, so
  memory, uptime and command line could be hours stale. Only `first_seen` is
  history now — it is the anchor the grace period is measured from — and every
  other field comes from the current snapshot. Latent rather than user-visible
  today, since nothing reports those fields from the daemon, but it made the
  struct lie about what it described.

### Changed
- CI lints tests too (`clippy --all-targets`). Without it, test code drifts out
  of lint compliance unnoticed; there were twelve such warnings.
- The dozen near-identical `validate()` boundary tests are now one table, so the
  accepted ranges are stated once instead of spread across twelve functions. The
  table also covers cases the individual tests missed (`scan_interval = 1`,
  `grace_period = 3600`, `sigterm_timeout = 1`, and the whitelist count limit).
- **`session clean` now does something when nothing was tracked.** A session
  registered without explicit `session track` calls had `pids: []`, so
  `session clean` found nothing and killed nothing. The shell integration was
  built entirely on that path — register a session at shell startup, run
  `session clean` on exit — which made it pure ceremony.

  With nothing tracked, cleanup now falls back to the descendants of the
  session's parent that match a target pattern and are not whitelisted, i.e. the
  same rule `scan` and the daemon apply. Explicitly tracked PIDs keep their old
  behaviour: killed with their whole subtree and no pattern filtering, because
  naming a PID is consent.

  The fallback is deliberately pattern-gated. Unfiltered it would be "kill every
  process in the terminal", which would bypass the target/whitelist model the rest
  of the tool rests on — `test_session_clean_fallback_spares_unmatched_processes`
  pins that a non-matching process survives, and fails if the filter is removed.
  With no target patterns configured the fallback kills nothing.

  The output states which mode ran, so it is never ambiguous what a given
  `session clean` was allowed to touch.
- `integrations/shell-integration.sh` describes what actually happens instead of
  implying automatic tracking, and documents that `pj-track` is only needed for
  processes the target patterns do *not* match — including its real limitation
  (it backgrounds the command, so an interactive program will not receive Ctrl-C
  through it).

## [0.9.1] - 2026-08-30

### Fixed
- **`exec` now takes the command down when *it* is told to stop, not only when
  its parent dies.** A signal aimed at the wrapper itself — `kill <pid>`,
  `pkill -f proc-janitor`, a service manager stopping the unit — killed the
  wrapper and left the command running with `PPID=1`, precisely the state the
  subcommand exists to prevent. Reproduced 2/2 on macOS 25.6 before the fix.

  `SIGINT`/`SIGTERM` are now observed rather than fatal: on macOS through
  `EVFILT_SIGNAL` in the same kqueue that already watches for exits (so it stays
  event-driven, no polling added), and on Linux through the existing signal
  thread. The wrapper terminates the command's tree and exits `128 + signal`.

  Two behaviours were explicitly verified not to regress: the child does **not**
  inherit the ignored dispositions (they are reset to `SIG_DFL` between fork and
  exec, so the command stays normally killable), and a process-group signal —
  what Ctrl-C actually sends — still cleans up both, since the child is
  deliberately left in the terminal's process group.

  Linux additionally reported the wrong cause: `PR_SET_PDEATHSIG` delivers an
  ordinary `SIGTERM`, so a user's `SIGTERM` was logged as "parent exited". The
  parent's PID is now re-checked to distinguish the two; both still terminate the
  command.

  Covered by `test_exec_kills_command_when_signalled_itself`, which keeps the
  parent shell alive so nothing but the wrapper can be responsible for the
  cleanup, and which fails against the 0.9.0 behaviour.

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
