# proc-janitor

> Automatic orphan process cleanup daemon for macOS (Linux experimental)

[![CI](https://github.com/jhlee0409/proc-janitor/actions/workflows/ci.yml/badge.svg)](https://github.com/jhlee0409/proc-janitor/actions/workflows/ci.yml)
[![Release](https://github.com/jhlee0409/proc-janitor/actions/workflows/release.yml/badge.svg)](https://github.com/jhlee0409/proc-janitor/releases)
[![crates.io](https://img.shields.io/crates/v/proc-janitor.svg)](https://crates.io/crates/proc-janitor)
[![Downloads](https://img.shields.io/crates/d/proc-janitor.svg)](https://crates.io/crates/proc-janitor)
[![GitHub Release](https://img.shields.io/github/v/release/jhlee0409/proc-janitor)](https://github.com/jhlee0409/proc-janitor/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**proc-janitor** detects and terminates orphaned processes that linger after their parent terminal or application exits. No more zombie Node.js instances eating up your RAM.

## Why?

When you close a terminal (Ghostty, iTerm2, VS Code, etc.), child processes like **Claude Code**, **Node.js**, or **MCP servers** often keep running as orphans (`PPID=1`). Each one silently consumes 200-300MB of memory.

This happens because:

- **Terminals don't always send SIGHUP** when closed via Cmd+W or the window button
- **macOS lacks `prctl(PR_SET_PDEATHSIG)`** — there's no native way to auto-kill children when the parent dies
- **Processes escape process groups** via `setsid`, `disown`, or background execution

You end up manually running `pkill -f claude` every few hours. proc-janitor automates this.

## How It Works

```
Discovery pass (every scan_interval, default 5s):

1. Scan process table for PPID=1 processes
2. Match against target patterns (regex)
3. Skip whitelisted processes
4. Wait grace period (default 30s) to avoid false positives
5. Send SIGTERM → wait → SIGKILL if unresponsive
6. Log everything

Between passes the daemon is not merely asleep — it is watching:

  • the PARENTS of processes that match a target but are not orphans yet
    → their exit is the instant a process becomes an orphan
  • tracked orphans themselves
    → so one that exits on its own leaves the grace-period map immediately
```

### Reacting without polling

A process becoming an orphan is an *event*, and macOS will report it: kqueue's
`EVFILT_PROC`/`NOTE_EXIT` watches any PID unprivileged. The daemon sleeps on
those notifications instead of only on a timer, so it notices the moment your
terminal dies rather than at the next tick.

Measured end-to-end (parent killed → orphan cleaned), debug build:

| `scan_interval` | Reaction |
|-----------------|----------|
| 5s | **30 ms** |
| 30s | **31 ms** |
| 60s | **29 ms** |

Reaction no longer depends on the interval, which means the interval is now free
to raise. The scan still bounds *discovery* — macOS has no unprivileged
process-creation event (`EndpointSecurity` requires an entitlement, and kqueue's
`NOTE_TRACK` returns `ENOTSUP`) — so a new process is picked up within one
interval. But once it is known, its death link is instant. At `scan_interval = 60`
the daemon does 1,440 scans a day instead of 17,280, with the same responsiveness.

On platforms without kqueue this degrades to the plain interval sleep. Linux's
own answer to the underlying problem is `PR_SET_PDEATHSIG`, which
[`proc-janitor exec`](#prevention-proc-janitor-exec) uses directly.

### Orphan Evidence

`PPID == 1` is a weaker signal than it looks. Measured on macOS 25.6: **470 of the
654 processes owned by the logged-in user already have PPID 1**, because launchd
both reparents orphans *and* directly launches most agents and services. The
PPID filter therefore removes under 30% of candidates, and safety rests almost
entirely on your target patterns.

The session id discriminates far better. Of those same 470 processes:

| Session state | Count | What it usually means |
|---------------|-------|-----------------------|
| In init's session (`sid == 1`) | 283 | launchd/systemd-managed service |
| Own session leader (`sid == pid`) | 179 | called `setsid()` — a detached daemon *or* a `disown`ed job |
| **Session leader gone** | **8** | **a terminal exited and left this behind** |

`scan` reports which of these applies to each detected process. Setting
`require_dead_session = true` restricts cleanup to the last category — the actual
signature of the problem this tool exists to solve. The trade-off: orphans that
called `setsid()` become their own session leader and are then indistinguishable
from an intentional daemon, so they are skipped.

## Prevention: `proc-janitor exec`

The daemon is cleanup — it finds processes that have *already* been orphaned and
decides from regex patterns whether they should die. `exec` is prevention, and it
needs no patterns at all:

```bash
proc-janitor exec -- claude
```

proc-janitor watches its own parent (your shell or terminal) and terminates the
command's process tree the instant that parent exits. It knows exactly which
process it started and exactly whose death should end it, so there is nothing to
match and no false positive to worry about.

```text
terminal ──spawns──▶ proc-janitor exec ──spawns──▶ claude
   │                        │
   └── exits ───────────────┤  NOTE_EXIT (macOS) / PDEATHSIG (Linux)
                            ▼
                   SIGTERM → SIGKILL the process tree
```

Linux has a kernel mechanism for this, `prctl(PR_SET_PDEATHSIG)`. macOS does not
— that is root cause #2 in [Why?](#why) above — but kqueue's
`EVFILT_PROC`/`NOTE_EXIT` can watch any PID without privileges, so the same
guarantee is available there. Measured on macOS 25.6: **0.22 ms** from the parent
exiting to the notification arriving. No polling, no process-table scanning, no
daemon required.

`exec` is transparent: stdin/stdout/stderr are inherited and the command's exit
code is propagated unchanged, so it composes with shell aliases and scripts.

```bash
alias claude='proc-janitor exec -- claude'
```

**Termination.** `exec` also takes the command down when it is itself told to
stop (`kill`, `pkill`, a service manager stopping the unit) — otherwise the very
orphan it exists to prevent would be left behind. Ctrl-C is unaffected: the child
stays in the terminal's process group, so the terminal signals both, and the
command keeps its normal signal dispositions.

**Limitations.** A descendant that calls `setsid()` re-parents itself out of the
tree and can no longer be reached from the command's PID — that is the case the
pattern-matching daemon exists to cover, so the two are complementary. Signals
are sent per PID with the same `start_time` identity verification the daemon
uses, so a PID recycled between the process-tree snapshot and the signal is
skipped rather than killed.

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/jhlee0409/proc-janitor/main/scripts/install-binary.sh | sh
```

Downloads the latest pre-built binary for your platform (macOS/Linux, x86_64/ARM64) and installs it to `/usr/local/bin`.

### Homebrew (macOS/Linux)

```bash
brew install jhlee0409/tap/proc-janitor

# Start as a background service
brew services start proc-janitor
```

### From crates.io

```bash
cargo install proc-janitor
```

### GitHub Releases

Pre-built binaries for every release are available on the [Releases page](https://github.com/jhlee0409/proc-janitor/releases/latest). Download the archive for your platform, extract, and place `proc-janitor` in your PATH.

| Platform | Architecture | Download |
|----------|-------------|----------|
| macOS | Apple Silicon (M1/M2/M3/M4) | `proc-janitor-v*-aarch64-apple-darwin.tar.gz` |
| macOS | Intel | `proc-janitor-v*-x86_64-apple-darwin.tar.gz` |
| Linux | x86_64 | `proc-janitor-v*-x86_64-unknown-linux-gnu.tar.gz` |
| Linux | ARM64 | `proc-janitor-v*-aarch64-unknown-linux-gnu.tar.gz` |

### Build from Source

```bash
git clone https://github.com/jhlee0409/proc-janitor.git
cd proc-janitor
cargo build --release
sudo cp target/release/proc-janitor /usr/local/bin/
```

### macOS Full Setup (LaunchAgent)

```bash
git clone https://github.com/jhlee0409/proc-janitor.git
cd proc-janitor && bash scripts/install.sh
```

This builds the binary, installs it, creates a default config, and sets up a macOS LaunchAgent for auto-start on login.

### Linux (systemd)

```bash
cargo install proc-janitor

# Create the data/config dirs (required by the sandboxed unit before it starts)
mkdir -p ~/.proc-janitor ~/.config/proc-janitor

# Choose what to clean up — nothing is killed until you configure targets
proc-janitor config init

# Install the user service, substituting the absolute path to your binary
# (cargo install puts it in ~/.cargo/bin, which is not on systemd's PATH).
mkdir -p ~/.config/systemd/user
sed "s|__BIN__|$(command -v proc-janitor)|" resources/proc-janitor.service \
  > ~/.config/systemd/user/proc-janitor.service

systemctl --user daemon-reload
systemctl --user enable --now proc-janitor

# IMPORTANT: keep the daemon running across reboots and without an active
# login session — without this, a --user service stops at logout/reboot.
loginctl enable-linger "$USER"
```

### Uninstall

```bash
# If installed via install.sh
bash scripts/install.sh --uninstall

# If installed via Homebrew
brew uninstall proc-janitor
```

## Quick Start

```bash
# Create a config file with explanations
proc-janitor config init

# Detect orphaned processes (safe, no killing)
proc-janitor scan

# Watch mode: continuously scan every 5 seconds
proc-janitor scan --watch 5

# Preview what would be killed (no signals sent)
proc-janitor clean --dry-run

# Kill all detected orphans (asks for confirmation on a terminal)
proc-janitor clean

# Kill only specific PIDs
proc-janitor clean --pid 12345 67890

# Kill only orphans matching a pattern
proc-janitor clean --pattern "node.*mcp"

# Kill only orphans older than 5 minutes
proc-janitor clean --min-age 300

# Interactive mode: confirm each kill
proc-janitor clean --interactive

# Start the daemon (runs in background)
proc-janitor start

# Check status
proc-janitor status

# Stop the daemon
proc-janitor stop

# Restart the daemon (stop + start)
proc-janitor restart

# Reload config without restart (send SIGHUP)
proc-janitor reload

# View cleanup statistics (last 7 days)
proc-janitor stats
proc-janitor stats --days 30

# View process tree filtered by pattern
proc-janitor tree --pattern "node"

# Diagnose issues
proc-janitor doctor

# Generate shell completions (add to your .zshrc/.bashrc)
proc-janitor completions zsh > ~/.zfunc/_proc-janitor

# Get JSON output
proc-janitor -j status
proc-janitor -j config show
proc-janitor -j scan
```

## Configuration

Config file: `~/.config/proc-janitor/config.toml` (all platforms)

```toml
# How often to scan (seconds, 1–3600)
scan_interval = 5

# Wait time before killing a new orphan (seconds)
grace_period = 30

# Time to wait after SIGTERM before SIGKILL (seconds)
sigterm_timeout = 5

# Target process patterns (regex)
targets = [
    "node.*claude",    # Claude Code
    "claude",          # Claude CLI
    "node.*mcp",       # MCP servers
]

# Never kill these (regex)
whitelist = [
    "node.*server",    # Your web servers
    "pm2",             # Process managers
]

# Require evidence that the process's session is gone, not just PPID=1
# (see "Orphan Evidence" below). Off by default.
require_dead_session = false

[logging]
enabled = true
path = "/Users/you/.proc-janitor/logs"  # absolute path required (~ not expanded)
retention_days = 7
```

Edit with: `proc-janitor config edit`

### Environment Variable Overrides

Every config option can be overridden via environment variables. Values outside the valid range are rejected with a warning and the default is kept.

| Variable | Valid Range | Example |
|----------|------------|---------|
| `PROC_JANITOR_SCAN_INTERVAL` | 1–3600 | `10` |
| `PROC_JANITOR_GRACE_PERIOD` | 0–3600 | `60` |
| `PROC_JANITOR_SIGTERM_TIMEOUT` | 1–60 | `15` |
| `PROC_JANITOR_TARGETS` | comma-separated regexes | `"python.*test,node.*dev"` |
| `PROC_JANITOR_WHITELIST` | comma-separated regexes | `"safe1,safe2"` |
| `PROC_JANITOR_REQUIRE_DEAD_SESSION` | `true` / `false` | `true` |
| `PROC_JANITOR_LOG_ENABLED` | `true` / `false` | `false` |
| `PROC_JANITOR_LOG_PATH` | path under `$HOME` | `"/Users/you/.proc-janitor/logs"` |
| `PROC_JANITOR_LOG_RETENTION_DAYS` | 0–365 | `14` |

`PROC_JANITOR_LOG_PATH` is validated for safety: directory traversal (`..`), system paths (`/etc/`, `/usr/`, etc.), and paths outside `$HOME` are rejected. `/var/log/` is allowed as a standard log location.

## CLI Reference

### Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--json` | `-j` | Output results in JSON format (supported by: `status`, `config show`, `scan`, `clean`, `stats`) |
| `--quiet` | `-q` | Suppress non-essential output (hints, spinners). Useful for scripts and cron jobs. |

### Core Commands

| Command | Description |
|---------|-------------|
| `start [-f\|--foreground] [-d\|--dry-run]` | Start the daemon. With `--dry-run`, scan and log without killing. |
| `stop` | Stop the daemon |
| `status` | Show daemon status (systemctl-style with uptime) |
| `scan [-w\|--watch SECS]` | Detect orphaned processes (safe, no killing). With `--watch`, continuously scan at interval. |
| `clean [--pid PIDs] [--pattern REGEX] [-i\|--interactive] [-d\|--dry-run] [-y\|--yes] [--min-age SECS]` | Kill orphaned target processes (all by default, or filter by PID/pattern/age). On an interactive terminal it lists the targets and asks for confirmation first; `-y` skips the prompt, `-i` confirms each kill, `-d` only shows what would be killed. |
| `restart [-f\|--foreground] [-d\|--dry-run]` | Restart the daemon (stop + start) |
| `reload` | Reload daemon configuration (sends SIGHUP, no restart needed) |
| `exec [--sigterm-timeout SECS] -- <command>` | Run a command that cannot outlive the terminal that started it. See [Prevention](#prevention-proc-janitor-exec). |
| `stats [--days N]` | Show cleanup statistics from the last N days (default: 7). Supports `--json`. |
| `tree [-t\|--targets-only] [-m\|--pattern REGEX]` | Visualize process tree (optionally filter by regex pattern) |
| `logs [-f\|--follow] [-n N]` | View logs (N: 1–10000, default 50) |
| `version` | Show version and build information |
| `doctor` | Diagnose common issues and check system health |
| `completions <shell>` | Generate shell completions (`bash`, `zsh`, `fish`, `powershell`) |

### Config Commands

| Command | Description |
|---------|-------------|
| `config init [--force] [--preset NAME] [-y\|--yes]` | Create config (auto-detects orphans, or use preset: `claude`, `dev`, `minimal`). Use `--yes` to skip prompts. `--list-presets` to see available presets. |
| `config show` | Display current config |
| `config edit` | Edit config in `$EDITOR` (validates after save, supports flags like `code --wait`) |
| `config env` | Show all environment variable overrides with current values |
| `config validate` | Validate configuration file and show a summary |

### Session Commands

Track related processes as a group. Each tracked PID stores its start_time for PID reuse detection — session cleanup verifies process identity before sending signals, even hours after registration.

`session clean` has two modes, which differ in how much they trust the caller:

| Session state | What is killed |
|---------------|----------------|
| Has explicitly tracked PIDs | Those PIDs and their whole subtrees, **without** pattern filtering — naming a PID via `session track` is consent |
| Nothing tracked | Descendants of the session's parent that match a target pattern and are not whitelisted — the same rule `scan` uses |

The second mode is what makes the [shell integration](integrations/shell-integration.sh) useful: a shell registers one session at startup and runs `session clean` on exit, so closing the terminal cleans up the target processes it started and nothing else. With no target patterns configured it kills nothing.

```bash
proc-janitor session register --name "my-session" --source terminal
proc-janitor session register --id custom-id --name "dev" --source vscode --parent-pid 1234
proc-janitor session track <session-id> <pid>
proc-janitor session list
proc-janitor session clean <session-id> [--dry-run]
proc-janitor session unregister <session-id>
proc-janitor session auto-clean [--dry-run]
```

Supported `--source` values: `claude-code`, `terminal`, `vscode`, `tmux`, or any custom string.

## Daemon Features

### Config Auto-Reload

The daemon watches `config.toml` for changes and automatically reloads when the file is modified. No restart needed — just edit and save.

### Desktop Notifications (macOS)

When the daemon kills orphaned processes, it sends a macOS notification via Notification Center showing how many processes were cleaned.

### Cleanup Statistics

Every cleanup action is recorded to `~/.proc-janitor/stats.jsonl` as append-only JSON Lines. Each entry includes a timestamp, the number of processes cleaned, and details of each kill (PID, name, signal used, success/failure). The file is automatically rotated (to `stats.jsonl.old`) when it exceeds 5 MB.

## macOS LaunchAgent

Auto-start on login:

```bash
# Install (done automatically by install.sh)
launchctl load ~/Library/LaunchAgents/com.proc-janitor.plist

# Uninstall
launchctl unload ~/Library/LaunchAgents/com.proc-janitor.plist
```

## Safety

- **Whitelist protection** — matching processes are never killed
- **System PID guard** — PIDs 0, 1, 2 are always protected
- **Grace period** — orphans get time to self-cleanup before termination
- **PID reuse mitigation** — verifies process identity (start_time) before sending signals, including session-tracked PIDs
- **Daemon identity verification** — `stop` confirms the PID file points to an actual proc-janitor process before sending signals
- **Symlink protection** — refuses to write to symlinks at predictable paths (`~/.proc-janitor/`), preventing local symlink attacks
- **TOCTOU-safe session store** — exclusive file lock held across full read-modify-write cycle
- **Guided setup** — shows a helpful hint when no target patterns are configured, guiding users to `config init`
- **Safe by default** — with no config file, targets are empty and nothing is killed; the daemon refuses to start until you run `config init` (or set `PROC_JANITOR_TARGETS`)
- **Confirm before killing** — interactive `clean` lists targets and prompts on a terminal (`-y` to skip, `-d` for a dry-run); non-TTY usage (scripts/cron) proceeds unprompted
- **Scan before clean** — `scan` is always safe (detection only), `clean` is always destructive (with optional filters)
- **Atomic file operations** — config and session data use file locking with fsync for crash safety
- **Directory permissions** — `~/.proc-janitor/` created with `0o700` (owner-only access)
- **Audit logging** — every termination is recorded to the rotating log (`~/.proc-janitor/logs/proc-janitor.<date>.log`, subject to `retention_days`) and to `stats.jsonl`, with timestamps, PID, and the signal used
- **Supervisor logs are left alone** — `launchd.log` / `launchd.err` / `daemon.out` / `daemon.err` are written by launchd, systemd, or the daemonizer, which hold those files open; proc-janitor never rotates or deletes them (deleting a file the supervisor has open would silently discard all further output). They are unrotated, so `doctor` warns when one exceeds 10 MiB and tells you how to truncate it

## Architecture

```text
proc-janitor/
├── src/
│   ├── main.rs        # Entry point
│   ├── cli.rs         # CLI argument parsing (clap)
│   ├── daemon.rs      # Daemon lifecycle (start/stop/status)
│   ├── scanner.rs     # Orphan process detection
│   ├── cleaner.rs     # Process termination (SIGTERM/SIGKILL)
│   ├── kill.rs        # Shared kill logic (system PID guard, PID reuse check, polling)
│   ├── doctor.rs      # Health checks and diagnostics (9 checks)
│   ├── config.rs      # TOML config + env var overrides + presets
│   ├── config_template.toml  # Commented config template (embedded at compile time)
│   ├── logger.rs      # Structured logging with rotation
│   ├── session.rs     # Session-based process tracking (TrackedPid with start_time)
│   ├── util.rs        # Shared utilities (color, symlink protection, process snapshots)
│   ├── watch.rs       # Event-driven exit notification (kqueue NOTE_EXIT)
│   ├── exec.rs        # `exec`: parent-death link (macOS PR_SET_PDEATHSIG equivalent)
│   └── visualize.rs   # ASCII process tree
├── resources/
│   └── com.proc-janitor.plist  # LaunchAgent template
├── scripts/
│   └── install.sh     # One-line installer
├── tests/
│   └── integration_test.rs
├── Cargo.toml
└── LICENSE
```

## License

[MIT](LICENSE)
