# proc-janitor

> Automatic orphan process cleanup daemon for macOS (Linux experimental)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

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
Every 5 seconds (configurable):

1. Scan process table for PPID=1 processes
2. Match against target patterns (regex)
3. Skip whitelisted processes
4. Wait grace period (default 30s) to avoid false positives
5. Send SIGTERM → wait → SIGKILL if unresponsive
6. Log everything
```

## Installation

### Build from Source

```bash
git clone https://github.com/jhlee0409/proc-janitor.git
cd proc-janitor
cargo build --release

# Copy binary to PATH
sudo cp target/release/proc-janitor /usr/local/bin/
```

### One-Line Install (macOS)

```bash
git clone https://github.com/jhlee0409/proc-janitor.git
cd proc-janitor && bash scripts/install.sh
```

This builds the binary, installs it, creates a default config, and sets up a macOS LaunchAgent for auto-start on login.

> **Linux note:** The daemon runs on Linux via `proc-janitor start`, but there is no systemd service file yet. The install script and LaunchAgent are macOS-only. Contributions welcome!

## Quick Start

```bash
# Create a config file with explanations
proc-janitor config init

# Detect orphaned processes (safe, no killing)
proc-janitor scan

# Kill all detected orphans
proc-janitor clean

# Kill only specific PIDs
proc-janitor clean --pid 12345 67890

# Kill only orphans matching a pattern
proc-janitor clean --pattern "node.*mcp"

# Start the daemon (runs in background)
proc-janitor start

# Check status
proc-janitor status

# Stop the daemon
proc-janitor stop

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
| `PROC_JANITOR_LOG_ENABLED` | `true` / `false` | `false` |
| `PROC_JANITOR_LOG_PATH` | path under `$HOME` | `"/Users/you/.proc-janitor/logs"` |
| `PROC_JANITOR_LOG_RETENTION_DAYS` | 0–365 | `14` |

`PROC_JANITOR_LOG_PATH` is validated for safety: directory traversal (`..`), system paths (`/etc/`, `/usr/`, etc.), and paths outside `$HOME` are rejected. `/var/log/` is allowed as a standard log location.

## CLI Reference

### Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--json` | `-j` | Output results in JSON format (supported by: `status`, `config show`, `scan`, `clean`) |

### Core Commands

| Command | Description |
|---------|-------------|
| `start [-f\|--foreground]` | Start the daemon |
| `stop` | Stop the daemon |
| `status` | Show daemon status (systemctl-style with uptime) |
| `scan` | Detect orphaned processes (safe, no killing) |
| `clean [--pid PIDs] [--pattern REGEX]` | Kill orphaned target processes (all by default, or filter by PID/pattern) |
| `tree [-t\|--targets-only]` | Visualize process tree |
| `logs [-f\|--follow] [-n N]` | View logs (N: 1–10000, default 50) |
| `doctor` | Diagnose common issues and check system health |
| `completions <shell>` | Generate shell completions (`bash`, `zsh`, `fish`, `powershell`) |

### Config Commands

| Command | Description |
|---------|-------------|
| `config init [--force] [--preset NAME] [-y\|--yes]` | Create config (auto-detects orphans, or use preset: `claude`, `dev`, `minimal`). Use `--yes` to skip prompts. `--list-presets` to see available presets. |
| `config show` | Display current config |
| `config edit` | Edit config in `$EDITOR` (validates after save, supports flags like `code --wait`) |
| `config env` | Show all environment variable overrides with current values |

### Session Commands

Track related processes as a group. Each tracked PID stores its start_time for PID reuse detection — session cleanup verifies process identity before sending signals, even hours after registration.

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
- **Scan before clean** — `scan` is always safe (detection only), `clean` is always destructive (with optional filters)
- **Atomic file operations** — config and session data use file locking with fsync for crash safety
- **Directory permissions** — `~/.proc-janitor/` created with `0o700` (owner-only access)
- **Audit logging** — every action is logged with timestamps

## Architecture

```
proc-janitor/
├── src/
│   ├── main.rs        # Entry point
│   ├── cli.rs         # CLI argument parsing (clap)
│   ├── daemon.rs      # Daemon lifecycle (start/stop/status)
│   ├── scanner.rs     # Orphan process detection
│   ├── cleaner.rs     # Process termination (SIGTERM/SIGKILL)
│   ├── kill.rs        # Shared kill logic (system PID guard, PID reuse check, polling)
│   ├── doctor.rs      # Health checks and diagnostics (8 checks)
│   ├── config.rs      # TOML config + env var overrides + presets
│   ├── config_template.toml  # Commented config template (embedded at compile time)
│   ├── logger.rs      # Structured logging with rotation
│   ├── session.rs     # Session-based process tracking (TrackedPid with start_time)
│   ├── util.rs        # Shared utilities (color detection, symlink protection)
│   └── visualize.rs   # ASCII tree + HTML dashboard
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
