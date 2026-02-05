# proc-janitor

> Automatic orphan process cleanup daemon for macOS/Linux

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

### From crates.io (Recommended)

```bash
cargo install proc-janitor
```

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

### Cargo Install (from source)

```bash
git clone https://github.com/jhlee0409/proc-janitor.git
cd proc-janitor
cargo install --path .
```

## Quick Start

```bash
# Create a config file with explanations
proc-janitor config init

# See what's lurking
proc-janitor scan

# Clean orphans immediately
proc-janitor clean

# Start the daemon (runs in background)
proc-janitor start

# Check status
proc-janitor status

# Stop the daemon
proc-janitor stop

# Get JSON output
proc-janitor --json status
proc-janitor --json config show
proc-janitor --json scan
```

## Configuration

Config file: `~/.config/proc-janitor/config.toml` (all platforms)

```toml
# How often to scan (seconds)
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

`PROC_JANITOR_LOG_PATH` is validated for safety: directory traversal (`..`), system paths (`/etc/`, `/usr/`, etc.), and paths outside `$HOME` are rejected.

## CLI Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--json` | Output results in JSON format (supported by: `status`, `config show`, `scan`, `clean`) |

### Core Commands

| Command | Description |
|---------|-------------|
| `start [--foreground]` | Start the daemon |
| `stop` | Stop the daemon |
| `status` | Show daemon status |
| `scan [--execute]` | Scan for orphans (dry-run by default) |
| `clean [--dry-run]` | Kill orphaned target processes |
| `tree [--targets-only]` | Visualize process tree |
| `dashboard [--live] [--interval N]` | Open browser-based dashboard (live mode auto-refreshes every N seconds, default 5) |
| `logs [-n N] [--follow]` | View logs |

### Config Commands

| Command | Description |
|---------|-------------|
| `config init [--force]` | Create a commented config template (`--force` to overwrite) |
| `config show` | Display current config |
| `config edit` | Edit config in `$EDITOR` |

### Session Commands

Track related processes as a group:

```bash
proc-janitor session register --name "my-session" --source terminal
proc-janitor session track <session-id> <pid>
proc-janitor session list
proc-janitor session clean <session-id> [--dry-run]
proc-janitor session auto-clean
```

## macOS LaunchAgent

Auto-start on login:

```bash
# Install (done automatically by install.sh)
launchctl load ~/Library/LaunchAgents/com.proc-janitor.plist

# Uninstall
launchctl unload ~/Library/LaunchAgents/com.proc-janitor.plist
```

## Configuration Examples

### Development Environment

```toml
targets = ["node", "python", "ruby", "webpack", "vite"]
whitelist = ["node.*server", "python.*api"]
grace_period = 60
```

### Claude Code Only

```toml
targets = ["claude", "node.*claude", "node.*mcp"]
whitelist = []
grace_period = 30
```

## Safety

- **Whitelist protection** — matching processes are never killed
- **System PID guard** — PIDs 0, 1, 2 are always protected
- **Grace period** — orphans get time to self-cleanup before termination
- **PID reuse mitigation** — verifies process identity before sending signals
- **Dry-run mode** — preview cleanup without executing
- **Atomic file operations** — config and session data use file locking
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
│   ├── kill.rs        # Shared kill logic (system PID guard, PID reuse check)
│   ├── config.rs      # TOML config + env var overrides
│   ├── logger.rs      # Structured logging with rotation
│   ├── session.rs     # Session-based process tracking
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

~3,000 lines of Rust. 20 tests (13 unit + 7 integration).

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `sysinfo` | Cross-platform process table access |
| `clap` | CLI argument parsing |
| `nix` | Unix signals (SIGTERM/SIGKILL) |
| `serde` + `toml` | Configuration |
| `tracing` | Structured logging |
| `daemonize` | Unix daemon support |
| `fs2` | File locking |
| `regex` | Pattern matching |

## Performance

- **Memory**: ~10-20MB resident
- **CPU**: <1% with default 5s scan interval
- **Startup**: <100ms
- **Scan**: <50ms per 1,000 processes

## Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

### Development

```bash
# Build
cargo build

# Test
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- start --foreground

# Check for issues
cargo clippy
```

## License

[MIT](LICENSE)

## Related Projects

| Project | Platform | Scope |
|---------|----------|-------|
| [orphan-reaper](https://github.com/maandree/orphan-reaper) | Linux | Subreaper-based |
| [zps](https://github.com/orhun/zps) | Linux | Zombie process lister |
| [phantom-killer](https://github.com/chris-sekira/phantom-killer) | Windows | PowerShell zombie killer |

proc-janitor fills the gap on macOS where none of these tools work, and provides a configurable, pattern-based approach to orphan cleanup.
