<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-06 -->

# resources

## Purpose
Platform-specific resource files for daemon auto-start.

## Key Files
| File | Description |
|------|-------------|
| `com.proc-janitor.plist` | macOS LaunchAgent template for auto-start on login |

## For AI Agents

### Working In This Directory
- The plist is installed to `~/Library/LaunchAgents/` by `scripts/install.sh`
- Loaded/unloaded via `launchctl load`/`unload`
- References the binary at `/usr/local/bin/proc-janitor`

<!-- MANUAL: -->
