<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-06 -->

# scripts

## Purpose
Installation and setup scripts for proc-janitor.

## Key Files
| File | Description |
|------|-------------|
| `install.sh` | One-line installer: builds binary, copies to `/usr/local/bin/`, creates default config, installs macOS LaunchAgent |

## For AI Agents

### Working In This Directory
- `install.sh` is macOS-specific (uses `launchctl` and `~/Library/LaunchAgents/`)
- The script references `resources/com.proc-janitor.plist` for the LaunchAgent template
- Changes here should be tested manually on a clean macOS system

<!-- MANUAL: -->
