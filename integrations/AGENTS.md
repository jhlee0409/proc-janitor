<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-06 -->

# integrations

## Purpose
Integration helpers for connecting proc-janitor with editors, shells, and tools.

## Key Files
| File | Description |
|------|-------------|
| `claude-code-setup.sh` | Setup script for Claude Code integration (auto-registers sessions) |
| `shell-integration.sh` | Shell hooks for automatic session tracking on terminal open/close |
| `vscode-tasks.json` | VS Code tasks for scan, clean, and status commands |

## For AI Agents

### Working In This Directory
- These are optional convenience scripts, not required for core functionality
- `shell-integration.sh` is sourced from `.bashrc`/`.zshrc`
- `vscode-tasks.json` is copied to `.vscode/tasks.json` in user projects

<!-- MANUAL: -->
