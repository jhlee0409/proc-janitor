<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-06 -->

# tests

## Purpose
Integration tests that invoke the compiled `proc-janitor` binary directly and verify CLI behavior.

## Key Files
| File | Description |
|------|-------------|
| `integration_test.rs` | 25 integration tests covering all major CLI commands plus the reload/grace-period regression |

## For AI Agents

### Working In This Directory
- Tests invoke the compiled binary next to the test executable — `cargo build` must succeed first
- `binary_path()` resolves the binary; `sandbox()` + `pj(&home)` run it against a private `$HOME`
- **Every test MUST use `pj(&home)`, never `Command::new(binary_path())`.** All state proc-janitor
  touches (`~/.config/proc-janitor/config.toml`, `~/.proc-janitor/{proc-janitor.pid,sessions.json,stats.jsonl,logs/}`)
  derives from `$HOME`. Without the sandbox, tests mutate the developer's live state and race each
  other — a test that starts a daemon writes the PID file another test asserts is absent
- Tests should not assume any specific config exists; write one into the sandbox if the test needs it
- Tests should not kill unrelated processes — use nonexistent PIDs, unique markers, or own children

### Testing Requirements
```bash
cargo build && cargo test --test integration_test
```

### Test Coverage
| Test | What It Verifies |
|------|-----------------|
| `test_help_command` | `--help` exits 0, output contains "proc-janitor" |
| `test_config_show` | `config show` outputs scan_interval |
| `test_scan_command` | `scan` exits 0 |
| `test_scan_json_output` | `--json scan` produces valid JSON with `orphans` and `orphan_count` |
| `test_status_command` | `status` handles daemon-not-running gracefully |
| `test_session_list` | `session list` exits 0 |
| `test_tree_command` | `tree` exits 0 |
| `test_clean_command` | `clean` exits 0 |
| `test_clean_with_pid_filter` | `clean --pid 99999` exits 0 |
| `test_clean_with_pattern_filter` | `clean --pattern nonexistent` exits 0 |
| `test_reload_preserves_grace_period` | Repeated config reloads do not restart an orphan's grace period (spawns a uniquely-marked PPID=1 probe, touches the config every 1s with `grace_period = 3`, asserts the probe is still terminated) |

<!-- MANUAL: -->
