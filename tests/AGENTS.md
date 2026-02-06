<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-06 -->

# tests

## Purpose
Integration tests that invoke the compiled `proc-janitor` binary directly and verify CLI behavior.

## Key Files
| File | Description |
|------|-------------|
| `integration_test.rs` | 10 integration tests covering all major CLI commands |

## For AI Agents

### Working In This Directory
- Tests invoke `target/debug/proc-janitor` directly — `cargo build` must succeed first
- `binary_path()` helper resolves the correct binary location
- Tests should not assume any specific config exists (use env var overrides if needed)
- Tests should not kill real processes — use nonexistent PIDs or patterns

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

<!-- MANUAL: -->
