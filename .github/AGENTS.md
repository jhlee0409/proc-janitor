<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-02-06 -->

# .github

## Purpose
GitHub-specific configuration: CI/CD workflows and issue templates.

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `workflows/` | CI workflow definitions |
| `ISSUE_TEMPLATE/` | Bug report and feature request templates |

## Key Files
| File | Description |
|------|-------------|
| `workflows/ci.yml` | CI pipeline: check, test (ubuntu + macos), clippy, fmt |
| `ISSUE_TEMPLATE/bug_report.md` | Bug report template |
| `ISSUE_TEMPLATE/feature_request.md` | Feature request template |

## For AI Agents

### Working In This Directory
- CI runs on every push to `main` and on PRs
- CI matrix: `macos-latest` + `ubuntu-latest` for check and test
- Clippy and fmt run on `macos-latest` only
- CI uses `dtolnay/rust-toolchain@stable` and `Swatinem/rust-cache@v2`
- Always run `cargo fmt` locally before pushing to avoid CI failures

<!-- MANUAL: -->
