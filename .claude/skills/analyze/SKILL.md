---
name: analyze
description: Run a structured production-readiness analysis on the codebase
user_invocable: true
---

# Codebase Production-Readiness Analysis

Perform a structured production-readiness analysis of this project. Follow these steps:

## Phase 1: Overview (First 2 tool calls)
1. Read README.md and Cargo.toml for project overview
2. List all source files in src/ and tests/
3. **Write initial overview to `analysis-report.md`** immediately

## Phase 2: Module-by-Module Analysis
For each source module in src/:
1. Read the file and analyze for:
   - **Security**: Input validation, injection risks, unsafe code, error handling
   - **Performance**: Resource management, algorithmic efficiency, memory usage
   - **Reliability**: Error handling, edge cases, panic safety
   - **Test Coverage**: Existing tests, untested paths
   - **Code Quality**: Idiomatic Rust, clippy compliance, documentation
2. **Append findings to `analysis-report.md`** after each module (incremental delivery)

## Phase 3: Cross-Cutting Concerns
- Dependency audit (outdated crates, known vulnerabilities)
- Integration test coverage
- Configuration validation
- Deployment readiness

## Phase 4: Final Report
Update `analysis-report.md` with:
- Executive summary (3 sentences)
- Categorized findings table:
  | Severity | File | Line | Issue | Recommendation |
  |----------|------|------|-------|----------------|
  | Critical | ... | ... | ... | ... |
  | High | ... | ... | ... | ... |
  | Medium | ... | ... | ... | ... |
  | Low | ... | ... | ... | ... |
- Prioritized action items (top 5)

## Rules
- ALWAYS write to `analysis-report.md` incrementally — never wait until the end
- Run `cargo clippy` and `cargo test` as part of the analysis
- Include exact file paths and line numbers for every finding
