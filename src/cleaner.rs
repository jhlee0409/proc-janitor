use std::collections::HashSet;

use anyhow::Result;
use nix::sys::signal::Signal;
use regex::Regex;
use serde::Serialize;

use crate::config::Config;
use crate::scanner::OrphanProcess;

/// Result of cleaning a single process
#[derive(Debug, Serialize)]
pub struct CleanResult {
    pub pid: u32,
    pub name: String,
    pub success: bool,
    pub error_message: Option<String>,
    #[serde(serialize_with = "serialize_signal")]
    pub signal_used: Signal,
}

/// Serialize Signal enum as string
fn serialize_signal<S>(signal: &Signal, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{signal:?}"))
}

/// Overall clean operation result
#[derive(Debug, Serialize)]
pub struct CleanSummary {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<CleanResult>,
    pub targets_configured: bool,
}

/// Clean a single process by PID using a shared System instance (for batch operations)
pub fn clean_process_with_sys(
    sys: &mut sysinfo::System,
    pid: u32,
    start_time: u64,
    sigterm_timeout: u64,
    dry_run: bool,
) -> Result<CleanResult> {
    if dry_run {
        eprintln!("[DRY-RUN] Would clean process {pid}");
        return Ok(CleanResult {
            pid,
            name: String::new(),
            success: true,
            error_message: None,
            signal_used: Signal::SIGTERM,
        });
    }

    eprintln!("Cleaning process {pid}...");
    match crate::kill::kill_process_with_sys(sys, pid, Some(start_time), sigterm_timeout) {
        Ok(signal) => {
            eprintln!(
                "Process {} terminated ({})",
                pid,
                if signal == Signal::SIGKILL {
                    "forced"
                } else {
                    "graceful"
                }
            );
            Ok(CleanResult {
                pid,
                name: String::new(),
                success: true,
                error_message: None,
                signal_used: signal,
            })
        }
        Err(e) => {
            let err_msg = format!("{e}");
            tracing::warn!("Failed to clean PID {}: {}", pid, err_msg);
            Ok(CleanResult {
                pid,
                name: String::new(),
                success: false,
                error_message: Some(err_msg),
                signal_used: Signal::SIGTERM,
            })
        }
    }
}

/// Clean a single process by PID
#[cfg(test)]
pub fn clean_process(
    pid: u32,
    start_time: u64,
    sigterm_timeout: u64,
    dry_run: bool,
) -> Result<CleanResult> {
    let mut sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::new().with_processes(sysinfo::ProcessRefreshKind::everything()),
    );
    clean_process_with_sys(&mut sys, pid, start_time, sigterm_timeout, dry_run)
}

/// Clean all orphaned processes
pub fn clean_all(
    orphans: &[OrphanProcess],
    sigterm_timeout: u64,
    dry_run: bool,
) -> Result<Vec<CleanResult>> {
    let mut results = Vec::new();
    let mut sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::new().with_processes(sysinfo::ProcessRefreshKind::everything()),
    );

    for orphan in orphans {
        match clean_process_with_sys(
            &mut sys,
            orphan.pid,
            orphan.start_time,
            sigterm_timeout,
            dry_run,
        ) {
            Ok(mut result) => {
                result.name = orphan.name.clone();
                results.push(result);
            }
            Err(e) => {
                tracing::warn!("Skipping PID {}: {}", orphan.pid, e);
            }
        }
    }

    Ok(results)
}

/// Clean orphaned processes with optional PID and pattern filters.
///
/// - If `pids` is non-empty: only kill orphans whose PID is in the list.
/// - If `pattern` is provided: only kill orphans whose cmdline matches the regex.
/// - If both: intersection (PID must be in list AND cmdline must match).
/// - If neither: kill all detected orphans.
pub fn clean_filtered(pids: &[u32], pattern: Option<&str>) -> Result<CleanSummary> {
    let mut config = Config::load()?;
    let sigterm_timeout = config.sigterm_timeout;
    let targets_configured = !config.targets.is_empty();
    // CLI clean should execute immediately without grace period
    config.grace_period = 0;
    let mut scanner = crate::scanner::Scanner::new(config)?;
    let orphans = scanner.scan()?;

    if let Some(p) = pattern {
        if p.len() > 1024 {
            anyhow::bail!("Filter pattern too long (max 1024 characters)");
        }
    }
    let pattern_re = pattern
        .map(Regex::new)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid filter pattern: {e}"))?;

    let pid_set: HashSet<u32> = pids.iter().copied().collect();
    let filtered: Vec<&OrphanProcess> = orphans
        .iter()
        .filter(|o| {
            let pid_ok = pid_set.is_empty() || pid_set.contains(&o.pid);
            #[allow(clippy::unnecessary_map_or)]
            let pattern_ok = pattern_re
                .as_ref()
                .map_or(true, |re| re.is_match(&o.cmdline));
            pid_ok && pattern_ok
        })
        .collect();

    // Collect owned copies for clean_all (which expects &[OrphanProcess])
    let to_clean: Vec<OrphanProcess> = filtered.into_iter().cloned().collect();

    let results = if !to_clean.is_empty() {
        clean_all(&to_clean, sigterm_timeout, false)?
    } else {
        Vec::new()
    };

    // Warn when filters were specified but nothing matched
    let has_filters = !pids.is_empty() || pattern.is_some();
    if has_filters && to_clean.is_empty() && !orphans.is_empty() {
        eprintln!(
            "Warning: Found {} orphan(s) but none matched your filters.",
            orphans.len()
        );
    }

    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.len() - successful;

    Ok(CleanSummary {
        total: results.len(),
        successful,
        failed,
        results,
        targets_configured,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_process_dry_run() {
        let result = clean_process(12345, 0, 5, true).unwrap();
        assert!(result.success);
        assert_eq!(result.signal_used, Signal::SIGTERM);
    }

    #[test]
    fn test_clean_all_empty() {
        let result = clean_all(&[], 5, false).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_clean_all_dry_run() {
        let orphans = vec![crate::scanner::OrphanProcess {
            pid: 99999,
            name: "test".to_string(),
            cmdline: "test cmd".to_string(),
            first_seen: std::time::Instant::now(),
            start_time: 0,
        }];
        let results = clean_all(&orphans, 5, true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].success);
    }
}
