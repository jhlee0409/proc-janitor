use anyhow::Result;
use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Instant;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

use crate::config::Config;

/// Detect if we're running inside a container.
/// In containers, all processes have PPID=1 which would cause false positives.
fn detect_container_environment() -> bool {
    // Check for Docker
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }
    // Check for common container cgroup indicators
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") || cgroup.contains("kubepods") || cgroup.contains("containerd")
        {
            return true;
        }
    }
    // Check for container environment variables
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        return true;
    }
    false
}

/// Represents an orphaned process detected by the scanner
#[derive(Debug, Clone, Serialize)]
pub struct OrphanProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    #[serde(skip)]
    pub first_seen: Instant,
    pub start_time: u64,     // Process start time for identity verification
    pub memory_bytes: u64,   // RSS memory usage in bytes
    pub uptime_seconds: u64, // How long the process has been running
}

/// Result of a scan operation (detection only, no killing)
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub orphans: Vec<OrphanProcess>,
    pub orphan_count: usize,
    pub targets_configured: bool,
}

/// Scanner tracks and identifies orphaned processes
pub struct Scanner {
    config: Config,
    tracked: HashMap<u32, OrphanProcess>,
    target_patterns: Vec<Regex>,
    whitelist_patterns: Vec<Regex>,
}

impl Scanner {
    /// Create a new Scanner with the given configuration
    pub fn new(config: Config) -> Result<Self> {
        // Pre-compile regex patterns
        let target_patterns = config
            .targets
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid target regex pattern in configuration: {e}"))?;

        let whitelist_patterns = config
            .whitelist
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                anyhow::anyhow!("Invalid whitelist regex pattern in configuration: {e}")
            })?;

        if target_patterns.is_empty() {
            tracing::warn!(
                "No target patterns configured. Scanner will not detect any orphaned processes. \
                            Run 'proc-janitor config init' to set up target patterns."
            );
        }

        if detect_container_environment() {
            tracing::warn!(
                "Container environment detected. All processes may appear as orphans (PPID=1). \
                 proc-janitor may not work correctly inside containers."
            );
        }

        Ok(Self {
            config,
            tracked: HashMap::new(),
            target_patterns,
            whitelist_patterns,
        })
    }

    /// Scan the process table and return orphaned processes that exceed grace period.
    /// Includes orphan roots (PPID=1) and their descendant processes that match targets.
    pub fn scan(&mut self) -> Result<Vec<OrphanProcess>> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

        let now = Instant::now();
        let mut current_orphans = Vec::new();
        let mut current_pids = std::collections::HashSet::new();

        // Phase 1: Single pass — build children map, collect current PIDs,
        // and identify orphan roots (PPID=1 + matches target + not whitelisted)
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut orphan_roots = Vec::new();
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            current_pids.insert(pid_u32);
            if let Some(ppid) = process.parent() {
                children_map.entry(ppid.as_u32()).or_default().push(pid_u32);
            }
            if is_orphan(process) {
                let cmdline = get_cmdline(process);
                if !cmdline.is_empty()
                    && self.matches_target(&cmdline)
                    && !self.is_whitelisted(&cmdline)
                {
                    orphan_roots.push(pid_u32);
                }
            }
        }

        // Expand orphan roots to include all their descendants
        let mut orphan_tree_pids = std::collections::HashSet::new();
        for root in orphan_roots {
            orphan_tree_pids.insert(root);
            crate::util::collect_descendants(root, &children_map, &mut orphan_tree_pids);
        }

        // Phase 3: Collect all cleanable processes from orphan trees
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();

            if !orphan_tree_pids.contains(&pid_u32) {
                continue;
            }

            let cmdline = get_cmdline(process);
            if cmdline.is_empty() {
                continue;
            }

            // Descendants must also match target patterns (don't kill unrelated children)
            if !self.matches_target(&cmdline) {
                continue;
            }
            if self.is_whitelisted(&cmdline) {
                continue;
            }

            // Track this process
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let orphan = self
                .tracked
                .entry(pid_u32)
                .or_insert_with(|| OrphanProcess {
                    pid: pid_u32,
                    name: process.name().to_string_lossy().to_string(),
                    cmdline: cmdline.clone(),
                    first_seen: now,
                    start_time: process.start_time(),
                    memory_bytes: process.memory(),
                    uptime_seconds: current_time.saturating_sub(process.start_time()),
                });

            // Check if grace period has elapsed
            let elapsed = now.duration_since(orphan.first_seen);
            if elapsed.as_secs() >= self.config.grace_period {
                current_orphans.push(orphan.clone());
            }
        }

        // Remove processes that are no longer running
        self.tracked.retain(|pid, _| current_pids.contains(pid));

        Ok(current_orphans)
    }

    /// Check if the command line matches any of the target patterns
    fn matches_target(&self, cmdline: &str) -> bool {
        self.target_patterns.iter().any(|re| re.is_match(cmdline))
    }

    /// Check if the command line is whitelisted
    fn is_whitelisted(&self, cmdline: &str) -> bool {
        self.whitelist_patterns
            .iter()
            .any(|re| re.is_match(cmdline))
    }
}

/// Extract command line from a process as a single string
fn get_cmdline(process: &sysinfo::Process) -> String {
    process
        .cmd()
        .iter()
        .map(|s| s.to_string_lossy().to_string())
        .collect::<Vec<String>>()
        .join(" ")
}

/// Check if a process is orphaned (PPID=1, reparented to init/launchd).
///
/// Note: In containers (Docker, etc.), all processes have PPID=1 since PID 1
/// is the container's init process. Running proc-janitor inside a container
/// would incorrectly flag all processes as orphans.
fn is_orphan(process: &sysinfo::Process) -> bool {
    process.parent().map(|p| p.as_u32()) == Some(1)
}

/// Public function for CLI scan command (creates a fresh Scanner each call).
/// Detection only — does not kill any processes.
pub fn scan() -> Result<ScanResult> {
    let mut config = Config::load()?;
    // CLI scan should show results immediately without grace period.
    // Grace period is only meaningful for the daemon which persists Scanner state.
    config.grace_period = 0;
    let mut scanner = Scanner::new(config)?;
    scan_with_scanner(&mut scanner)
}

/// Scan using an existing Scanner instance, preserving tracked state across calls.
/// This is used by the daemon to maintain grace_period tracking between scan cycles.
/// Detection only — does not kill any processes.
pub fn scan_with_scanner(scanner: &mut Scanner) -> Result<ScanResult> {
    let targets_configured = !scanner.target_patterns.is_empty();
    let orphans = scanner.scan()?;
    let orphan_count = orphans.len();

    Ok(ScanResult {
        orphans,
        orphan_count,
        targets_configured,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_detection_on_host() {
        // On a normal macOS/Linux host, this should return false
        // (unless you're actually running tests in a container)
        let result = detect_container_environment();
        // We can't assert false because CI might run in containers
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_is_orphan_check() {
        // Just verify the function exists and can be compiled
        // Actual orphan detection requires a real Process object
        // which we can't easily mock
    }

    #[test]
    fn test_scanner_new_with_empty_targets() {
        let config = Config {
            scan_interval: 5,
            grace_period: 30,
            sigterm_timeout: 5,
            targets: vec![],
            whitelist: vec![],
            logging: crate::config::LoggingConfig {
                enabled: false,
                path: "/tmp/test".to_string(),
                retention_days: 7,
            },
        };
        let scanner = Scanner::new(config);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scanner_new_with_invalid_regex() {
        let config = Config {
            scan_interval: 5,
            grace_period: 30,
            sigterm_timeout: 5,
            targets: vec!["[invalid".to_string()],
            whitelist: vec![],
            logging: crate::config::LoggingConfig {
                enabled: false,
                path: "/tmp/test".to_string(),
                retention_days: 7,
            },
        };
        let scanner = Scanner::new(config);
        assert!(scanner.is_err());
    }

    #[test]
    fn test_scanner_matches_target() {
        let config = Config {
            scan_interval: 5,
            grace_period: 30,
            sigterm_timeout: 5,
            targets: vec!["node.*claude".to_string(), "python".to_string()],
            whitelist: vec!["node.*server".to_string()],
            logging: crate::config::LoggingConfig {
                enabled: false,
                path: "/tmp/test".to_string(),
                retention_days: 7,
            },
        };
        let scanner = Scanner::new(config).unwrap();
        assert!(scanner.matches_target("node --experimental-vm-modules claude"));
        assert!(scanner.matches_target("python script.py"));
        assert!(!scanner.matches_target("cargo build"));
    }

    #[test]
    fn test_scanner_whitelist() {
        let config = Config {
            scan_interval: 5,
            grace_period: 30,
            sigterm_timeout: 5,
            targets: vec!["node".to_string()],
            whitelist: vec!["node.*server".to_string()],
            logging: crate::config::LoggingConfig {
                enabled: false,
                path: "/tmp/test".to_string(),
                retention_days: 7,
            },
        };
        let scanner = Scanner::new(config).unwrap();
        assert!(scanner.is_whitelisted("node express-server"));
        assert!(!scanner.is_whitelisted("node claude-mcp"));
    }
}
