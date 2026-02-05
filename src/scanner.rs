use anyhow::Result;
use regex::Regex;
use serde::Serialize;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use std::collections::HashMap;
use std::time::Instant;

use crate::config::Config;

/// Represents an orphaned process detected by the scanner
#[derive(Debug, Clone, Serialize)]
pub struct OrphanProcess {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    #[serde(skip)]
    pub first_seen: Instant,
    pub start_time: u64,  // Process start time for identity verification
}

/// Result of a scan operation
#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub orphans: Vec<OrphanProcess>,
    pub total_scanned: usize,
    pub executed: bool,
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
        let target_patterns = config.targets
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid target regex pattern in configuration: {}", e))?;

        let whitelist_patterns = config.whitelist
            .iter()
            .map(|p| Regex::new(p))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Invalid whitelist regex pattern in configuration: {}", e))?;

        Ok(Self {
            config,
            tracked: HashMap::new(),
            target_patterns,
            whitelist_patterns,
        })
    }

    /// Scan the process table and return orphaned processes that exceed grace period
    pub fn scan(&mut self) -> Result<Vec<OrphanProcess>> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

        let now = Instant::now();
        let mut current_orphans = Vec::new();
        let mut current_pids = std::collections::HashSet::new();

        // Scan all processes
        for (pid, process) in sys.processes() {
            let pid_u32 = pid.as_u32();
            current_pids.insert(pid_u32);

            // Check if process is an orphan (PPID = 1)
            if !is_orphan(process) {
                continue;
            }

            // Get command line - convert OsString to String
            let cmdline = process.cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect::<Vec<String>>()
                .join(" ");
            if cmdline.is_empty() {
                continue;
            }

            // Check if it matches target patterns
            if !self.matches_target(&cmdline) {
                continue;
            }

            // Check if it's whitelisted
            if self.is_whitelisted(&cmdline) {
                continue;
            }

            // Track this orphan
            let orphan = self.tracked.entry(pid_u32).or_insert_with(|| OrphanProcess {
                pid: pid_u32,
                name: process.name().to_string_lossy().to_string(),
                cmdline: cmdline.clone(),
                first_seen: now,
                start_time: process.start_time(),  // Capture process start time for identity verification
            });

            // Check if grace period has elapsed
            let elapsed = now.duration_since(orphan.first_seen);
            if elapsed.as_secs() >= self.config.grace_period {
                current_orphans.push(orphan.clone());
            }
        }

        // Remove processes that are no longer orphans
        self.tracked.retain(|pid, _| current_pids.contains(pid));

        Ok(current_orphans)
    }

    /// Check if the command line matches any of the target patterns
    fn matches_target(&self, cmdline: &str) -> bool {
        self.target_patterns.iter().any(|re| re.is_match(cmdline))
    }

    /// Check if the command line is whitelisted
    fn is_whitelisted(&self, cmdline: &str) -> bool {
        self.whitelist_patterns.iter().any(|re| re.is_match(cmdline))
    }
}

/// Check if a process is an orphan (PPID = 1)
fn is_orphan(process: &sysinfo::Process) -> bool {
    process.parent().map(|p| p.as_u32()) == Some(1)
}

/// Public function for CLI scan command (creates a fresh Scanner each call)
pub fn scan(execute: bool) -> Result<ScanResult> {
    let config = Config::load()?;
    let sigterm_timeout = config.sigterm_timeout;
    let mut scanner = Scanner::new(config)?;
    scan_with_scanner(&mut scanner, execute, sigterm_timeout)
}

/// Scan using an existing Scanner instance, preserving tracked state across calls.
/// This is used by the daemon to maintain grace_period tracking between scan cycles.
pub fn scan_with_scanner(scanner: &mut Scanner, execute: bool, sigterm_timeout: u64) -> Result<ScanResult> {
    let orphans = scanner.scan()?;

    let total_scanned = orphans.len();

    if execute && !orphans.is_empty() {
        crate::cleaner::clean_all(&orphans, sigterm_timeout, false)?;
    }

    Ok(ScanResult {
        orphans,
        total_scanned,
        executed: execute,
    })
}
