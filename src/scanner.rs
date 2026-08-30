use anyhow::Result;
use nix::unistd::{getsid, Pid};
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use sysinfo::System;

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

/// Guard destructive operations against running inside a container.
///
/// In containers every process has PPID=1 (the container init), so orphan
/// detection is meaningless and would flag the container's own workload. `scan`
/// (detection only) is always allowed; `clean` and the daemon call this to
/// refuse to act unless the user explicitly opts in via
/// `PROC_JANITOR_ALLOW_CONTAINER=1`.
pub fn container_guard() -> Result<()> {
    if !detect_container_environment() {
        return Ok(());
    }
    let allowed = std::env::var("PROC_JANITOR_ALLOW_CONTAINER")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if allowed {
        tracing::warn!(
            "Container detected but PROC_JANITOR_ALLOW_CONTAINER is set; proceeding anyway."
        );
        return Ok(());
    }
    anyhow::bail!(
        "Container environment detected: every process has PPID=1, so proc-janitor cannot \
         distinguish real orphans from your container's workload and is refusing to act \
         (this prevents killing the container itself). Set PROC_JANITOR_ALLOW_CONTAINER=1 to override."
    )
}

/// Why a process looks orphaned, beyond the bare `PPID == 1` test.
///
/// `PPID == 1` is a weak signal on macOS: measured on macOS 25.6, 470 of the 654
/// processes owned by the logged-in user already have PPID 1, because launchd
/// both reparents orphans *and* directly launches most agents and services. The
/// filter therefore removes under 30% of candidates and safety rests entirely on
/// the target regex.
///
/// The session id discriminates. Of those same 470 processes: 283 sit in init's
/// session, 179 are their own session leader, and only 8 have a session leader
/// that no longer exists — which is exactly the signature of "a terminal exited
/// and left this process behind".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanEvidence {
    /// The session leader is gone: this process was started from a session (a
    /// terminal) that has since exited. The strongest signal available without
    /// privileges.
    DeadSession,
    /// The process is its own session leader — it called `setsid()`, or was
    /// launched that way. Ambiguous: covers both a `disown`ed job and a
    /// deliberately detached daemon.
    OwnSession,
    /// The process lives in init's session, the usual shape of a
    /// launchd/systemd-managed service.
    InitSession,
    /// Its session leader is still running, so its session has not gone away.
    LiveSession,
    /// `getsid()` failed, or the PID does not fit in a `pid_t`.
    Unknown,
}

impl OrphanEvidence {
    /// Short label for human-readable output.
    pub fn label(self) -> &'static str {
        match self {
            Self::DeadSession => "session leader gone",
            Self::OwnSession => "own session leader",
            Self::InitSession => "init session",
            Self::LiveSession => "session leader alive",
            Self::Unknown => "unknown session",
        }
    }
}

/// Classify a process from its session id, given the set of live PIDs.
///
/// Split out from [`orphan_evidence`] so the decision table is testable without
/// having to manufacture real processes in specific session states.
fn classify_session(pid: u32, sid: u32, live_pids: &HashSet<u32>) -> OrphanEvidence {
    if sid == pid {
        OrphanEvidence::OwnSession
    } else if sid == 1 {
        OrphanEvidence::InitSession
    } else if live_pids.contains(&sid) {
        OrphanEvidence::LiveSession
    } else {
        OrphanEvidence::DeadSession
    }
}

/// Classify why `pid` looks orphaned from its session id.
///
/// `getsid()` is one syscall and works across users on macOS (verified: 305
/// processes owned by root or another uid, zero `EPERM`), so this can be applied
/// to every candidate.
fn orphan_evidence(pid: u32, live_pids: &HashSet<u32>) -> OrphanEvidence {
    if pid > i32::MAX as u32 {
        return OrphanEvidence::Unknown;
    }
    let Ok(sid) = getsid(Some(Pid::from_raw(pid as i32))) else {
        return OrphanEvidence::Unknown;
    };
    let sid = sid.as_raw();
    if sid <= 0 {
        return OrphanEvidence::Unknown;
    }
    classify_session(pid, sid as u32, live_pids)
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
    /// Why this process is considered orphaned (see [`OrphanEvidence`]).
    pub evidence: OrphanEvidence,
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
    /// Long-lived process table. Refreshing an existing `System` costs about
    /// half of building a fresh one each cycle (measured 2.76 ms versus 6.40 ms
    /// on a 960-process machine) and avoids reallocating the whole table 17k
    /// times a day at the default 5s interval.
    sys: System,
    /// PIDs whose exit should wake the daemon early, refreshed by every `scan()`.
    ///
    /// Holds the *parent* of each target-matching process that is not an orphan
    /// yet — its exit is the exact moment the process becomes one — plus each
    /// tracked orphan itself, so one that exits on its own leaves the
    /// grace-period map immediately. See [`crate::watch`].
    watch_pids: Vec<u32>,
}

impl Scanner {
    /// Compile the target and whitelist regexes from a configuration.
    fn compile_patterns(config: &Config) -> Result<(Vec<Regex>, Vec<Regex>)> {
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

        Ok((target_patterns, whitelist_patterns))
    }

    /// Create a new Scanner with the given configuration
    pub fn new(config: Config) -> Result<Self> {
        let (target_patterns, whitelist_patterns) = Self::compile_patterns(&config)?;

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
            // Left unrefreshed: `scan()` refreshes before every use.
            sys: System::new_with_specifics(
                sysinfo::RefreshKind::new().with_processes(crate::util::process_refresh_kind()),
            ),
            watch_pids: Vec::new(),
        })
    }

    /// Apply a new configuration in place, preserving grace-period tracking.
    ///
    /// Replacing the whole `Scanner` on reload would drop `tracked` (and with it
    /// every `first_seen` timestamp), restarting each orphan's grace period. Any
    /// repeated config touch — editor autosave, `config edit`, a SIGHUP loop —
    /// would then postpone cleanup indefinitely and silently.
    ///
    /// Patterns are compiled before anything is mutated, so an invalid config
    /// leaves the scanner untouched.
    pub fn reconfigure(&mut self, config: Config) -> Result<()> {
        let (target_patterns, whitelist_patterns) = Self::compile_patterns(&config)?;
        self.config = config;
        self.target_patterns = target_patterns;
        self.whitelist_patterns = whitelist_patterns;
        Ok(())
    }

    /// Scan the process table and return orphaned processes that exceed grace period.
    /// Includes orphan roots (PPID=1) and their descendant processes that match targets.
    pub fn scan(&mut self) -> Result<Vec<OrphanProcess>> {
        let kind = crate::util::process_refresh_kind();
        self.sys
            .refresh_processes_specifics(sysinfo::ProcessesToUpdate::All, kind);

        let now = Instant::now();

        // Bind the pattern lists instead of calling methods on `self`: a `&self`
        // receiver would conflict with mutating `self.tracked` further down.
        let target_patterns = &self.target_patterns;
        let whitelist_patterns = &self.whitelist_patterns;
        let is_target = |cmdline: &str| matches_any(target_patterns, cmdline);
        let is_listed = |cmdline: &str| matches_any(whitelist_patterns, cmdline);

        // Phase 1: one pass over the table — children map, live PIDs, the orphan
        // roots (PPID=1 + matches a target + not whitelisted), and the PIDs whose
        // exit should wake the daemon early.
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut current_pids: HashSet<u32> = HashSet::new();
        let mut orphan_roots = Vec::new();
        let mut watch_pids: HashSet<u32> = HashSet::new();
        for (pid, process) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            current_pids.insert(pid_u32);
            let ppid = process.parent().map(|p| p.as_u32());
            if let Some(ppid) = ppid {
                children_map.entry(ppid).or_default().push(pid_u32);
            }

            if is_orphan(process) {
                let cmdline = get_cmdline(process);
                if !cmdline.is_empty() && is_target(&cmdline) && !is_listed(&cmdline) {
                    orphan_roots.push(pid_u32);
                    // Already an orphan: watch it so that its own exit clears the
                    // grace-period entry without waiting for the next tick.
                    watch_pids.insert(pid_u32);
                }
            } else if let Some(ppid) = ppid.filter(|p| *p > 1) {
                // Not an orphan yet. If it would be a target once orphaned, the
                // parent's exit is precisely the moment that happens, so watching
                // the parent turns "notice within scan_interval" into "notice in
                // about a millisecond".
                let cmdline = get_cmdline(process);
                if !cmdline.is_empty() && is_target(&cmdline) && !is_listed(&cmdline) {
                    watch_pids.insert(ppid);
                }
            }
        }

        // Phase 2: expand each root to its descendants. With
        // `require_dead_session`, a root must additionally show that the session
        // it belonged to is gone — see [`OrphanEvidence`] for why PPID=1 alone is
        // weak. Evidence is only computed for roots that already matched a
        // target pattern, so this costs one `getsid()` per candidate, not per
        // process.
        let mut orphan_tree_pids: HashSet<u32> = HashSet::new();
        for root in orphan_roots {
            if self.config.require_dead_session {
                let evidence = orphan_evidence(root, &current_pids);
                if evidence != OrphanEvidence::DeadSession {
                    tracing::debug!(
                        pid = root,
                        evidence = evidence.label(),
                        "skipping orphan candidate: require_dead_session is set"
                    );
                    continue;
                }
            }
            orphan_tree_pids.insert(root);
            crate::util::collect_descendants(root, &children_map, &mut orphan_tree_pids);
        }

        // Phase 3a: snapshot the cleanable processes. The orphan tree is small,
        // and collecting first releases the borrow on the process table so the
        // tracking map can be updated below.
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut cleanable: Vec<OrphanProcess> = Vec::new();
        for (pid, process) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            if !orphan_tree_pids.contains(&pid_u32) {
                continue;
            }
            let cmdline = get_cmdline(process);
            // Descendants must also match target patterns (don't kill unrelated children)
            if cmdline.is_empty() || !is_target(&cmdline) || is_listed(&cmdline) {
                continue;
            }
            cleanable.push(OrphanProcess {
                pid: pid_u32,
                name: process.name().to_string_lossy().to_string(),
                cmdline,
                first_seen: now,
                start_time: process.start_time(),
                memory_bytes: process.memory(),
                uptime_seconds: current_time.saturating_sub(process.start_time()),
                evidence: orphan_evidence(pid_u32, &current_pids),
            });
        }

        // Phase 3b: the grace period runs from the first sighting, so an existing
        // entry always wins over the fresh snapshot.
        let mut due = Vec::new();
        for candidate in cleanable {
            let tracked = self.tracked.entry(candidate.pid).or_insert(candidate);
            if now.duration_since(tracked.first_seen).as_secs() >= self.config.grace_period {
                due.push(tracked.clone());
            }
        }

        // Remove processes that are no longer running
        self.tracked.retain(|pid, _| current_pids.contains(pid));

        self.watch_pids = watch_pids.into_iter().collect();

        Ok(due)
    }

    /// PIDs whose exit should end the daemon's sleep early, as of the last
    /// [`Scanner::scan`]. Empty before the first scan.
    pub fn watch_pids(&self) -> &[u32] {
        &self.watch_pids
    }
}

/// True when `cmdline` matches any of `patterns`.
///
/// The single matching primitive for the whole crate: the scanner uses it for
/// both target and whitelist lists, and `visualize` uses it so the process tree
/// highlights exactly what a scan would select. Note that `cmdline` is the full
/// argv joined with spaces, so an unanchored pattern also matches text inside
/// argument paths.
pub fn matches_any(patterns: &[Regex], cmdline: &str) -> bool {
    patterns.iter().any(|re| re.is_match(cmdline))
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

    fn compile(patterns: &[&str]) -> Vec<Regex> {
        patterns.iter().map(|p| Regex::new(p).unwrap()).collect()
    }

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
            require_dead_session: false,
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
            require_dead_session: false,
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
    fn test_matches_any_targets() {
        let patterns = compile(&["node.*claude", "python"]);
        assert!(matches_any(
            &patterns,
            "node --experimental-vm-modules claude"
        ));
        assert!(matches_any(&patterns, "python script.py"));
        assert!(!matches_any(&patterns, "cargo build"));
    }

    #[test]
    fn test_matches_any_whitelist() {
        let patterns = compile(&["node.*server"]);
        assert!(matches_any(&patterns, "node express-server"));
        assert!(!matches_any(&patterns, "node claude-mcp"));
    }

    #[test]
    fn test_matches_any_empty_never_matches() {
        assert!(!matches_any(&[], "anything at all"));
    }

    #[test]
    fn test_classify_session_decision_table() {
        let live: HashSet<u32> = HashSet::from([1, 100, 200]);

        // Called setsid (or is a session leader): ambiguous, not evidence.
        assert_eq!(
            classify_session(200, 200, &live),
            OrphanEvidence::OwnSession
        );
        // Sits in init's session: the shape of a launchd/systemd service.
        assert_eq!(classify_session(300, 1, &live), OrphanEvidence::InitSession);
        // Session leader still running: its session has not gone away.
        assert_eq!(
            classify_session(300, 100, &live),
            OrphanEvidence::LiveSession
        );
        // Session leader is gone: the terminal that started it has exited.
        assert_eq!(
            classify_session(300, 999, &live),
            OrphanEvidence::DeadSession
        );
    }

    #[test]
    fn test_orphan_evidence_of_a_live_process() {
        // Classified against the real process table: this test process was
        // started by a harness that is still running, so its session cannot look
        // dead. Guards against an inverted liveness check.
        let sys = crate::util::process_snapshot();
        let live: HashSet<u32> = sys.processes().keys().map(|p| p.as_u32()).collect();
        let me = std::process::id();
        assert_ne!(
            orphan_evidence(me, &live),
            OrphanEvidence::DeadSession,
            "a live test process must not look like a dead-session orphan"
        );

        // A PID that cannot be a pid_t is unclassifiable, never an orphan.
        assert_eq!(
            orphan_evidence(u32::MAX, &live),
            OrphanEvidence::Unknown,
            "out-of-range PIDs must not be classified as orphans"
        );
    }
}
