//! Session-based process tracking
//!
//! Enables tracking processes by session ID (terminal tab, Claude Code instance, etc.)
//! Sessions can be registered and their processes cleaned up when the session ends.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

/// Maximum number of sessions to prevent unbounded growth
const MAX_SESSIONS: usize = 1000;

/// A tracked process with its PID and start time (for PID reuse detection)
#[derive(Debug, Clone, Serialize)]
pub struct TrackedPid {
    pub pid: u32,
    pub start_time: Option<u64>,
}

/// Custom deserializer for backward compatibility: accepts both a bare u32 and a {pid, start_time} object.
impl<'de> Deserialize<'de> for TrackedPid {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum TrackedPidRepr {
            Bare(u32),
            Full { pid: u32, start_time: Option<u64> },
        }

        match TrackedPidRepr::deserialize(deserializer)? {
            TrackedPidRepr::Bare(pid) => Ok(TrackedPid {
                pid,
                start_time: None,
            }),
            TrackedPidRepr::Full { pid, start_time } => Ok(TrackedPid { pid, start_time }),
        }
    }
}

/// Represents a tracked session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: Option<String>,
    pub source: SessionSource,
    pub pids: Vec<TrackedPid>,
    pub created_at: DateTime<Utc>,
    pub tty: Option<String>,
    pub parent_pid: Option<u32>,
}

/// Source of the session for extensibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SessionSource {
    ClaudeCode,
    Terminal,
    VsCode,
    Tmux,
    Custom(String),
}

impl std::fmt::Display for SessionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionSource::ClaudeCode => write!(f, "claude-code"),
            SessionSource::Terminal => write!(f, "terminal"),
            SessionSource::VsCode => write!(f, "vscode"),
            SessionSource::Tmux => write!(f, "tmux"),
            SessionSource::Custom(name) => write!(f, "{name}"),
        }
    }
}

impl std::str::FromStr for SessionSource {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(anyhow::anyhow!("Session source cannot be empty"));
        }
        if s.len() > 50 {
            return Err(anyhow::anyhow!("Session source too long (max 50 chars)"));
        }
        if !s
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow::anyhow!(
                "Session source must be alphanumeric with - or _"
            ));
        }

        Ok(match s.to_lowercase().as_str() {
            "claude-code" | "claude" => SessionSource::ClaudeCode,
            "terminal" | "term" => SessionSource::Terminal,
            "vscode" | "vs-code" => SessionSource::VsCode,
            "tmux" => SessionSource::Tmux,
            _ => SessionSource::Custom(s.to_string()),
        })
    }
}

/// Session store - persists session data to disk
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SessionStore {
    pub sessions: HashMap<String, Session>,
}

impl SessionStore {
    /// Load session store from disk with a shared lock (read-only).
    /// Use `load_exclusive()` for read-modify-write operations.
    pub fn load() -> Result<Self> {
        let path = sessions_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        // Open with shared lock for reading
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .with_context(|| format!("Failed to open sessions file: {}", path.display()))?;

        fs2::FileExt::lock_shared(&file)
            .with_context(|| "Failed to acquire shared lock on sessions file")?;

        // Read directly from the locked file handle to avoid TOCTOU race
        let mut content = String::new();
        file.read_to_string(&mut content)
            .with_context(|| format!("Failed to read sessions file: {}", path.display()))?;

        fs2::FileExt::unlock(&file).with_context(|| "Failed to release lock on sessions file")?;

        // Parse JSON with corruption recovery
        match serde_json::from_str::<SessionStore>(&content) {
            Ok(store) => Ok(store),
            Err(_) => {
                eprintln!(
                    "Warning: Sessions file is corrupted, backing up and creating fresh store."
                );

                // Create backup path
                let backup_path = path.with_extension("json.corrupt");
                eprintln!("  Backup saved to: {}", backup_path.display());

                // Backup the corrupt file
                crate::util::check_not_symlink(&backup_path)?;
                fs::copy(&path, &backup_path).with_context(|| {
                    format!(
                        "Failed to backup corrupt sessions file to: {}",
                        backup_path.display()
                    )
                })?;

                // Return fresh store so session subsystem continues working
                Ok(Self::default())
            }
        }
    }

    /// Load session store with exclusive lock for read-modify-write operations.
    /// Returns the store and the locked file handle. Caller must pass file to `save_with_lock()`.
    fn load_exclusive() -> Result<(SessionStore, std::fs::File)> {
        ensure_data_dir()?;
        let path = sessions_path()?;
        crate::util::check_not_symlink(&path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        fs2::FileExt::lock_exclusive(&file)?;

        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let store = if content.is_empty() {
            SessionStore {
                sessions: HashMap::new(),
            }
        } else {
            serde_json::from_str(&content).unwrap_or_else(|_| {
                // Corruption recovery - same as load()
                let bak_path = path.with_extension("json.bak");
                crate::util::check_not_symlink(&bak_path).ok();
                let _ = std::fs::copy(&path, &bak_path);
                SessionStore {
                    sessions: HashMap::new(),
                }
            })
        };

        Ok((store, file))
    }

    /// Save session store to an already-locked file handle.
    fn save_with_lock(&self, file: &std::fs::File) -> Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        let content = serde_json::to_string_pretty(self)?;
        file.set_len(0)?;
        (&*file).seek(SeekFrom::Start(0))?;
        (&*file).write_all(content.as_bytes())?;
        file.sync_all()?;
        // Lock released when file is dropped
        Ok(())
    }

    /// Get a session by ID
    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// List all sessions
    pub fn list(&self) -> Vec<&Session> {
        self.sessions.values().collect()
    }
}

/// Get path to sessions file
fn sessions_path() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?
        .join(".proc-janitor")
        .join("sessions.json"))
}

/// Ensure data directory exists
fn ensure_data_dir() -> Result<()> {
    let path = sessions_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

// ============================================================================
// CLI Functions
// ============================================================================

/// Register a new session
pub fn register(
    id: Option<String>,
    name: Option<String>,
    source: String,
    parent_pid: Option<u32>,
) -> Result<String> {
    // Validate custom session ID if provided before consuming the Option
    if let Some(ref custom_id) = id {
        if custom_id.is_empty() {
            anyhow::bail!("Session ID cannot be empty");
        }
        if custom_id.len() > 100 {
            anyhow::bail!("Session ID too long (max 100 characters)");
        }
        if !custom_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            anyhow::bail!("Session ID must be alphanumeric with hyphens or underscores only");
        }
    }

    let session_id = id.unwrap_or_else(uuid_v4);
    let tty = get_current_tty();

    let session = Session {
        id: session_id.clone(),
        name,
        source: source.parse()?,
        pids: Vec::new(),
        created_at: Utc::now(),
        tty,
        parent_pid: parent_pid.or_else(|| Some(std::process::id())),
    };

    let (mut store, file) = SessionStore::load_exclusive()?;

    // Enforce session limit to prevent unbounded growth
    if store.sessions.len() >= MAX_SESSIONS {
        bail!(
            "Session limit reached ({MAX_SESSIONS}). Remove old sessions with 'session unregister' or 'session auto-clean'."
        );
    }

    store.sessions.insert(session.id.clone(), session);
    store.save_with_lock(&file)?;

    println!("Session registered: {session_id}");
    Ok(session_id)
}

/// Track a PID under a session
pub fn track(session_id: &str, pid: u32) -> Result<()> {
    let (mut store, file) = SessionStore::load_exclusive()?;

    // Capture start_time from process table for PID reuse detection
    let start_time = {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(
            pid,
        )]));
        sys.process(sysinfo::Pid::from_u32(pid))
            .map(|p| p.start_time())
    };

    if let Some(session) = store.sessions.get_mut(session_id) {
        if !session.pids.iter().any(|tp| tp.pid == pid) {
            session.pids.push(TrackedPid { pid, start_time });
        }
        store.save_with_lock(&file)?;
        println!("PID {pid} tracked under session {session_id}");
        Ok(())
    } else {
        bail!("Session not found: {session_id}")
    }
}

/// Clean up a specific session's processes
pub fn clean_session(session_id: &str, dry_run: bool) -> Result<()> {
    let (mut store, file) = SessionStore::load_exclusive()?;

    let session = store
        .get(session_id)
        .with_context(|| format!("Session not found: {session_id}"))?
        .clone();

    println!(
        "Cleaning session: {} ({}) - {} tracked PIDs",
        session_id,
        session.source,
        session.pids.len()
    );

    // Load config for sigterm_timeout
    let sigterm_timeout = crate::config::Config::load()
        .map(|c| c.sigterm_timeout)
        .unwrap_or(5);

    // Get current process list
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    // Find all descendant processes
    let root_pids: Vec<u32> = session.pids.iter().map(|tp| tp.pid).collect();
    let pids_to_clean = find_descendant_pids(&sys, &root_pids);

    // Build a map from pid -> start_time from tracked pids for kill verification
    let start_time_map: HashMap<u32, Option<u64>> = session
        .pids
        .iter()
        .map(|tp| (tp.pid, tp.start_time))
        .collect();

    if pids_to_clean.is_empty() {
        println!("No processes to clean.");
    } else {
        println!("Found {} process(es) to clean:", pids_to_clean.len());
        for pid in &pids_to_clean {
            if let Some(process) = sys.process(sysinfo::Pid::from_u32(*pid)) {
                let name = process.name().to_string_lossy();
                println!("  PID {pid} - {name}");
            }
        }

        if !dry_run {
            let mut killed = 0;
            let mut failed = 0;
            for pid in &pids_to_clean {
                let st = start_time_map.get(pid).copied().flatten();
                match crate::kill::kill_process_with_sys(&mut sys, *pid, st, sigterm_timeout) {
                    Ok(_) => killed += 1,
                    Err(e) => {
                        failed += 1;
                        tracing::warn!("Failed to kill PID {}: {}", pid, e);
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            println!("  Killed: {killed}, Failed: {failed}");
        } else {
            println!("\n(dry-run mode - no processes were killed)");
        }
    }

    // Remove session from store
    if !dry_run {
        store.sessions.remove(session_id);
        store.save_with_lock(&file)?;
        println!("Session {session_id} removed.");
    }

    Ok(())
}

/// List all active sessions
pub fn list() -> Result<()> {
    let store = SessionStore::load()?;
    let sessions = store.list();

    if sessions.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    println!("Active sessions ({}):", sessions.len());
    println!("{:-<70}", "");
    for session in sessions {
        println!("  {} [{}]", session.id, session.source);
        if let Some(name) = &session.name {
            println!("    Name: {name}");
        }
        println!(
            "    Created: {}",
            session.created_at.format("%Y-%m-%d %H:%M:%S")
        );
        let pid_list: Vec<u32> = session.pids.iter().map(|tp| tp.pid).collect();
        println!("    Tracked PIDs: {pid_list:?}");
        if let Some(tty) = &session.tty {
            println!("    TTY: {tty}");
        }
        println!();
    }

    Ok(())
}

/// Unregister a session without cleaning processes
pub fn unregister(session_id: &str) -> Result<()> {
    let (mut store, file) = SessionStore::load_exclusive()?;
    if store.sessions.remove(session_id).is_some() {
        store.save_with_lock(&file)?;
        println!("Session {session_id} unregistered.");
    } else {
        println!("Session {session_id} not found.");
    }
    Ok(())
}

/// Auto-detect and clean orphaned sessions
pub fn auto_clean(dry_run: bool) -> Result<()> {
    let (mut store, file) = SessionStore::load_exclusive()?;

    // Load config for sigterm_timeout
    let sigterm_timeout = crate::config::Config::load()
        .map(|c| c.sigterm_timeout)
        .unwrap_or(5);

    // Find stale sessions first
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let stale_ids: Vec<String> = store
        .sessions
        .iter()
        .filter(|(_, session)| {
            if let Some(parent_pid) = session.parent_pid {
                !sys.processes()
                    .contains_key(&sysinfo::Pid::from_u32(parent_pid))
            } else {
                false
            }
        })
        .map(|(id, _)| id.clone())
        .collect();

    if stale_ids.is_empty() {
        println!("No stale sessions found.");
        return Ok(());
    }

    println!("Found {} stale session(s):", stale_ids.len());

    for id in &stale_ids {
        if let Some(session) = store.sessions.get(id) {
            println!(
                "  {} ({}) - {} tracked PIDs",
                id,
                session.source,
                session.pids.len()
            );

            if !dry_run {
                // Build start_time map from tracked pids
                let start_time_map: HashMap<u32, Option<u64>> = session
                    .pids
                    .iter()
                    .map(|tp| (tp.pid, tp.start_time))
                    .collect();

                // Kill descendant processes
                let root_pids: Vec<u32> = session.pids.iter().map(|tp| tp.pid).collect();
                let pids_to_clean = find_descendant_pids(&sys, &root_pids);
                let mut killed = 0;
                let mut failed = 0;
                for pid in &pids_to_clean {
                    let st = start_time_map.get(pid).copied().flatten();
                    match crate::kill::kill_process_with_sys(&mut sys, *pid, st, sigterm_timeout) {
                        Ok(_) => killed += 1,
                        Err(e) => {
                            failed += 1;
                            tracing::warn!("Failed to kill PID {}: {}", pid, e);
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                println!("  Killed: {killed}, Failed: {failed}");
            }
        }
    }

    // Remove all stale sessions at once and save once
    if !dry_run {
        for id in &stale_ids {
            store.sessions.remove(id);
        }
        store.save_with_lock(&file)?;
        println!("Removed {} stale session(s).", stale_ids.len());
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a cryptographically secure UUID v4
fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Get current TTY from environment variables.
///
/// TTY detection via env vars is unreliable. Falls back to None if TTY/SSH_TTY not set.
fn get_current_tty() -> Option<String> {
    std::env::var("TTY")
        .or_else(|_| std::env::var("SSH_TTY"))
        .ok()
}

/// Find all descendant PIDs from a list of parent PIDs
fn find_descendant_pids(sys: &System, parent_pids: &[u32]) -> Vec<u32> {
    // Build parent->children map once for O(n) traversal
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, process) in sys.processes() {
        if let Some(parent) = process.parent() {
            children_map
                .entry(parent.as_u32())
                .or_default()
                .push(pid.as_u32());
        }
    }

    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut to_check: Vec<u32> = parent_pids.to_vec();

    while let Some(pid) = to_check.pop() {
        if !visited.insert(pid) {
            continue; // Already visited
        }

        // Check if process still exists
        if sys.process(sysinfo::Pid::from_u32(pid)).is_some() {
            result.push(pid);
        }

        // Add children to check
        if let Some(children) = children_map.get(&pid) {
            for &child_pid in children {
                if !visited.contains(&child_pid) {
                    to_check.push(child_pid);
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_source_parsing() {
        assert_eq!(
            "claude-code".parse::<SessionSource>().unwrap(),
            SessionSource::ClaudeCode
        );
        assert_eq!(
            "terminal".parse::<SessionSource>().unwrap(),
            SessionSource::Terminal
        );
    }

    #[test]
    fn test_uuid_generation() {
        let uuid1 = uuid_v4();
        let uuid2 = uuid_v4();
        // UUIDs should be different (with very high probability)
        assert_ne!(uuid1, uuid2);
    }

    #[test]
    fn test_tracked_pid_deserialize_bare() {
        let json = "42";
        let tp: TrackedPid = serde_json::from_str(json).unwrap();
        assert_eq!(tp.pid, 42);
        assert_eq!(tp.start_time, None);
    }

    #[test]
    fn test_tracked_pid_deserialize_full() {
        let json = r#"{"pid": 42, "start_time": 1234567890}"#;
        let tp: TrackedPid = serde_json::from_str(json).unwrap();
        assert_eq!(tp.pid, 42);
        assert_eq!(tp.start_time, Some(1234567890));
    }

    #[test]
    fn test_tracked_pid_deserialize_full_no_start_time() {
        let json = r#"{"pid": 42, "start_time": null}"#;
        let tp: TrackedPid = serde_json::from_str(json).unwrap();
        assert_eq!(tp.pid, 42);
        assert_eq!(tp.start_time, None);
    }

    #[test]
    fn test_session_backward_compat() {
        // Simulate old format with bare u32 pids
        let json = r#"{
            "sessions": {
                "test-session": {
                    "id": "test-session",
                    "name": null,
                    "source": "terminal",
                    "pids": [100, 200, 300],
                    "created_at": "2024-01-01T00:00:00Z",
                    "tty": null,
                    "parent_pid": null
                }
            }
        }"#;
        let store: SessionStore = serde_json::from_str(json).unwrap();
        let session = store.sessions.get("test-session").unwrap();
        assert_eq!(session.pids.len(), 3);
        assert_eq!(session.pids[0].pid, 100);
        assert_eq!(session.pids[0].start_time, None);
        assert_eq!(session.pids[2].pid, 300);
    }
}
