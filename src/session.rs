//! Session-based process tracking
//!
//! Enables tracking processes by session ID (terminal tab, Claude Code instance, etc.)
//! Sessions can be registered and their processes cleaned up when the session ends.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

/// Represents a tracked session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub name: Option<String>,
    pub source: SessionSource,
    pub pids: Vec<u32>,
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
            SessionSource::Custom(name) => write!(f, "{}", name),
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
        if !s.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow::anyhow!("Session source must be alphanumeric with - or _"));
        }

        Ok(match s.to_lowercase().as_str() {
            "claude-code" | "claude" => SessionSource::ClaudeCode,
            "terminal" | "term" => SessionSource::Terminal,
            "vscode" | "vs-code" => SessionSource::VsCode,
            "tmux" => SessionSource::Tmux,
            other => SessionSource::Custom(other.to_string()),
        })
    }
}

/// Session store - persists session data to disk
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SessionStore {
    pub sessions: HashMap<String, Session>,
}

impl SessionStore {
    /// Load session store from disk
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

        file.lock_shared()
            .with_context(|| "Failed to acquire shared lock on sessions file")?;

        // Read directly from the locked file handle to avoid TOCTOU race
        let mut content = String::new();
        file.read_to_string(&mut content)
            .with_context(|| format!("Failed to read sessions file: {}", path.display()))?;

        file.unlock()
            .with_context(|| "Failed to release lock on sessions file")?;

        let store: SessionStore = serde_json::from_str(&content)
            .with_context(|| "Failed to parse sessions file")?;

        Ok(store)
    }

    /// Save session store to disk
    pub fn save(&self) -> Result<()> {
        ensure_data_dir()?;
        let path = sessions_path()?;
        let temp_path = path.with_extension("json.tmp");

        // Write to temp file first
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&temp_path, &content)?;

        // Open original file for exclusive lock (create if doesn't exist)
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("Failed to open sessions file for locking: {}", path.display()))?;

        file.lock_exclusive()
            .with_context(|| "Failed to acquire exclusive lock on sessions file")?;

        // Atomic rename
        fs::rename(&temp_path, &path)
            .with_context(|| "Failed to atomically update sessions file")?;

        file.unlock()
            .with_context(|| "Failed to release lock on sessions file")?;

        Ok(())
    }

    /// Register a new session
    pub fn register(&mut self, session: Session) -> Result<()> {
        self.sessions.insert(session.id.clone(), session);
        self.save()
    }

    /// Get a session by ID
    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Remove a session
    pub fn remove(&mut self, id: &str) -> Result<Option<Session>> {
        let session = self.sessions.remove(id);
        self.save()?;
        Ok(session)
    }

    /// Add a PID to a session
    pub fn add_pid(&mut self, session_id: &str, pid: u32) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if !session.pids.contains(&pid) {
                session.pids.push(pid);
            }
            self.save()?;
        }
        Ok(())
    }

    /// Clean up stale sessions (parent process no longer exists)
    #[allow(dead_code)] // May be used for future session management features
    pub fn cleanup_stale(&mut self) -> Result<Vec<String>> {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                if let Some(parent_pid) = session.parent_pid {
                    // Check if parent process still exists
                    !sys.processes().contains_key(&sysinfo::Pid::from_u32(parent_pid))
                } else {
                    false
                }
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in &stale {
            self.sessions.remove(id);
        }

        if !stale.is_empty() {
            self.save()?;
        }

        Ok(stale)
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
        if !custom_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
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

    let mut store = SessionStore::load()?;
    store.register(session)?;

    println!("Session registered: {}", session_id);
    Ok(session_id)
}

/// Track a PID under a session
pub fn track(session_id: &str, pid: u32) -> Result<()> {
    let mut store = SessionStore::load()?;
    store.add_pid(session_id, pid)?;
    println!("PID {} tracked under session {}", pid, session_id);
    Ok(())
}

/// Clean up a specific session's processes
pub fn clean_session(session_id: &str, dry_run: bool) -> Result<()> {
    let mut store = SessionStore::load()?;

    let session = store
        .get(session_id)
        .with_context(|| format!("Session not found: {}", session_id))?
        .clone();

    println!(
        "Cleaning session: {} ({}) - {} tracked PIDs",
        session_id,
        session.source,
        session.pids.len()
    );

    // Get current process list
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    // Find all descendant processes
    let pids_to_clean = find_descendant_pids(&sys, &session.pids);

    if pids_to_clean.is_empty() {
        println!("No processes to clean.");
    } else {
        println!("Found {} process(es) to clean:", pids_to_clean.len());
        for pid in &pids_to_clean {
            if let Some(process) = sys.process(sysinfo::Pid::from_u32(*pid)) {
                let name = process.name().to_string_lossy();
                println!("  PID {} - {}", pid, name);
            }
        }

        if !dry_run {
            for pid in &pids_to_clean {
                let _ = kill_process(*pid);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            println!("Processes terminated.");
        } else {
            println!("\n(dry-run mode - no processes were killed)");
        }
    }

    // Remove session from store
    if !dry_run {
        store.remove(session_id)?;
        println!("Session {} removed.", session_id);
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
        println!(
            "  {} [{}]",
            session.id,
            session.source
        );
        if let Some(name) = &session.name {
            println!("    Name: {}", name);
        }
        println!("    Created: {}", session.created_at.format("%Y-%m-%d %H:%M:%S"));
        println!("    Tracked PIDs: {:?}", session.pids);
        if let Some(tty) = &session.tty {
            println!("    TTY: {}", tty);
        }
        println!();
    }

    Ok(())
}

/// Unregister a session without cleaning processes
pub fn unregister(session_id: &str) -> Result<()> {
    let mut store = SessionStore::load()?;
    if store.remove(session_id)?.is_some() {
        println!("Session {} unregistered.", session_id);
    } else {
        println!("Session {} not found.", session_id);
    }
    Ok(())
}

/// Auto-detect and clean orphaned sessions
pub fn auto_clean(dry_run: bool) -> Result<()> {
    let store = SessionStore::load()?;

    // Find stale sessions first (without deleting from store yet)
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let stale_ids: Vec<String> = store
        .sessions
        .iter()
        .filter(|(_, session)| {
            if let Some(parent_pid) = session.parent_pid {
                !sys.processes().contains_key(&sysinfo::Pid::from_u32(parent_pid))
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

    // Clean processes for each stale session
    for id in &stale_ids {
        println!("  {}", id);
        if !dry_run {
            if let Err(e) = clean_session(id, false) {
                tracing::warn!("Failed to clean session {}: {}", id, e);
            }
        }
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

/// Get current TTY
fn get_current_tty() -> Option<String> {
    std::env::var("TTY")
        .or_else(|_| std::env::var("SSH_TTY"))
        .ok()
}

/// Find all descendant PIDs from a list of parent PIDs
fn find_descendant_pids(sys: &System, parent_pids: &[u32]) -> Vec<u32> {
    let mut result = Vec::new();
    let mut to_check: Vec<u32> = parent_pids.to_vec();

    while let Some(pid) = to_check.pop() {
        // Check if process still exists
        if sys.process(sysinfo::Pid::from_u32(pid)).is_some() {
            result.push(pid);
        }

        // Find children
        for (child_pid, process) in sys.processes() {
            if let Some(parent) = process.parent() {
                if parent.as_u32() == pid && !result.contains(&child_pid.as_u32()) {
                    to_check.push(child_pid.as_u32());
                }
            }
        }
    }

    result
}

/// Kill a process with SIGTERM, then SIGKILL
///
/// Safety measures:
/// - Refuses to kill system-critical PIDs (0, 1, 2)
/// - Uses checked i32 conversion to avoid wrapping on large PIDs
/// - Verifies process existence via sysinfo before sending signals
/// - Properly handles errors (ignoring ESRCH for already-exited processes)
fn kill_process(pid: u32) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;

    // Guard against killing system-critical processes
    if pid == 0 || pid == 1 || pid == 2 {
        bail!("Refusing to kill system process (PID {})", pid);
    }

    // Safe PID conversion: reject values that exceed i32::MAX
    let raw_pid = i32::try_from(pid).context("PID exceeds i32 range")?;
    let nix_pid = Pid::from_raw(raw_pid);

    // Verify the process actually exists before attempting to kill it.
    // This mitigates (but cannot fully prevent) PID reuse attacks.
    {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All);
        if sys.process(sysinfo::Pid::from_u32(pid)).is_none() {
            tracing::debug!("PID {} no longer exists, skipping kill", pid);
            return Ok(());
        }
    }

    // Try SIGTERM first for graceful shutdown
    match kill(nix_pid, Signal::SIGTERM) {
        Ok(()) => {}
        Err(Errno::ESRCH) => {
            // Process already exited between our check and signal
            return Ok(());
        }
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to send SIGTERM to PID {}", pid));
        }
    }

    // Give the process time to handle SIGTERM
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if still alive; if so, escalate to SIGKILL
    match kill(nix_pid, None) {
        Ok(()) => {
            // Process still alive, force kill
            match kill(nix_pid, Signal::SIGKILL) {
                Ok(()) => {}
                Err(Errno::ESRCH) => {
                    // Exited between check and SIGKILL
                }
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to send SIGKILL to PID {}", pid));
                }
            }
        }
        Err(Errno::ESRCH) => {
            // Process exited after SIGTERM, success
        }
        Err(e) => {
            return Err(e)
                .with_context(|| format!("Failed to check if PID {} is still alive", pid));
        }
    }

    Ok(())
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
}
