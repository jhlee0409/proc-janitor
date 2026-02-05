//! Shared process kill logic
//!
//! Provides a unified kill implementation with PID reuse mitigation.
//! Used by both cleaner.rs (daemon/CLI clean) and session.rs (session clean).

use anyhow::{bail, Context, Result};
use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessesToUpdate, System};
#[cfg(test)]
use sysinfo::{ProcessRefreshKind, RefreshKind};

/// System-critical PIDs that must never be killed
const SYSTEM_PIDS: [u32; 3] = [0, 1, 2];

/// Verify process identity using an existing System instance (for batch operations).
/// Falls back to creating a new instance if none provided.
pub fn verify_process_identity_with_sys(sys: &mut System, pid: u32, expected_start_time: u64) -> bool {
    sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]));
    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        process.start_time() == expected_start_time
    } else {
        false
    }
}

/// Verify that a process still has the same identity (start_time) to mitigate PID reuse
#[cfg(test)]
pub fn verify_process_identity(pid: u32, expected_start_time: u64) -> bool {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    verify_process_identity_with_sys(&mut sys, pid, expected_start_time)
}

/// Check if a process exists using signal 0 (lightweight, no full system scan)
pub fn process_exists(pid: u32) -> bool {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    kill(Pid::from_raw(raw_pid), None).is_ok()
}

/// Kill a process using a shared System instance (for batch operations).
/// Avoids creating a new System instance per kill during batch cleanup.
pub fn kill_process_with_sys(sys: &mut System, pid: u32, start_time: Option<u64>, sigterm_timeout_secs: u64) -> Result<Signal> {
    // Guard against killing system-critical processes
    if SYSTEM_PIDS.contains(&pid) {
        bail!("Refusing to kill system process (PID {pid})");
    }

    let raw_pid = i32::try_from(pid).context("PID exceeds i32 range")?;
    let nix_pid = Pid::from_raw(raw_pid);

    if let Some(st) = start_time {
        if !verify_process_identity_with_sys(sys, pid, st) {
            bail!("Process {pid} identity changed (possible PID reuse), skipping kill");
        }
    } else if !process_exists(pid) {
        return Ok(Signal::SIGTERM);
    }

    // Try SIGTERM first for graceful shutdown
    match kill(nix_pid, Signal::SIGTERM) {
        Ok(()) => {}
        Err(Errno::ESRCH) => return Ok(Signal::SIGTERM),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to send SIGTERM to PID {pid}"));
        }
    }

    // Poll for graceful shutdown instead of sleeping full timeout
    let poll_interval = Duration::from_millis(100);
    let deadline = Duration::from_secs(sigterm_timeout_secs);
    let mut elapsed = Duration::ZERO;

    let still_alive = loop {
        thread::sleep(poll_interval);
        elapsed += poll_interval;

        match kill(nix_pid, None) {
            Err(Errno::ESRCH) => break false,
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to check if PID {pid} is still alive"));
            }
            Ok(()) => {
                if elapsed >= deadline {
                    break true;
                }
            }
        }
    };

    if still_alive {
        match kill(nix_pid, Signal::SIGKILL) {
            Ok(()) => Ok(Signal::SIGKILL),
            Err(Errno::ESRCH) => Ok(Signal::SIGTERM),
            Err(e) => Err(e).with_context(|| format!("Failed to send SIGKILL to PID {pid}")),
        }
    } else {
        Ok(Signal::SIGTERM)
    }
}

/// Kill a process with SIGTERM→SIGKILL pattern.
///
/// Safety measures:
/// - Refuses to kill system-critical PIDs (0, 1, 2)
/// - Verifies process identity via start_time before sending signals (when start_time provided)
/// - Uses configurable SIGTERM timeout
/// - Handles ESRCH for already-exited processes
#[cfg(test)]
pub fn kill_process(pid: u32, start_time: Option<u64>, sigterm_timeout_secs: u64) -> Result<Signal> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    kill_process_with_sys(&mut sys, pid, start_time, sigterm_timeout_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_pid_guard_pid0() {
        let result = kill_process(0, None, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("system process"));
    }

    #[test]
    fn test_system_pid_guard_pid1() {
        let result = kill_process(1, None, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("system process"));
    }

    #[test]
    fn test_system_pid_guard_pid2() {
        let result = kill_process(2, None, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("system process"));
    }

    #[test]
    fn test_pid_exceeds_i32_range() {
        // u32::MAX (4294967295) exceeds i32::MAX
        let result = kill_process(u32::MAX, None, 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("i32 range"));
    }

    #[test]
    fn test_process_exists_nonexistent() {
        assert!(!process_exists(4_000_000_000));
    }

    #[test]
    fn test_process_exists_self() {
        assert!(process_exists(std::process::id()));
    }

    #[test]
    fn test_kill_nonexistent_without_start_time() {
        // Non-existent PID without start_time should return Ok (already gone)
        let result = kill_process(4_000_000_000, None, 5);
        // Either Ok (already gone) or Err (i32 range) - both acceptable
        // 4 billion exceeds i32 range, so this should error
        assert!(result.is_err());
    }

    #[test]
    fn test_kill_with_wrong_start_time() {
        // Killing our own PID with wrong start_time should fail (identity mismatch)
        let our_pid = std::process::id();
        let result = kill_process(our_pid, Some(0), 5);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("identity changed"));
    }

    #[test]
    fn test_verify_identity_nonexistent() {
        assert!(!verify_process_identity(4_000_000_000, 0));
    }

    #[test]
    fn test_kill_real_child_process() {
        use std::process::Command;

        // Spawn a child process that sleeps
        let mut child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("Failed to spawn sleep process");

        let pid = child.id();

        // Verify process exists
        assert!(process_exists(pid));

        // Kill it with SIGTERM (no start_time check)
        let result = kill_process(pid, None, 5);
        assert!(result.is_ok());

        // Wait for the child to actually exit and be reaped
        let _ = child.wait();

        // Process should no longer exist
        assert!(!process_exists(pid));
    }

    #[test]
    fn test_kill_real_child_with_identity() {
        use std::process::Command;
        use sysinfo::{ProcessRefreshKind, RefreshKind, System, ProcessesToUpdate};

        // Spawn a child process
        let mut child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("Failed to spawn sleep process");

        let pid = child.id();

        // Get the real start_time
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]));
        let start_time = sys.process(sysinfo::Pid::from_u32(pid))
            .map(|p| p.start_time())
            .unwrap_or(0);

        // Kill with correct start_time should succeed
        let result = kill_process(pid, Some(start_time), 5);
        assert!(result.is_ok());

        // Wait for the child to actually exit and be reaped
        let _ = child.wait();

        assert!(!process_exists(pid));
    }

    #[test]
    fn test_verify_identity_with_sys() {
        // verify our own process with correct start_time
        let pid = std::process::id();
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]));
        let our_start_time = sys.process(sysinfo::Pid::from_u32(pid))
            .map(|p| p.start_time())
            .expect("Should find our own process");

        assert!(verify_process_identity(pid, our_start_time));
        assert!(!verify_process_identity(pid, our_start_time + 9999));
    }
}
