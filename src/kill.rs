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
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

/// System-critical PIDs that must never be killed
const SYSTEM_PIDS: [u32; 3] = [0, 1, 2];

/// Verify that a process still has the same identity (start_time) to mitigate PID reuse
pub fn verify_process_identity(pid: u32, expected_start_time: u64) -> bool {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All);

    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        process.start_time() == expected_start_time
    } else {
        false // Process no longer exists
    }
}

/// Check if a process exists using signal 0 (lightweight, no full system scan)
pub fn process_exists(pid: u32) -> bool {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    kill(Pid::from_raw(raw_pid), None).is_ok()
}

/// Kill a process with SIGTERM→SIGKILL pattern.
///
/// Safety measures:
/// - Refuses to kill system-critical PIDs (0, 1, 2)
/// - Verifies process identity via start_time before sending signals (when start_time provided)
/// - Uses configurable SIGTERM timeout
/// - Handles ESRCH for already-exited processes
pub fn kill_process(pid: u32, start_time: Option<u64>, sigterm_timeout_secs: u64) -> Result<Signal> {
    // Guard against killing system-critical processes
    if SYSTEM_PIDS.contains(&pid) {
        bail!("Refusing to kill system process (PID {pid})");
    }

    // Safe PID conversion
    let raw_pid = i32::try_from(pid).context("PID exceeds i32 range")?;
    let nix_pid = Pid::from_raw(raw_pid);

    // Verify process identity if start_time is provided
    if let Some(st) = start_time {
        if !verify_process_identity(pid, st) {
            bail!("Process {pid} identity changed (possible PID reuse), skipping kill");
        }
    } else {
        // No start_time: at least verify process exists
        if !process_exists(pid) {
            return Ok(Signal::SIGTERM); // Already gone
        }
    }

    // Try SIGTERM first for graceful shutdown
    match kill(nix_pid, Signal::SIGTERM) {
        Ok(()) => {}
        Err(Errno::ESRCH) => return Ok(Signal::SIGTERM), // Already exited
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

        // Check if process has exited
        match kill(nix_pid, None) {
            Err(Errno::ESRCH) => break false, // Process exited
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("Failed to check if PID {pid} is still alive"));
            }
            Ok(()) => {
                if elapsed >= deadline {
                    break true; // Timeout reached, still alive
                }
            }
        }
    };

    if still_alive {
        // Process still alive, force kill
        match kill(nix_pid, Signal::SIGKILL) {
            Ok(()) => Ok(Signal::SIGKILL),
            Err(Errno::ESRCH) => Ok(Signal::SIGTERM),
            Err(e) => {
                Err(e).with_context(|| format!("Failed to send SIGKILL to PID {pid}"))
            }
        }
    } else {
        Ok(Signal::SIGTERM) // Exited after SIGTERM
    }
}
