use anyhow::{Context, Result};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Serialize;
use std::thread;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

use crate::config::Config;
use crate::scanner::OrphanProcess;

/// Result of cleaning a single process
#[derive(Debug, Serialize)]
pub struct CleanResult {
    pub pid: u32,
    pub name: String,
    pub success: bool,
    #[serde(serialize_with = "serialize_signal")]
    pub signal_used: Signal,
}

/// Serialize Signal enum as string
fn serialize_signal<S>(signal: &Signal, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!("{:?}", signal))
}

/// Overall clean operation result
#[derive(Debug, Serialize)]
pub struct CleanSummary {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<CleanResult>,
    pub dry_run: bool,
}

/// Verify process identity before killing to prevent PID reuse attacks
fn verify_process_identity(pid: u32, expected_start_time: u64) -> bool {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All);

    if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
        process.start_time() == expected_start_time
    } else {
        false  // Process no longer exists
    }
}

/// Clean a single process by PID
pub fn clean_process(pid: u32, start_time: u64, sigterm_timeout: u64, dry_run: bool) -> Result<CleanResult> {
    // Prevent killing system-critical processes
    if pid == 0 || pid == 1 || pid == 2 {
        return Err(anyhow::anyhow!(
            "Refusing to kill system process (PID {}). This would destabilize the system.",
            pid
        ));
    }

    // Verify process identity before killing to prevent PID reuse vulnerability
    if !verify_process_identity(pid, start_time) {
        return Err(anyhow::anyhow!(
            "Process {} identity changed (possible PID reuse), skipping kill",
            pid
        ));
    }
    let pid_nix = Pid::from_raw(
        i32::try_from(pid).with_context(|| format!("PID {} exceeds i32 range", pid))?
    );

    if dry_run {
        println!("[DRY-RUN] Would clean process {}", pid);
        return Ok(CleanResult {
            pid,
            name: String::new(),
            success: true,
            signal_used: Signal::SIGTERM,
        });
    }

    // First try SIGTERM (graceful shutdown)
    println!("Sending SIGTERM to process {}...", pid);
    if let Err(_e) = send_signal(pid_nix, Signal::SIGTERM) {
        return Ok(CleanResult {
            pid,
            name: String::new(),
            success: false,
            signal_used: Signal::SIGTERM,
        });
    }

    // Wait for graceful shutdown using configured timeout
    thread::sleep(Duration::from_secs(sigterm_timeout));

    // Check if process still exists
    if !process_exists(pid) {
        println!("Process {} terminated gracefully", pid);
        return Ok(CleanResult {
            pid,
            name: String::new(),
            success: true,
            signal_used: Signal::SIGTERM,
        });
    }

    // Process still exists, use SIGKILL
    println!("Process {} still running, sending SIGKILL...", pid);
    if let Err(_e) = send_signal(pid_nix, Signal::SIGKILL) {
        return Ok(CleanResult {
            pid,
            name: String::new(),
            success: false,
            signal_used: Signal::SIGKILL,
        });
    }

    // Wait a moment and verify
    thread::sleep(Duration::from_millis(500));
    let success = !process_exists(pid);

    if success {
        println!("Process {} killed successfully", pid);
    } else {
        println!("Failed to kill process {}", pid);
    }

    Ok(CleanResult {
        pid,
        name: String::new(),
        success,
        signal_used: Signal::SIGKILL,
    })
}

/// Clean all orphaned processes
pub fn clean_all(orphans: &[OrphanProcess], sigterm_timeout: u64, dry_run: bool) -> Result<Vec<CleanResult>> {
    let mut results = Vec::new();

    for orphan in orphans {
        match clean_process(orphan.pid, orphan.start_time, sigterm_timeout, dry_run) {
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

/// Send a signal to a process
fn send_signal(pid: Pid, signal: Signal) -> Result<()> {
    kill(pid, signal).context(format!("Failed to send {:?} to PID {}", signal, pid))
}

/// Check if a process exists
fn process_exists(pid: u32) -> bool {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    sys.process(sysinfo::Pid::from_u32(pid)).is_some()
}

/// Public function for CLI clean command
pub fn clean(dry_run: bool) -> Result<CleanSummary> {
    let mut config = Config::load()?;
    let sigterm_timeout = config.sigterm_timeout;
    // CLI clean should execute immediately without grace period
    config.grace_period = 0;
    let mut scanner = crate::scanner::Scanner::new(config)?;
    let orphans = scanner.scan()?;

    let results = if !orphans.is_empty() {
        clean_all(&orphans, sigterm_timeout, dry_run)?
    } else {
        Vec::new()
    };

    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.len() - successful;

    Ok(CleanSummary {
        total: results.len(),
        successful,
        failed,
        results,
        dry_run,
    })
}
