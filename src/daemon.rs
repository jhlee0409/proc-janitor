use crate::config::Config;
use crate::logger;
use crate::scanner::{self, Scanner};
use anyhow::{bail, Context, Result};
use daemonize::Daemonize;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Maximum number of polling iterations when waiting for daemon to stop
const DAEMON_STOP_MAX_POLLS: u32 = 50;

/// Interval between polls when waiting for daemon to stop (milliseconds)
const DAEMON_STOP_POLL_INTERVAL_MS: u64 = 100;

#[derive(Serialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub stale_pid_file: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_interval: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist_count: Option<usize>,
}

pub struct Daemon {
    config: Config,
    scanner: Scanner,
    running: Arc<AtomicBool>,
    condvar: Arc<(Mutex<bool>, Condvar)>,
    config_mtime: Option<std::time::SystemTime>,
    dry_run: bool,
}

impl Daemon {
    pub fn new(config: Config, scanner: Scanner, dry_run: bool) -> Self {
        let config_mtime = crate::config::config_path()
            .ok()
            .and_then(|p| fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());
        Self {
            config,
            scanner,
            running: Arc::new(AtomicBool::new(false)),
            condvar: Arc::new((Mutex::new(false), Condvar::new())),
            config_mtime,
            dry_run,
        }
    }

    /// Check if config file has been modified and reload if so
    fn check_config_reload(&mut self) {
        let current_mtime = crate::config::config_path()
            .ok()
            .and_then(|p| fs::metadata(p).ok())
            .and_then(|m| m.modified().ok());

        if current_mtime != self.config_mtime {
            self.config_mtime = current_mtime;
            match Config::load() {
                Ok(new_config) => match Scanner::new(new_config.clone()) {
                    Ok(new_scanner) => {
                        eprintln!("Config reloaded successfully.");
                        self.config = new_config;
                        self.scanner = new_scanner;
                    }
                    Err(e) => {
                        eprintln!("Config reload failed (invalid patterns): {e}");
                    }
                },
                Err(e) => {
                    eprintln!("Config reload failed: {e}");
                }
            }
        }
    }

    /// Interruptible sleep
    fn sleep_interruptible(&self, duration: Duration) {
        let (lock, cvar) = &*self.condvar;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = cvar
            .wait_timeout(guard, duration)
            .unwrap_or_else(|e| e.into_inner());
    }

    pub fn start(&mut self) -> Result<()> {
        // Initialize logger
        if let Err(e) = logger::init_logger() {
            eprintln!("Warning: Failed to initialize logger: {e}");
            // Continue without file logging
        }

        self.running.store(true, Ordering::SeqCst);

        // Setup signal handlers with double-signal guard
        let running = Arc::clone(&self.running);
        let condvar = Arc::clone(&self.condvar);
        let shutdown_initiated = Arc::new(AtomicBool::new(false));
        let shutdown_flag = Arc::clone(&shutdown_initiated);
        ctrlc::set_handler(move || {
            // Prevent double-shutdown from repeated signals
            if shutdown_flag.swap(true, Ordering::SeqCst) {
                return;
            }
            eprintln!("Received termination signal, shutting down gracefully...");
            running.store(false, Ordering::SeqCst);
            // Wake up the daemon immediately
            let (lock, cvar) = &*condvar;
            let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            *guard = true;
            cvar.notify_one();
        })
        .context("Failed to set signal handler")?;

        let sigterm_timeout = self.config.sigterm_timeout;
        println!(
            "Daemon started. Scanning every {} seconds...",
            self.config.scan_interval
        );

        // Main loop - reuses self.scanner to preserve tracked state across cycles
        while self.running.load(Ordering::SeqCst) {
            self.check_config_reload();
            match scanner::scan_with_scanner(&mut self.scanner) {
                Ok(result) if !result.orphans.is_empty() => {
                    let count = result.orphans.len();
                    if self.dry_run {
                        eprintln!("[DRY-RUN] Would clean {count} orphaned process(es):");
                        for orphan in &result.orphans {
                            eprintln!(
                                "[DRY-RUN]   PID {} - {} ({})",
                                orphan.pid, orphan.name, orphan.cmdline
                            );
                        }
                    } else {
                        match crate::cleaner::clean_all(&result.orphans, sigterm_timeout, false) {
                            Ok(results) => {
                                let cleaned = results.iter().filter(|r| r.success).count();
                                if cleaned > 0 {
                                    send_notification(cleaned);
                                }
                                record_cleanup_stats(&results);
                            }
                            Err(e) => {
                                eprintln!("Error cleaning {count} processes: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error scanning processes: {e}");
                }
                _ => {}
            }

            // Use interruptible sleep instead of thread::sleep
            self.sleep_interruptible(Duration::from_secs(self.config.scan_interval));
        }

        println!("Daemon stopped.");
        Ok(())
    }
}

/// Send a macOS notification when processes are cleaned
#[cfg(target_os = "macos")]
fn send_notification(count: usize) {
    let msg = if count == 1 {
        "Cleaned 1 orphaned process.".to_string()
    } else {
        format!("Cleaned {count} orphaned processes.")
    };
    // Fire and forget — don't block the daemon loop
    let _ = std::process::Command::new("osascript")
        .args([
            "-e",
            &format!("display notification \"{msg}\" with title \"proc-janitor\""),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(not(target_os = "macos"))]
fn send_notification(_count: usize) {
    // Notifications not supported on this platform
}

/// A single cleanup event record
#[derive(Serialize, Deserialize)]
struct CleanupEvent {
    timestamp: String,
    cleaned: usize,
    failed: usize,
    processes: Vec<String>,
}

/// Record a cleanup event to stats file
fn record_cleanup_stats(results: &[crate::cleaner::CleanResult]) {
    let cleaned = results.iter().filter(|r| r.success).count();
    let failed = results.len() - cleaned;
    if cleaned == 0 && failed == 0 {
        return;
    }

    let event = CleanupEvent {
        timestamp: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
        cleaned,
        failed,
        processes: results
            .iter()
            .filter(|r| r.success)
            .map(|r| format!("{} (PID {})", r.name, r.pid))
            .collect(),
    };

    let stats_path = match dirs::home_dir() {
        Some(home) => home.join(".proc-janitor").join("stats.jsonl"),
        None => return,
    };

    // Symlink protection: refuse to write through symlinks
    if let Err(e) = crate::util::check_not_symlink(&stats_path) {
        tracing::warn!("Refusing to write stats: {e}");
        return;
    }

    // Rotate if file exceeds 5 MB
    const MAX_STATS_SIZE: u64 = 5 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(&stats_path) {
        if meta.len() > MAX_STATS_SIZE {
            let rotated = stats_path.with_extension("jsonl.old");
            if let Err(e) = crate::util::check_not_symlink(&rotated) {
                tracing::warn!("Refusing to rotate stats: {e}");
                return;
            }
            let _ = std::fs::rename(&stats_path, &rotated);
        }
    }

    // Append one JSON line
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&stats_path)
    {
        if let Ok(line) = serde_json::to_string(&event) {
            use std::io::Write;
            let _ = writeln!(file, "{line}");
        }
    }
}

/// Get stats file path
fn get_stats_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".proc-janitor").join("stats.jsonl"))
}

/// Show cleanup statistics summary
pub fn show_stats(days: u64, json: bool) -> Result<()> {
    let stats_path = get_stats_path().ok_or_else(|| anyhow::anyhow!("HOME not found"))?;
    if !stats_path.exists() {
        if json {
            println!("{{\"total_cleaned\":0,\"total_failed\":0,\"events\":0}}");
        } else {
            println!("No cleanup statistics found.");
            println!("Stats are recorded when the daemon cleans orphaned processes.");
        }
        return Ok(());
    }

    let cutoff = chrono::Local::now() - chrono::Duration::days(days as i64);
    let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

    let file = std::io::BufReader::new(fs::File::open(&stats_path)?);
    use std::io::BufRead;

    let mut total_cleaned: usize = 0;
    let mut total_failed: usize = 0;
    let mut event_count: usize = 0;
    let mut process_counts: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for line in file.lines().map_while(Result::ok) {
        if let Ok(event) = serde_json::from_str::<CleanupEvent>(&line) {
            if event.timestamp < cutoff_str {
                continue;
            }
            event_count += 1;
            total_cleaned += event.cleaned;
            total_failed += event.failed;
            for proc_name in &event.processes {
                // Extract just the name (before " (PID")
                let name = proc_name
                    .split(" (PID")
                    .next()
                    .unwrap_or(proc_name)
                    .to_string();
                *process_counts.entry(name).or_default() += 1;
            }
        }
    }

    if json {
        let mut top: Vec<_> = process_counts.iter().collect();
        top.sort_by(|a, b| b.1.cmp(a.1));
        let top_procs: Vec<_> = top
            .iter()
            .take(10)
            .map(|(k, v)| serde_json::json!({"name": k, "count": v}))
            .collect();
        let output = serde_json::json!({
            "days": days,
            "events": event_count,
            "total_cleaned": total_cleaned,
            "total_failed": total_failed,
            "top_processes": top_procs,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        let use_color = crate::util::use_color();
        if use_color {
            println!(
                "{}",
                format!("Cleanup Statistics (Last {days} Days)").bold()
            );
        } else {
            println!("Cleanup Statistics (Last {days} Days)");
        }
        println!("{}", "=".repeat(36));
        println!("  Events: {event_count}");
        println!("  Processes cleaned: {total_cleaned}");
        println!("  Failed kills: {total_failed}");

        if !process_counts.is_empty() {
            let mut top: Vec<_> = process_counts.iter().collect();
            top.sort_by(|a, b| b.1.cmp(a.1));
            println!("  Most cleaned:");
            for (name, count) in top.iter().take(5) {
                println!("    {name}: {count}");
            }
        }
    }

    Ok(())
}

/// Get the PID file path
fn get_pid_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?;
    let pid_dir = home.join(".proc-janitor");

    // Create directory if it doesn't exist
    fs::create_dir_all(&pid_dir).context("Failed to create PID directory")?;

    // Set directory permissions to 700 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pid_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    Ok(pid_dir.join("proc-janitor.pid"))
}

/// Write PID to file
fn write_pid_file(pid: u32) -> Result<()> {
    use std::io::Write;
    let pid_file = get_pid_file_path()?;
    let mut file = crate::util::open_nofollow_write(&pid_file)?;
    file.write_all(pid.to_string().as_bytes())
        .context("Failed to write PID file")?;
    file.sync_all().context("Failed to sync PID file")?;
    Ok(())
}

/// Remove PID file
fn remove_pid_file() -> Result<()> {
    let pid_file = get_pid_file_path()?;
    if pid_file.exists() {
        fs::remove_file(&pid_file).context("Failed to remove PID file")?;
    }
    Ok(())
}

/// Get daemon PID from file
pub fn get_daemon_pid() -> Option<u32> {
    let pid_file = get_pid_file_path().ok()?;
    let pid_str = fs::read_to_string(pid_file).ok()?;
    pid_str.trim().parse::<u32>().ok()
}

/// Check if daemon is running
pub fn is_daemon_running() -> bool {
    if let Some(pid) = get_daemon_pid() {
        // Check if process exists using nix::sys::signal::kill with None (signal 0)
        use nix::sys::signal::kill;
        use nix::unistd::Pid as NixPid;

        let Ok(pid_i32) = i32::try_from(pid) else {
            return false;
        };
        let nix_pid = NixPid::from_raw(pid_i32);
        // Sending None (signal 0) checks if process exists without actually signaling it
        kill(nix_pid, None).is_ok()
    } else {
        false
    }
}

/// Daemonize the process
pub fn daemonize() -> Result<()> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?;
    let daemon_dir = home.join(".proc-janitor");

    // Create directory if it doesn't exist
    fs::create_dir_all(&daemon_dir).context("Failed to create daemon directory")?;

    // Set directory permissions to 700 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&daemon_dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let stdout_file = daemon_dir.join("daemon.out");
    let stderr_file = daemon_dir.join("daemon.err");

    use nix::libc;
    use std::os::unix::fs::OpenOptionsExt;

    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&stdout_file)
        .context("Failed to open stdout file")?;
    let stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&stderr_file)
        .context("Failed to open stderr file")?;

    let daemonize = Daemonize::new()
        .working_directory(&daemon_dir)
        .stdout(stdout)
        .stderr(stderr);

    daemonize.start().context("Failed to daemonize process")?;

    Ok(())
}

/// Start the daemon (called from CLI)
pub fn start(foreground: bool, dry_run: bool) -> Result<()> {
    // Try to acquire exclusive lock on PID file to prevent race conditions
    let pid_path = get_pid_file_path()?;
    let lock_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&pid_path)
        .context("Failed to open PID file for locking")?;

    // Try non-blocking lock - if it fails, another daemon holds it
    if fs2::FileExt::try_lock_exclusive(&lock_file).is_err() {
        if let Some(old_pid) = get_daemon_pid() {
            bail!("Daemon already running with PID {old_pid}");
        }
        bail!("Another daemon instance is starting");
    }

    // We have the lock - check if there's a stale PID
    if let Some(old_pid) = get_daemon_pid() {
        // Check if process exists using nix
        use nix::sys::signal::kill;
        use nix::unistd::Pid;

        let nix_pid = Pid::from_raw(i32::try_from(old_pid).context("PID exceeds i32 range")?);
        if kill(nix_pid, None).is_ok() {
            // Process exists and we have the lock - this shouldn't happen
            // but if it does, the other process doesn't hold the lock
            let _ = fs2::FileExt::unlock(&lock_file);
            bail!("Daemon already running with PID {old_pid}");
        }
        tracing::info!("Removing stale PID file from previous crash...");
    }

    // Load config
    let config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "Warning: Failed to load config ({e}). Using defaults. \
                 Fix with: proc-janitor config init --force"
            );
            Config::default()
        }
    };
    let scanner = Scanner::new(config.clone())?;

    if foreground {
        // Foreground mode: don't daemonize, run directly
        println!("Starting proc-janitor in foreground mode...");

        // Write PID file
        write_pid_file(std::process::id())?;

        // Create and start daemon
        let mut daemon = Daemon::new(config, scanner, dry_run);
        daemon.start()?;

        // Cleanup on exit
        remove_pid_file()?;
    } else {
        // Background mode: daemonize the process
        daemonize()?;

        // Write PID file (truncate and write new PID)
        write_pid_file(std::process::id())?;

        // Create and start daemon
        // Note: lock_file is kept open and locked until this process exits
        let mut daemon = Daemon::new(config, scanner, dry_run);
        daemon.start()?;

        // Cleanup on exit
        remove_pid_file()?;
    }
    // Lock is automatically released when lock_file is dropped

    Ok(())
}

/// Stop the daemon (called from CLI)
pub fn stop() -> Result<()> {
    if let Some(pid) = get_daemon_pid() {
        if !is_daemon_running() {
            println!("Daemon is not running (stale PID file)");
            remove_pid_file()?;
            return Ok(());
        }

        // Verify PID identity before sending signals
        {
            use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
            let mut sys = System::new_with_specifics(
                RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
            );
            sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]));

            if let Some(process) = sys.process(sysinfo::Pid::from_u32(pid)) {
                let name = process.name().to_string_lossy().to_string();
                if !name.contains("proc-janitor") && !name.contains("proc_janitor") {
                    bail!(
                        "PID {} is not proc-janitor (found: '{}'). PID file may be stale. \
                         Remove {} manually if the daemon is not running.",
                        pid,
                        name,
                        get_pid_file_path().unwrap_or_default().display()
                    );
                }
            }
        }

        // Send SIGTERM using nix
        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid as NixPid;

        let nix_pid = NixPid::from_raw(i32::try_from(pid).context("PID exceeds i32 range")?);
        kill(nix_pid, Signal::SIGTERM)
            .with_context(|| format!("Failed to send SIGTERM to daemon (PID: {pid})"))?;

        println!("Sent SIGTERM to daemon (PID: {pid})");

        // Poll for process termination
        let max_wait = DAEMON_STOP_MAX_POLLS;
        let mut terminated = false;
        for _ in 0..max_wait {
            std::thread::sleep(Duration::from_millis(DAEMON_STOP_POLL_INTERVAL_MS));
            if kill(nix_pid, None).is_err() {
                // Process no longer exists
                terminated = true;
                break;
            }
        }

        if terminated {
            println!("Daemon stopped successfully (PID: {pid})");
            remove_pid_file()?;
        } else {
            // Escalate to SIGKILL if SIGTERM didn't work
            eprintln!(
                "Warning: Daemon (PID: {}) did not terminate within {} seconds, sending SIGKILL...",
                pid,
                (DAEMON_STOP_MAX_POLLS as u64 * DAEMON_STOP_POLL_INTERVAL_MS) / 1000
            );
            let _ = kill(nix_pid, Signal::SIGKILL);
            // Brief wait for SIGKILL to take effect
            std::thread::sleep(Duration::from_millis(500));
            if kill(nix_pid, None).is_err() {
                println!("Daemon force-killed successfully (PID: {pid})");
                remove_pid_file()?;
            } else {
                eprintln!("Error: Failed to kill daemon (PID: {pid}). PID file retained.");
            }
        }

        Ok(())
    } else {
        bail!("Daemon is not running (no PID file found)");
    }
}

/// Send SIGHUP to daemon to trigger config reload
pub fn reload() -> Result<()> {
    if let Some(pid) = get_daemon_pid() {
        if !is_daemon_running() {
            bail!("Daemon is not running (stale PID file)");
        }

        use nix::sys::signal::{kill, Signal};
        use nix::unistd::Pid as NixPid;

        let nix_pid = NixPid::from_raw(i32::try_from(pid).context("PID exceeds i32 range")?);
        kill(nix_pid, Signal::SIGHUP)
            .with_context(|| format!("Failed to send SIGHUP to daemon (PID: {pid})"))?;

        println!("Sent SIGHUP to daemon (PID: {pid}). Config will be reloaded on next scan cycle.");
        Ok(())
    } else {
        bail!("Daemon is not running (no PID file found)");
    }
}

/// Restart the daemon (stop then start)
pub fn restart(foreground: bool, dry_run: bool) -> Result<()> {
    // Stop if running
    if is_daemon_running() {
        stop()?;
        // Brief wait for clean shutdown
        std::thread::sleep(Duration::from_millis(500));
    }
    start(foreground, dry_run)
}

/// Get daemon uptime as (raw_seconds, human-readable string)
fn get_daemon_uptime(pid: u32) -> Option<(u64, String)> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let mut sys =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    sys.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(
        pid,
    )]));

    let process = sys.process(sysinfo::Pid::from_u32(pid))?;
    let start_time = process.start_time();
    if start_time == 0 {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let uptime_secs = now.saturating_sub(start_time);

    let hours = uptime_secs / 3600;
    let minutes = (uptime_secs % 3600) / 60;
    let seconds = uptime_secs % 60;

    let display = if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    };
    Some((uptime_secs, display))
}

/// Print recent log entries
fn print_recent_logs(count: usize) {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return,
    };
    let log_dir = home.join(".proc-janitor").join("logs");
    if !log_dir.exists() {
        return;
    }

    // Find the most recent log file
    let mut entries: Vec<_> = match std::fs::read_dir(&log_dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(_) => return,
    };
    entries.sort_by(|a, b| {
        let a_time = a.metadata().and_then(|m| m.modified()).ok();
        let b_time = b.metadata().and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    if let Some(entry) = entries.first() {
        if let Ok(file) = std::fs::File::open(entry.path()) {
            use std::collections::VecDeque;
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(file);
            let mut last_lines: VecDeque<String> = VecDeque::with_capacity(count + 1);
            for line in reader.lines().map_while(Result::ok) {
                last_lines.push_back(line);
                if last_lines.len() > count {
                    last_lines.pop_front();
                }
            }
            if !last_lines.is_empty() {
                println!("\n  Recent logs:");
                for line in &last_lines {
                    println!("    {line}");
                }
            }
        }
    }
}

/// Show daemon status (called from CLI)
pub fn status(json: bool) -> Result<()> {
    let running = is_daemon_running();
    let pid = get_daemon_pid();
    let stale_pid_file = !running && pid.is_some();

    // Gather uptime info if running
    let uptime_info = if running {
        pid.and_then(get_daemon_uptime)
    } else {
        None
    };

    // Gather config info if running
    let config_info = if running {
        crate::config::Config::load().ok()
    } else {
        None
    };

    if json {
        let status = DaemonStatus {
            running,
            pid,
            stale_pid_file,
            uptime_seconds: uptime_info.as_ref().map(|(secs, _)| *secs),
            uptime: uptime_info.as_ref().map(|(_, display)| display.clone()),
            scan_interval: config_info.as_ref().map(|c| c.scan_interval),
            grace_period: config_info.as_ref().map(|c| c.grace_period),
            target_count: config_info.as_ref().map(|c| c.targets.len()),
            whitelist_count: config_info.as_ref().map(|c| c.whitelist.len()),
        };
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        let use_color = crate::util::use_color();

        if running {
            if use_color {
                println!(
                    "{} proc-janitor daemon ({})",
                    "●".green(),
                    "running".green()
                );
            } else {
                println!("● proc-janitor daemon (running)");
            }
            if let Some(pid) = pid {
                if let Some((_, ref display)) = uptime_info {
                    println!("  PID: {pid} | Uptime: {display}");
                } else {
                    println!("  PID: {pid}");
                }
            }

            // Show config summary
            if let Some(ref config) = config_info {
                println!(
                    "  Patterns: {} target(s), {} whitelisted",
                    config.targets.len(),
                    config.whitelist.len()
                );
                println!(
                    "  Scan interval: {}s | Grace period: {}s",
                    config.scan_interval, config.grace_period
                );
            }

            // Show last few log lines
            print_recent_logs(3);
        } else {
            if use_color {
                println!(
                    "{} proc-janitor daemon ({})",
                    "●".dimmed(),
                    "stopped".dimmed()
                );
            } else {
                println!("● proc-janitor daemon (stopped)");
            }
            if stale_pid_file {
                if use_color {
                    println!(
                        "  {}",
                        "Stale PID file found - daemon may have crashed".yellow()
                    );
                    println!(
                        "  Fix: Run 'proc-janitor stop' to clean up, then 'proc-janitor start'"
                    );
                } else {
                    println!("  Stale PID file found - daemon may have crashed");
                    println!(
                        "  Fix: Run 'proc-janitor stop' to clean up, then 'proc-janitor start'"
                    );
                }
            } else {
                println!("  Start with: proc-janitor start");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_status_serialization() {
        let status = DaemonStatus {
            running: true,
            pid: Some(1234),
            stale_pid_file: false,
            uptime_seconds: Some(3661),
            uptime: Some("1h 1m".to_string()),
            scan_interval: Some(5),
            grace_period: Some(30),
            target_count: Some(3),
            whitelist_count: Some(1),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"stale_pid_file\":false"));
        assert!(json.contains("\"uptime_seconds\":3661"));
        assert!(json.contains("\"scan_interval\":5"));
        assert!(json.contains("\"target_count\":3"));
    }

    #[test]
    fn test_daemon_status_not_running() {
        let status = DaemonStatus {
            running: false,
            pid: None,
            stale_pid_file: true,
            uptime_seconds: None,
            uptime: None,
            scan_interval: None,
            grace_period: None,
            target_count: None,
            whitelist_count: None,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"running\":false"));
        assert!(json.contains("\"pid\":null"));
        assert!(json.contains("\"stale_pid_file\":true"));
        // Optional fields should be absent when None (skip_serializing_if)
        assert!(!json.contains("uptime_seconds"));
        assert!(!json.contains("scan_interval"));
    }

    #[test]
    fn test_get_pid_file_path() {
        let path = get_pid_file_path();
        assert!(path.is_ok());
        let path = path.unwrap();
        assert!(path.to_string_lossy().contains("proc-janitor.pid"));
    }

    #[test]
    fn test_daemon_stop_constants() {
        // Verify timeout is reasonable: 50 * 100ms = 5 seconds
        assert_eq!(DAEMON_STOP_MAX_POLLS, 50);
        assert_eq!(DAEMON_STOP_POLL_INTERVAL_MS, 100);
        let total_ms = DAEMON_STOP_MAX_POLLS as u64 * DAEMON_STOP_POLL_INTERVAL_MS;
        assert_eq!(total_ms, 5000);
    }
}
