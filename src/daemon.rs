use crate::config::Config;
use crate::logger;
use crate::scanner::{self, Scanner};
use anyhow::{bail, Context, Result};
use daemonize::Daemonize;
use fs2::FileExt;
use owo_colors::OwoColorize;
use serde::Serialize;
use std::fs;
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
}

pub struct Daemon {
    config: Config,
    scanner: Scanner,
    running: Arc<AtomicBool>,
    condvar: Arc<(Mutex<bool>, Condvar)>,
}

impl Daemon {
    pub fn new(config: Config, scanner: Scanner) -> Self {
        Self {
            config,
            scanner,
            running: Arc::new(AtomicBool::new(false)),
            condvar: Arc::new((Mutex::new(false), Condvar::new())),
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

    /// Signal the daemon to wake up
    #[allow(dead_code)] // Used for graceful shutdown in future
    pub fn wake(&self) {
        let (lock, cvar) = &*self.condvar;
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        *guard = true;
        cvar.notify_one();
    }

    pub fn start(&mut self) -> Result<()> {
        // Initialize logger
        if let Err(e) = logger::init_logger() {
            eprintln!("Warning: Failed to initialize logger: {e}");
            // Continue without file logging
        }

        self.running.store(true, Ordering::SeqCst);

        // Setup signal handlers
        let running = Arc::clone(&self.running);
        let condvar = Arc::clone(&self.condvar);
        ctrlc::set_handler(move || {
            // Use eprintln instead of println for signal handler safety
            // (ctrlc crate runs handler in a dedicated thread on most platforms,
            // but we avoid stdout which may be captured/redirected by launchd)
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
            if let Err(e) = scanner::scan_with_scanner(&mut self.scanner, true, sigterm_timeout) {
                eprintln!("Error scanning processes: {e}");
            }

            // Use interruptible sleep instead of thread::sleep
            self.sleep_interruptible(Duration::from_secs(self.config.scan_interval));
        }

        println!("Daemon stopped.");
        Ok(())
    }

    #[allow(dead_code)] // Used for graceful shutdown in future
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.wake();
    }
}

/// Get the PID file path
fn get_pid_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?;
    let pid_dir = home.join(".proc-janitor");

    // Create directory if it doesn't exist
    fs::create_dir_all(&pid_dir).context("Failed to create PID directory")?;

    Ok(pid_dir.join("proc-janitor.pid"))
}

/// Write PID to file
fn write_pid_file(pid: u32) -> Result<()> {
    let pid_file = get_pid_file_path()?;
    fs::write(&pid_file, pid.to_string()).context("Failed to write PID file")?;
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
    let home = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?;
    let daemon_dir = home.join(".proc-janitor");

    // Create directory if it doesn't exist
    fs::create_dir_all(&daemon_dir).context("Failed to create daemon directory")?;

    let stdout_file = daemon_dir.join("daemon.out");
    let stderr_file = daemon_dir.join("daemon.err");

    let stdout = fs::File::create(&stdout_file).context("Failed to create stdout file")?;
    let stderr = fs::File::create(&stderr_file).context("Failed to create stderr file")?;

    let daemonize = Daemonize::new()
        .working_directory(&daemon_dir)
        .stdout(stdout)
        .stderr(stderr);

    daemonize.start().context("Failed to daemonize process")?;

    Ok(())
}

/// Start the daemon (called from CLI)
pub fn start(foreground: bool) -> Result<()> {
    // Try to acquire exclusive lock on PID file to prevent race conditions
    let pid_path = get_pid_file_path()?;
    let lock_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&pid_path)
        .context("Failed to open PID file for locking")?;

    // Try non-blocking lock - if it fails, another daemon holds it
    if lock_file.try_lock_exclusive().is_err() {
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
            let _ = lock_file.unlock();
            bail!("Daemon already running with PID {old_pid}");
        }
        tracing::info!("Removing stale PID file from previous crash...");
    }

    // Load config
    let config = Config::load()?;
    let scanner = Scanner::new(config.clone())?;

    if foreground {
        // Foreground mode: don't daemonize, run directly
        println!("Starting proc-janitor in foreground mode...");

        // Write PID file
        write_pid_file(std::process::id())?;

        // Create and start daemon
        let mut daemon = Daemon::new(config, scanner);
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
        let mut daemon = Daemon::new(config, scanner);
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
        } else {
            println!(
                "Warning: Daemon (PID: {}) did not terminate within {} seconds",
                pid,
                (DAEMON_STOP_MAX_POLLS as u64 * DAEMON_STOP_POLL_INTERVAL_MS) / 1000
            );
        }

        remove_pid_file()?;

        Ok(())
    } else {
        bail!("Daemon is not running (no PID file found)");
    }
}

/// Get daemon uptime as a human-readable string
fn get_daemon_uptime(pid: u32) -> Option<String> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::new()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

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

    if hours > 0 {
        Some(format!("{hours}h {minutes}m"))
    } else if minutes > 0 {
        Some(format!("{minutes}m {seconds}s"))
    } else {
        Some(format!("{seconds}s"))
    }
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
    entries.sort_by_key(|e| std::cmp::Reverse(e.path()));

    if let Some(entry) = entries.first() {
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(count);
            if !lines[start..].is_empty() {
                println!("\n  Recent logs:");
                for line in &lines[start..] {
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

    if json {
        let status = DaemonStatus {
            running,
            pid,
            stale_pid_file,
        };
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        let use_color = std::env::var("NO_COLOR").is_err()
            && supports_color::on(supports_color::Stream::Stdout).is_some();

        if running {
            if use_color {
                println!("{} proc-janitor daemon ({})", "●".green(), "running".green());
            } else {
                println!("● proc-janitor daemon (running)");
            }
            if let Some(pid) = pid {
                // Try to get process uptime
                let uptime_str = get_daemon_uptime(pid).unwrap_or_default();
                if uptime_str.is_empty() {
                    println!("  PID: {pid}");
                } else {
                    println!("  PID: {pid} | Uptime: {uptime_str}");
                }
            }

            // Show config summary
            if let Ok(config) = crate::config::Config::load() {
                println!("  Patterns: {} target(s), {} whitelisted", config.targets.len(), config.whitelist.len());
                println!("  Scan interval: {}s | Grace period: {}s", config.scan_interval, config.grace_period);
            }

            // Show last few log lines
            print_recent_logs(3);
        } else {
            if use_color {
                println!("{} proc-janitor daemon ({})", "●".dimmed(), "stopped".dimmed());
            } else {
                println!("● proc-janitor daemon (stopped)");
            }
            if stale_pid_file {
                if use_color {
                    println!("  {}", "Stale PID file found - daemon may have crashed".yellow());
                    println!("  Fix: Run 'proc-janitor stop' to clean up, then 'proc-janitor start'");
                } else {
                    println!("  Stale PID file found - daemon may have crashed");
                    println!("  Fix: Run 'proc-janitor stop' to clean up, then 'proc-janitor start'");
                }
            } else {
                println!("  Start with: proc-janitor start");
            }
        }
    }
    Ok(())
}
