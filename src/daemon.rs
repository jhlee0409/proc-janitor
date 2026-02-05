use crate::config::Config;
use crate::scanner::{self, Scanner};
use crate::logger;
use anyhow::{Result, Context, bail};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::path::PathBuf;
use std::fs;
use daemonize::Daemonize;
use fs2::FileExt;

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
        let _ = cvar.wait_timeout(guard, duration).unwrap_or_else(|e| e.into_inner());
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
            eprintln!("Warning: Failed to initialize logger: {}", e);
            // Continue without file logging
        }

        // Cleanup old logs
        if let Err(e) = logger::cleanup_old_logs() {
            tracing::warn!("Failed to cleanup old logs: {}", e);
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
        println!("Daemon started. Scanning every {} seconds...", self.config.scan_interval);

        // Main loop - reuses self.scanner to preserve tracked state across cycles
        while self.running.load(Ordering::SeqCst) {
            if let Err(e) = scanner::scan_with_scanner(&mut self.scanner, true, sigterm_timeout) {
                eprintln!("Error scanning processes: {}", e);
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
    let home = std::env::var("HOME")
        .context("HOME environment variable not set")?;
    let pid_dir = PathBuf::from(home).join(".proc-janitor");

    // Create directory if it doesn't exist
    fs::create_dir_all(&pid_dir)
        .context("Failed to create PID directory")?;

    Ok(pid_dir.join("proc-janitor.pid"))
}

/// Write PID to file
fn write_pid_file(pid: u32) -> Result<()> {
    let pid_file = get_pid_file_path()?;
    fs::write(&pid_file, pid.to_string())
        .context("Failed to write PID file")?;
    Ok(())
}

/// Remove PID file
fn remove_pid_file() -> Result<()> {
    let pid_file = get_pid_file_path()?;
    if pid_file.exists() {
        fs::remove_file(&pid_file)
            .context("Failed to remove PID file")?;
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
    let home = std::env::var("HOME")
        .context("HOME environment variable not set")?;
    let daemon_dir = PathBuf::from(home).join(".proc-janitor");

    // Create directory if it doesn't exist
    fs::create_dir_all(&daemon_dir)
        .context("Failed to create daemon directory")?;

    let stdout_file = daemon_dir.join("daemon.out");
    let stderr_file = daemon_dir.join("daemon.err");

    let stdout = fs::File::create(&stdout_file)
        .context("Failed to create stdout file")?;
    let stderr = fs::File::create(&stderr_file)
        .context("Failed to create stderr file")?;

    let daemonize = Daemonize::new()
        .working_directory(&daemon_dir)
        .stdout(stdout)
        .stderr(stderr);

    daemonize.start()
        .context("Failed to daemonize process")?;

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
            bail!("Daemon already running with PID {}", old_pid);
        }
        bail!("Another daemon instance is starting");
    }

    // We have the lock - check if there's a stale PID
    if let Some(old_pid) = get_daemon_pid() {
        // Check if process exists using nix
        use nix::sys::signal::kill;
        use nix::unistd::Pid;

        let nix_pid = Pid::from_raw(
            i32::try_from(old_pid).context("PID exceeds i32 range")?
        );
        if kill(nix_pid, None).is_ok() {
            // Process exists and we have the lock - this shouldn't happen
            // but if it does, the other process doesn't hold the lock
            let _ = lock_file.unlock();
            bail!("Daemon already running with PID {}", old_pid);
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

        let nix_pid = NixPid::from_raw(
            i32::try_from(pid).context("PID exceeds i32 range")?
        );
        kill(nix_pid, Signal::SIGTERM)
            .with_context(|| format!("Failed to send SIGTERM to daemon (PID: {})", pid))?;

        println!("Sent SIGTERM to daemon (PID: {})", pid);

        // Poll for process termination (max 5 seconds, 100ms intervals)
        let max_wait = 50; // 50 * 100ms = 5 seconds
        let mut terminated = false;
        for _ in 0..max_wait {
            std::thread::sleep(Duration::from_millis(100));
            if kill(nix_pid, None).is_err() {
                // Process no longer exists
                terminated = true;
                break;
            }
        }

        if terminated {
            println!("Daemon stopped successfully (PID: {})", pid);
        } else {
            println!("Warning: Daemon (PID: {}) did not terminate within 5 seconds", pid);
        }

        remove_pid_file()?;

        Ok(())
    } else {
        bail!("Daemon is not running (no PID file found)");
    }
}

/// Show daemon status (called from CLI)
pub fn status() -> Result<()> {
    if is_daemon_running() {
        if let Some(pid) = get_daemon_pid() {
            println!("Daemon is running (PID: {})", pid);
        } else {
            println!("Daemon is running (PID unknown)");
        }
    } else {
        println!("Daemon is not running");

        // Check for stale PID file
        if get_daemon_pid().is_some() {
            println!("(Stale PID file found, daemon might have crashed)");
        }
    }
    Ok(())
}
