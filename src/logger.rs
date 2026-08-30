use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{Config, LoggingConfig};

/// True for a file produced by this process's rolling appender
/// (`proc-janitor.YYYY-MM-DD.log`).
///
/// Everything else in the log directory belongs to the service supervisor —
/// launchd's `StandardOutPath`/`StandardErrorPath` (`launchd.log`/`launchd.err`)
/// and the `daemonize` redirects (`daemon.out`/`daemon.err`). Those fds are held
/// open by launchd/systemd for the daemon's whole lifetime, so unlinking one
/// silently routes all further output to a deleted inode. They are the
/// supervisor's files: never rotate, delete, or tail them here.
fn is_rotating_log(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("proc-janitor.") && n.ends_with(".log"))
}

/// Initialize the logger (loads config automatically)
pub fn init_logger() -> Result<()> {
    let config = Config::load()?;
    init_logger_with_config(&config.logging)
}

/// Initialize the logger with the given configuration
fn init_logger_with_config(config: &LoggingConfig) -> Result<()> {
    if !config.enabled {
        // Simple stdout-only logger when disabled
        tracing_subscriber::fmt()
            .with_target(true)
            .with_level(true)
            .with_env_filter(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
            .try_init()
            .ok();
        return Ok(());
    }

    // Ensure log directory exists
    let log_path = PathBuf::from(&config.path);
    fs::create_dir_all(&log_path)
        .with_context(|| format!("Failed to create log directory: {}", log_path.display()))?;

    // Create file appender with daily rotation
    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("proc-janitor")
        .filename_suffix("log")
        .build(&log_path)
        .with_context(|| format!("Failed to create log file appender: {}", log_path.display()))?;

    // Create layers for both file and stdout
    let file_layer = fmt::layer()
        .with_writer(file_appender)
        .with_target(true)
        .with_level(true)
        .with_ansi(false);

    let stdout_layer = fmt::layer().with_target(true).with_level(true);

    // Initialize subscriber with both layers
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive(Level::INFO.into()))
        .with(file_layer)
        .with(stdout_layer)
        .try_init()
        .ok();

    // Clean up old logs
    cleanup_old_logs_with_params(&log_path, config.retention_days)?;

    tracing::info!("Logger initialized: {}", log_path.display());

    Ok(())
}

/// Clean up old log files based on retention policy
fn cleanup_old_logs_with_params(path: &Path, retention_days: u32) -> Result<()> {
    if retention_days == 0 {
        return Ok(()); // Never delete logs
    }

    let cutoff = chrono::Utc::now() - chrono::Duration::days(i64::from(retention_days));

    let entries = fs::read_dir(path)
        .with_context(|| format!("Failed to read log directory: {}", path.display()))?;

    let mut deleted_count = 0;

    for entry in entries {
        let entry = entry?;
        let file_path = entry.path();

        if !is_rotating_log(&file_path) {
            continue;
        }

        // Check file modification time
        let metadata = fs::metadata(&file_path)?;
        if let Ok(modified) = metadata.modified() {
            let modified_time = chrono::DateTime::<chrono::Utc>::from(modified);

            if modified_time < cutoff {
                match fs::remove_file(&file_path) {
                    Ok(_) => {
                        tracing::info!("Deleted old log file: {}", file_path.display());
                        deleted_count += 1;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to delete log file {}: {}", file_path.display(), e);
                    }
                }
            }
        }
    }

    if deleted_count > 0 {
        tracing::info!("Cleaned up {} old log file(s)", deleted_count);
    }

    Ok(())
}

/// Show logs (used by the CLI `logs` command)
pub fn show_logs(follow: bool, lines: u64) -> Result<()> {
    let config = crate::config::Config::load()?;
    let log_path = PathBuf::from(&config.logging.path);

    if !log_path.exists() {
        println!("No logs found at: {}", log_path.display());
        return Ok(());
    }

    // Find the most recent log file
    let entries = fs::read_dir(&log_path)
        .with_context(|| format!("Failed to read log directory: {}", log_path.display()))?;

    let mut log_files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| is_rotating_log(p))
        .collect();

    if log_files.is_empty() {
        println!("No log files found in: {}", log_path.display());
        return Ok(());
    }

    // Sort by modification time (newest first)
    log_files.sort_by(|a, b| {
        let a_time = fs::metadata(a).and_then(|m| m.modified()).ok();
        let b_time = fs::metadata(b).and_then(|m| m.modified()).ok();
        b_time.cmp(&a_time)
    });

    let latest_log = &log_files[0];

    // Read last N lines using ring buffer
    let file = fs::File::open(latest_log)
        .with_context(|| format!("Failed to open log file: {}", latest_log.display()))?;
    let reader = std::io::BufReader::new(&file);

    use std::collections::VecDeque;
    use std::io::BufRead;

    let max_lines = lines as usize;
    let mut last_lines: VecDeque<String> = VecDeque::with_capacity(max_lines + 1);

    for line in reader.lines() {
        match line {
            Ok(l) => {
                last_lines.push_back(l);
                if last_lines.len() > max_lines {
                    last_lines.pop_front();
                }
            }
            Err(_) => break,
        }
    }

    for line in &last_lines {
        println!("{line}");
    }

    if follow {
        use std::io::{Seek, SeekFrom};

        // Get current file size as our starting position
        let mut file = fs::File::open(latest_log).with_context(|| {
            format!(
                "Failed to open log file for following: {}",
                latest_log.display()
            )
        })?;
        file.seek(SeekFrom::End(0))?;

        let mut reader = std::io::BufReader::new(file);

        println!(
            "--- Following {} (Ctrl+C to stop) ---",
            latest_log.display()
        );

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // No new data, wait and retry
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Ok(_) => {
                    // Remove trailing newline for consistent output
                    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                    println!("{trimmed}");
                }
                Err(e) => {
                    eprintln!("Error reading log file: {e}");
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_cleanup_old_logs() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let log_path = temp_dir.path();

        let ten_days_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 24 * 60 * 60);
        let backdate = |p: &std::path::Path| -> Result<()> {
            filetime::set_file_mtime(p, filetime::FileTime::from_system_time(ten_days_ago))?;
            Ok(())
        };
        let touch = |name: &str| -> Result<std::path::PathBuf> {
            let p = log_path.join(name);
            let mut f = File::create(&p)?;
            writeln!(f, "{name}")?;
            Ok(p)
        };

        // Our own rotated file, old enough to expire.
        let old_file = touch("proc-janitor.2020-01-01.log")?;
        backdate(&old_file)?;

        // Our own current file.
        let recent_file = touch("proc-janitor.2999-12-31.log")?;

        // The supervisor's redirect targets. launchd/systemd hold these fds open
        // for the daemon's whole lifetime, so unlinking one would silently send
        // every later write to a deleted inode. They must survive regardless of
        // age, even though `launchd.log` ends in `.log`.
        let launchd_out = touch("launchd.log")?;
        let launchd_err = touch("launchd.err")?;
        let daemon_out = touch("daemon.out")?;
        backdate(&launchd_out)?;
        backdate(&launchd_err)?;
        backdate(&daemon_out)?;

        cleanup_old_logs_with_params(log_path, 7)?;

        assert!(!old_file.exists(), "expired rotated log should be deleted");
        assert!(recent_file.exists(), "current rotated log should survive");
        assert!(launchd_out.exists(), "launchd.log is not ours to delete");
        assert!(launchd_err.exists(), "launchd.err is not ours to delete");
        assert!(daemon_out.exists(), "daemon.out is not ours to delete");

        Ok(())
    }

    #[test]
    fn test_is_rotating_log_discriminates_supervisor_files() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let dir = temp_dir.path();
        for name in [
            "proc-janitor.2026-01-01.log",
            "launchd.log",
            "launchd.err",
            "daemon.out",
            "notes.txt",
        ] {
            File::create(dir.join(name))?;
        }

        assert!(is_rotating_log(&dir.join("proc-janitor.2026-01-01.log")));
        assert!(!is_rotating_log(&dir.join("launchd.log")));
        assert!(!is_rotating_log(&dir.join("launchd.err")));
        assert!(!is_rotating_log(&dir.join("daemon.out")));
        assert!(!is_rotating_log(&dir.join("notes.txt")));
        // A directory named like a log file is not a log file.
        fs::create_dir(dir.join("proc-janitor.dir.log"))?;
        assert!(!is_rotating_log(&dir.join("proc-janitor.dir.log")));

        Ok(())
    }

    #[test]
    fn test_logger_init_disabled() -> Result<()> {
        let config = LoggingConfig {
            enabled: false,
            path: "/tmp/test-logs".to_string(),
            retention_days: 7,
        };

        // Should not panic
        init_logger_with_config(&config)?;

        Ok(())
    }
}
