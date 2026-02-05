use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::{Config, LoggingConfig};

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

        // Only process log files
        if !file_path.is_file() {
            continue;
        }

        if let Some(ext) = file_path.extension() {
            if ext != "log" {
                continue;
            }
        } else {
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
        .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "log"))
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

    use std::io::BufRead;
    use std::collections::VecDeque;

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
        let mut file = fs::File::open(latest_log)
            .with_context(|| format!("Failed to open log file for following: {}", latest_log.display()))?;
        file.seek(SeekFrom::End(0))?;

        let mut reader = std::io::BufReader::new(file);

        println!("--- Following {} (Ctrl+C to stop) ---", latest_log.display());

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

        // Create some old log files
        let old_file = log_path.join("old.log");
        let mut f = File::create(&old_file)?;
        writeln!(f, "old log")?;

        // Set file time to 10 days ago
        let ten_days_ago =
            std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 24 * 60 * 60);
        filetime::set_file_mtime(
            &old_file,
            filetime::FileTime::from_system_time(ten_days_ago),
        )?;

        // Create a recent log file
        let recent_file = log_path.join("recent.log");
        let mut f = File::create(&recent_file)?;
        writeln!(f, "recent log")?;

        // Clean up logs older than 7 days
        cleanup_old_logs_with_params(log_path, 7)?;

        // Old file should be deleted
        assert!(!old_file.exists());
        // Recent file should still exist
        assert!(recent_file.exists());

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
