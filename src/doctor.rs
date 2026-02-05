use anyhow::Result;
use owo_colors::OwoColorize;
use std::fs;

use crate::config;
use crate::daemon;
use crate::session::SessionStore;

fn use_color() -> bool {
    std::env::var("NO_COLOR").is_err()
        && supports_color::on(supports_color::Stream::Stdout).is_some()
}

fn pass(label: &str, detail: &str) {
    if use_color() {
        println!("  {} {:<22} {}", "✓".green(), label, detail);
    } else {
        println!("  ✓ {label:<22} {detail}");
    }
}

fn fail(label: &str, detail: &str, fix: Option<&str>) {
    if use_color() {
        println!("  {} {:<22} {}", "✗".red(), label, detail);
    } else {
        println!("  ✗ {label:<22} {detail}");
    }
    if let Some(fix) = fix {
        println!("  {:<25} Fix: {}", "", fix);
    }
}

/// Get the data directory path (~/.proc-janitor/)
fn data_dir() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".proc-janitor"))
}

fn check_config_file() -> bool {
    match config::config_path() {
        Ok(config_path) => {
            if config_path.exists() {
                pass(
                    "Config file",
                    &format!("Found at {}", config_path.display()),
                );
                true
            } else {
                fail(
                    "Config file",
                    &format!("Not found: {}", config_path.display()),
                    Some("Run 'proc-janitor config init' to create it"),
                );
                false
            }
        }
        Err(_) => {
            fail(
                "Config file",
                "Cannot determine config path (HOME not set)",
                Some("Set the HOME environment variable"),
            );
            false
        }
    }
}

fn check_config_validation() -> bool {
    match config::Config::load() {
        Ok(cfg) => {
            match cfg.validate() {
                Ok(_) => {
                    let pattern_count = cfg.targets.len() + cfg.whitelist.len();
                    pass(
                        "Config validation",
                        &format!("All {pattern_count} patterns valid"),
                    );
                    true
                }
                Err(e) => {
                    fail(
                        "Config validation",
                        &format!("Invalid pattern: {e}"),
                        Some("Fix regex patterns in config.toml"),
                    );
                    false
                }
            }
        }
        Err(e) => {
            fail(
                "Config validation",
                &format!("Failed to load: {e}"),
                Some("Check config.toml syntax"),
            );
            false
        }
    }
}

fn check_data_directory() -> bool {
    let data_dir = match data_dir() {
        Some(d) => d,
        None => {
            fail(
                "Data directory",
                "Cannot determine path (HOME not set)",
                Some("Set the HOME environment variable"),
            );
            return false;
        }
    };

    if !data_dir.exists() {
        if fs::create_dir_all(&data_dir).is_ok() {
            pass(
                "Data directory",
                &format!("{} created", data_dir.display()),
            );
            return true;
        } else {
            fail(
                "Data directory",
                &format!("Cannot create {}", data_dir.display()),
                Some("Check filesystem permissions"),
            );
            return false;
        }
    }

    // Check if writable
    let test_file = data_dir.join(".write_test");
    match fs::write(&test_file, b"test") {
        Ok(_) => {
            let _ = fs::remove_file(&test_file);
            pass(
                "Data directory",
                &format!("{} exists and writable", data_dir.display()),
            );
            true
        }
        Err(_) => {
            fail(
                "Data directory",
                &format!("{} exists but not writable", data_dir.display()),
                Some("Check directory permissions"),
            );
            false
        }
    }
}

fn check_log_directory() -> bool {
    let log_dir = match dirs::home_dir() {
        Some(h) => h.join(".proc-janitor").join("logs"),
        None => {
            fail(
                "Log directory",
                "Cannot determine path (HOME not set)",
                Some("Set the HOME environment variable"),
            );
            return false;
        }
    };

    if !log_dir.exists() {
        fail(
            "Log directory",
            &format!("Not found: {}", log_dir.display()),
            Some("Run 'proc-janitor start' to create it"),
        );
        return false;
    }

    // Check if writable
    let test_file = log_dir.join(".write_test");
    match fs::write(&test_file, b"test") {
        Ok(_) => {
            let _ = fs::remove_file(&test_file);
            pass(
                "Log directory",
                &format!("{} exists and writable", log_dir.display()),
            );
            true
        }
        Err(_) => {
            fail(
                "Log directory",
                &format!("{} exists but not writable", log_dir.display()),
                Some("Check directory permissions"),
            );
            false
        }
    }
}

fn check_pid_file() -> bool {
    let pid_file = match dirs::home_dir() {
        Some(h) => h.join(".proc-janitor").join("proc-janitor.pid"),
        None => {
            fail(
                "PID file",
                "Cannot determine path (HOME not set)",
                Some("Set the HOME environment variable"),
            );
            return false;
        }
    };

    if !pid_file.exists() {
        pass("PID file", "No stale PID file");
        return true;
    }

    // PID file exists, check if the process is alive
    if daemon::is_daemon_running() {
        if let Some(pid) = daemon::get_daemon_pid() {
            pass("PID file", &format!("Valid (daemon PID: {pid})"));
        } else {
            pass("PID file", "Valid");
        }
        true
    } else {
        fail(
            "PID file",
            "Stale PID file (daemon not running)",
            Some("Run 'proc-janitor stop' to clean up"),
        );
        false
    }
}

fn check_daemon() -> bool {
    if daemon::is_daemon_running() {
        if let Some(pid) = daemon::get_daemon_pid() {
            pass("Daemon", &format!("Running (PID: {pid})"));
        } else {
            pass("Daemon", "Running");
        }
        true
    } else {
        fail(
            "Daemon",
            "Not running",
            Some("Run 'proc-janitor start' to start it"),
        );
        false
    }
}

fn check_session_store() -> bool {
    match SessionStore::load() {
        Ok(store) => {
            let count = store.sessions.len();
            if count == 0 {
                pass("Session store", "Valid (no sessions)");
            } else {
                pass(
                    "Session store",
                    &format!(
                        "Valid ({} session{})",
                        count,
                        if count == 1 { "" } else { "s" }
                    ),
                );
            }
            true
        }
        Err(_) => {
            // Check if the file even exists
            let sessions_file = match data_dir() {
                Some(d) => d.join("sessions.json"),
                None => {
                    pass("Session store", "Not initialized (will be created on first use)");
                    return true;
                }
            };
            if sessions_file.exists() {
                fail(
                    "Session store",
                    "Invalid JSON",
                    Some("Run any session command to auto-recover, or remove sessions.json"),
                );
                false
            } else {
                pass("Session store", "Not initialized (will be created on first use)");
                true
            }
        }
    }
}

pub fn run() -> Result<()> {
    println!("proc-janitor doctor");
    println!("==================");
    println!();

    let mut passed = 0;
    let total = 7;

    if check_config_file() {
        passed += 1;
    }
    if check_config_validation() {
        passed += 1;
    }
    if check_data_directory() {
        passed += 1;
    }
    if check_log_directory() {
        passed += 1;
    }
    if check_pid_file() {
        passed += 1;
    }
    if check_daemon() {
        passed += 1;
    }
    if check_session_store() {
        passed += 1;
    }

    println!();
    if passed == total {
        if use_color() {
            println!("{}", format!("{passed}/{total} checks passed").green());
        } else {
            println!("{passed}/{total} checks passed");
        }
    } else if use_color() {
        println!(
            "{}",
            format!("{passed}/{total} checks passed").yellow()
        );
    } else {
        println!("{passed}/{total} checks passed");
    }

    Ok(())
}
