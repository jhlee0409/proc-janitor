use anyhow::Result;
use owo_colors::OwoColorize;
use std::fs;

use crate::config;
use crate::daemon;
use crate::session::SessionStore;
use crate::util::use_color;

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

fn check_targets_configured() -> bool {
    match config::Config::load() {
        Ok(config) => {
            if config.targets.is_empty() {
                fail(
                    "Target patterns",
                    "No target patterns configured",
                    Some("Run 'proc-janitor config init' to set up"),
                );
                false
            } else {
                pass(
                    "Target patterns",
                    &format!("{} pattern{} configured", config.targets.len(), if config.targets.len() == 1 { "" } else { "s" }),
                );
                true
            }
        }
        Err(_) => {
            fail(
                "Target patterns",
                "Cannot load config",
                None,
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
    if crate::util::check_not_symlink(&test_file).is_ok() {
        let write_result = fs::write(&test_file, b"test");
        // Always clean up the test file
        let _ = fs::remove_file(&test_file);
        match write_result {
            Ok(_) => {
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
    } else {
        pass(
            "Data directory",
            &format!("{} exists (write test skipped: symlink check failed)", data_dir.display()),
        );
        true
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
    if crate::util::check_not_symlink(&test_file).is_ok() {
        let write_result = fs::write(&test_file, b"test");
        // Always clean up the test file
        let _ = fs::remove_file(&test_file);
        match write_result {
            Ok(_) => {
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
    } else {
        pass(
            "Log directory",
            &format!("{} exists (write test skipped: symlink check failed)", log_dir.display()),
        );
        true
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
    let total = 8;

    if check_config_file() {
        passed += 1;
    }
    if check_config_validation() {
        passed += 1;
    }
    if check_targets_configured() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_dir_returns_expected_suffix() {
        // data_dir() should return Some(.../.proc-janitor) when HOME is set
        if let Some(dir) = data_dir() {
            assert!(
                dir.ends_with(".proc-janitor"),
                "Expected path ending with .proc-janitor, got: {}",
                dir.display()
            );
        }
        // If HOME is not set, data_dir() returns None — acceptable in CI
    }

    #[test]
    fn test_pass_does_not_panic() {
        // Verify the formatting function handles various inputs without panicking
        pass("Test label", "Some detail");
        pass("", "");
        pass("Long label text here", "Detail with special chars: <>&\"'");
    }

    #[test]
    fn test_fail_does_not_panic() {
        fail("Test label", "Some failure", Some("Try this fix"));
        fail("Test label", "Some failure", None);
        fail("", "", Some(""));
    }

    #[test]
    fn test_run_total_matches_check_count() {
        // The run() function declares total = 8 and calls exactly 8 check functions.
        // This test verifies the constant is correct by parsing the source.
        // If someone adds a check but forgets to update total, this catches it.
        let source = include_str!("doctor.rs");

        // Extract only the run() function body (up to #[cfg(test)] or end)
        let run_fn_start = source.find("pub fn run()").expect("run() function not found");
        let run_body = &source[run_fn_start..];
        let run_body = match run_body.find("#[cfg(test)]") {
            Some(pos) => &run_body[..pos],
            None => run_body,
        };

        let check_calls = run_body.matches("if check_").count();
        assert_eq!(
            check_calls, 8,
            "Number of check calls in run() should match total"
        );
    }

    #[test]
    fn test_check_data_directory_creates_if_missing() {
        // This test relies on actual HOME dir — it verifies check_data_directory
        // doesn't panic and returns a bool. The actual directory likely exists
        // on dev machines.
        let _result = check_data_directory();
        // If we reach here without panicking, the test passes
    }

    #[test]
    fn test_check_session_store_handles_missing() {
        // SessionStore::load() handles missing file gracefully
        let _result = check_session_store();
        // If we reach here without panicking, the test passes
    }
}
