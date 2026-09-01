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
        Ok(cfg) => match cfg.validate() {
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
        },
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
                // How many live processes each pattern matches. Deliberately
                // informational, never a failure: "matches nothing" is exactly
                // what a correct config looks like when the target program simply
                // is not running right now, so it cannot be told apart from a
                // typo. Showing the counts lets the user make that call.
                let sys = crate::util::process_snapshot();
                let cmdlines: Vec<String> = sys
                    .processes()
                    .values()
                    .map(|p| {
                        p.cmd()
                            .iter()
                            .map(|s| s.to_string_lossy())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .collect();
                let unmatched: Vec<&String> = config
                    .targets
                    .iter()
                    .filter(|pattern| match crate::scanner::compile_pattern(pattern) {
                        Ok(re) => !cmdlines.iter().any(|c| re.is_match(c)),
                        Err(_) => false, // reported by the validation check
                    })
                    .collect();

                let detail = format!(
                    "{} pattern{} configured{}",
                    config.targets.len(),
                    if config.targets.len() == 1 { "" } else { "s" },
                    if unmatched.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "; matching no running process right now: {}",
                            unmatched
                                .iter()
                                .map(|p| format!("'{p}'"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                );
                pass("Target patterns", &detail);
                true
            }
        }
        Err(_) => {
            fail("Target patterns", "Cannot load config", None);
            false
        }
    }
}

/// Would the daemon's own command line match a target pattern?
///
/// The daemon refuses to signal itself (since 0.8.3), so this cannot make it
/// suicide — but a pattern broad enough to match `proc-janitor` will also match
/// *another* proc-janitor process, and is almost always a sign of a pattern like
/// `.*` that will take unrelated processes with it.
fn check_self_matching_patterns() -> bool {
    let Ok(config) = config::Config::load() else {
        fail("Self-match guard", "Cannot load config", None);
        return false;
    };
    if config.targets.is_empty() {
        pass("Self-match guard", "No target patterns to check");
        return true;
    }

    // The command line the daemon actually runs under, which is what the scanner
    // would test — not `doctor`'s own argv.
    let exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "proc-janitor".to_string());
    let daemon_cmdline = format!("{exe} start --foreground");

    let compile = |patterns: &[String]| -> Vec<regex::Regex> {
        patterns
            .iter()
            .filter_map(|p| crate::scanner::compile_pattern(p).ok())
            .collect()
    };
    let whitelist = compile(&config.whitelist);
    if crate::scanner::matches_any(&whitelist, &daemon_cmdline) {
        pass("Self-match guard", "proc-janitor is whitelisted");
        return true;
    }

    let offenders: Vec<&String> = config
        .targets
        .iter()
        .filter(|p| {
            crate::scanner::compile_pattern(p)
                .map(|re| re.is_match(&daemon_cmdline))
                .unwrap_or(false)
        })
        .collect();

    if offenders.is_empty() {
        pass("Self-match guard", "No pattern matches proc-janitor itself");
        return true;
    }

    fail(
        "Self-match guard",
        &format!(
            "these patterns match proc-janitor's own command line: {}",
            offenders
                .iter()
                .map(|p| format!("'{p}'"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Some("Narrow the pattern, or add 'proc-janitor' to the whitelist"),
    );
    false
}

/// The program path recorded in the installed service definition, if any.
///
/// Returns `(description, path)`. Parsing is intentionally minimal: the goal is
/// to read back the one path the installer wrote, not to implement plist or unit
/// file parsers.
fn supervisor_program() -> Option<(String, std::path::PathBuf)> {
    let home = dirs::home_dir()?;

    let plist = home
        .join("Library")
        .join("LaunchAgents")
        .join("com.proc-janitor.plist");
    if let Ok(text) = fs::read_to_string(&plist) {
        // First <string> naming an absolute path to the binary.
        let path = text
            .split("<string>")
            .skip(1)
            .filter_map(|chunk| chunk.split("</string>").next())
            .find(|value| value.starts_with('/') && value.contains("proc-janitor"));
        if let Some(path) = path {
            return Some(("LaunchAgent".to_string(), std::path::PathBuf::from(path)));
        }
    }

    let unit = home
        .join(".config")
        .join("systemd")
        .join("user")
        .join("proc-janitor.service");
    if let Ok(text) = fs::read_to_string(&unit) {
        let path = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("ExecStart="))
            .and_then(|value| value.split_whitespace().next());
        if let Some(path) = path {
            return Some(("systemd unit".to_string(), std::path::PathBuf::from(path)));
        }
    }

    None
}

/// Does the installed service still point at a binary that exists?
///
/// This is the "the install is silently broken" case: the unit or plist keeps the
/// absolute path it was written with, so moving or reinstalling the binary
/// elsewhere leaves the supervisor launching something that is no longer there —
/// launchd retries forever, systemd fails with 203/EXEC, and nothing cleans up.
fn check_supervisor_binary() -> bool {
    let Some((kind, path)) = supervisor_program() else {
        pass(
            "Service definition",
            "None installed (run manually or via brew)",
        );
        return true;
    };

    if !path.exists() {
        fail(
            "Service definition",
            &format!("{kind} points at {}, which does not exist", path.display()),
            Some("Reinstall the service so it points at the current binary"),
        );
        return false;
    }

    // Existing but different from the binary on PATH is legitimate (both may be
    // installed), so report it without failing.
    let on_path = which_proc_janitor();
    let detail = match &on_path {
        Some(p) if *p != path => format!(
            "{kind} runs {} (PATH resolves proc-janitor to {})",
            path.display(),
            p.display()
        ),
        _ => format!("{kind} runs {}", path.display()),
    };
    pass("Service definition", &detail);
    true
}

/// First `proc-janitor` on `PATH`.
fn which_proc_janitor() -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join("proc-janitor"))
        .find(|candidate| candidate.is_file())
}

/// Are `PROC_JANITOR_*` overrides set here but invisible to the daemon?
///
/// Environment overrides set in a shell profile apply to the CLI but not to a
/// launchd or systemd service, which does not inherit the shell's environment.
/// The result is `config env` showing one configuration and the daemon running
/// with another — a difference that is otherwise very hard to notice.
fn check_env_reaches_daemon() -> bool {
    let set_here: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| k.starts_with("PROC_JANITOR_"))
        .collect();

    if set_here.is_empty() {
        pass("Env overrides", "None set");
        return true;
    }

    let Some((kind, _)) = supervisor_program() else {
        pass(
            "Env overrides",
            &format!(
                "{} set; no service installed to diverge from",
                set_here.len()
            ),
        );
        return true;
    };

    // Read the service definition and see whether it carries them too.
    let home = dirs::home_dir();
    let definition = home
        .map(|h| {
            [
                h.join("Library")
                    .join("LaunchAgents")
                    .join("com.proc-janitor.plist"),
                h.join(".config")
                    .join("systemd")
                    .join("user")
                    .join("proc-janitor.service"),
            ]
        })
        .map(|paths| {
            paths
                .iter()
                .filter_map(|p| fs::read_to_string(p).ok())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    let missing: Vec<&String> = set_here
        .iter()
        .filter(|key| !definition.contains(key.as_str()))
        .collect();

    if missing.is_empty() {
        pass("Env overrides", &format!("{kind} carries all of them"));
        return true;
    }

    fail(
        "Env overrides",
        &format!(
            "set in this shell but absent from the {kind}, so the daemon does not see them: {}",
            missing
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Some("Put them in the service definition, or in the config file instead"),
    );
    false
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
            pass("Data directory", &format!("{} created", data_dir.display()));
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
            &format!(
                "{} exists (write test skipped: symlink check failed)",
                data_dir.display()
            ),
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
            &format!(
                "{} exists (write test skipped: symlink check failed)",
                log_dir.display()
            ),
        );
        true
    }
}

/// Files the service supervisor writes and owns: launchd's
/// `StandardOutPath`/`StandardErrorPath` and the `daemonize` redirects.
const SUPERVISOR_LOG_FILES: &[&str] = &["launchd.log", "launchd.err", "daemon.out", "daemon.err"];

const SUPERVISOR_LOG_WARN_BYTES: u64 = 10 * 1024 * 1024;

/// The rotating appender only manages `proc-janitor.<date>.log`, and retention
/// deliberately never unlinks the supervisor's files — the supervisor holds those
/// fds open for the daemon's whole lifetime, so deleting one would silently route
/// all further output to a deleted inode. They therefore grow without bound and
/// only the user can truncate them.
fn check_supervisor_logs() -> bool {
    let log_dir = match data_dir() {
        Some(d) => d.join("logs"),
        None => {
            fail(
                "Supervisor logs",
                "Cannot determine path (HOME not set)",
                Some("Set the HOME environment variable"),
            );
            return false;
        }
    };

    let mut oversized: Vec<(String, u64)> = Vec::new();
    let mut total = 0u64;
    for name in SUPERVISOR_LOG_FILES {
        let path = log_dir.join(name);
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        let len = meta.len();
        total += len;
        if len >= SUPERVISOR_LOG_WARN_BYTES {
            oversized.push(((*name).to_string(), len));
        }
    }

    let mib = |b: u64| format!("{:.1} MiB", b as f64 / (1024.0 * 1024.0));

    if oversized.is_empty() {
        pass(
            "Supervisor logs",
            &format!("{} (unrotated, not managed by retention)", mib(total)),
        );
        return true;
    }

    let detail = oversized
        .iter()
        .map(|(name, len)| format!("{name} is {}", mib(*len)))
        .collect::<Vec<_>>()
        .join(", ");
    let fix = format!(
        "Truncate in place (keeps the supervisor's open fd valid): {}",
        oversized
            .iter()
            .map(|(name, _)| format!(": > {}", log_dir.join(name).display()))
            .collect::<Vec<_>>()
            .join(" ; ")
    );
    fail("Supervisor logs", &detail, Some(&fix));
    false
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
                    pass(
                        "Session store",
                        "Not initialized (will be created on first use)",
                    );
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
                pass(
                    "Session store",
                    "Not initialized (will be created on first use)",
                );
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
    let total = 12;

    if check_config_file() {
        passed += 1;
    }
    if check_config_validation() {
        passed += 1;
    }
    if check_targets_configured() {
        passed += 1;
    }
    if check_self_matching_patterns() {
        passed += 1;
    }
    if check_supervisor_binary() {
        passed += 1;
    }
    if check_env_reaches_daemon() {
        passed += 1;
    }
    if check_data_directory() {
        passed += 1;
    }
    if check_log_directory() {
        passed += 1;
    }
    if check_supervisor_logs() {
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
        println!("{}", format!("{passed}/{total} checks passed").yellow());
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
        // `run()` declares `total` and then calls exactly that many check
        // functions. Both numbers are read out of the source so that adding a
        // check without updating `total` (or vice versa) fails here instead of
        // silently reporting "8/9 checks passed".
        let source = include_str!("doctor.rs");

        let run_fn_start = source
            .find("pub fn run()")
            .expect("run() function not found");
        let run_body = &source[run_fn_start..];
        let run_body = match run_body.find("#[cfg(test)]") {
            Some(pos) => &run_body[..pos],
            None => run_body,
        };

        let declared_total: usize = run_body
            .split("let total = ")
            .nth(1)
            .and_then(|rest| rest.split(';').next())
            .expect("`let total = N;` not found in run()")
            .trim()
            .parse()
            .expect("`total` is not a number");

        let check_calls = run_body.matches("if check_").count();
        assert_eq!(
            check_calls, declared_total,
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
