use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

extern crate libc;

fn binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps
    path.push("proc-janitor");
    path
}

/// A private `$HOME` for a single test.
///
/// Every path proc-janitor touches is derived from `$HOME`:
/// `~/.config/proc-janitor/config.toml` and
/// `~/.proc-janitor/{proc-janitor.pid,sessions.json,stats.jsonl,logs/}`.
/// Running against the developer's real home made these tests mutate live state
/// and race each other — a test that starts a daemon writes the PID file that
/// `test_reload_when_not_running` asserts is absent, so the suite failed
/// intermittently under the default test parallelism.
fn sandbox() -> TempDir {
    tempfile::tempdir().expect("Failed to create sandbox HOME")
}

/// A `proc-janitor` invocation pinned to a sandboxed `$HOME`.
fn pj(home: &TempDir) -> Command {
    let mut cmd = Command::new(binary_path());
    cmd.env("HOME", home.path());
    cmd
}

#[test]
fn test_help_command() {
    let home = sandbox();
    let output = pj(&home)
        .arg("--help")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("proc-janitor"));
    assert!(stdout.contains("process") || stdout.contains("daemon"));
}

#[test]
fn test_config_show() {
    let home = sandbox();
    let output = pj(&home)
        .arg("config")
        .arg("show")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("scan_interval"));
}

#[test]
fn test_scan_command() {
    let home = sandbox();
    let output = pj(&home)
        .arg("scan")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_scan_json_output() {
    let home = sandbox();
    let output = pj(&home)
        .arg("--json")
        .arg("scan")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Look for JSON in either stdout or stderr
    let json_output = if !stdout.is_empty() && stdout.trim_start().starts_with('{') {
        &stdout
    } else if !stderr.is_empty() && stderr.contains('{') {
        &stderr
    } else {
        // If no JSON found, scan might output text - this is acceptable
        return;
    };

    // Find the JSON object in the output (may be preceded by non-JSON text)
    let json_start = json_output.find('{');
    let json_end = json_output.rfind('}'); // Use rfind for the LAST closing brace
    if let (Some(start), Some(end)) = (json_start, json_end) {
        if end > start {
            let json_str = &json_output[start..=end];
            let result: serde_json::Value =
                serde_json::from_str(json_str).expect("Failed to parse scan JSON output");
            assert!(
                result.get("orphans").is_some(),
                "JSON should have 'orphans' field"
            );
            assert!(
                result.get("orphan_count").is_some(),
                "JSON should have 'orphan_count' field"
            );
        }
    }
}

#[test]
fn test_status_command() {
    let home = sandbox();
    let output = pj(&home)
        .arg("status")
        .output()
        .expect("Failed to execute command");

    // Status can fail if daemon not running, but should not crash
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("not running")
            || stdout.contains("running")
            || stdout.contains("stopped")
            || stderr.contains("not running")
            || stderr.contains("stopped")
    );
}

#[test]
fn test_session_list() {
    let home = sandbox();
    let output = pj(&home)
        .arg("session")
        .arg("list")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_tree_command() {
    let home = sandbox();
    let output = pj(&home)
        .arg("tree")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_clean_command() {
    let home = sandbox();
    let output = pj(&home)
        .arg("clean")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_clean_dry_run() {
    // Dry-run must never kill anything and must succeed regardless of state.
    let home = sandbox();
    let output = pj(&home)
        .args(["clean", "--dry-run"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Either there are matches ("[DRY-RUN] ... would be killed") or none.
    assert!(combined.contains("DRY-RUN") || combined.contains("would be killed"));
}

#[test]
fn test_clean_dry_run_json() {
    let home = sandbox();
    let output = pj(&home)
        .args(["--json", "clean", "--dry-run"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // JSON summary must expose the dry_run flag set to true.
    assert!(stdout.contains("\"dry_run\": true"));
}

#[test]
fn test_clean_with_pid_filter() {
    let home = sandbox();
    let output = pj(&home)
        .args(["clean", "--pid", "99999"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_clean_with_pattern_filter() {
    let home = sandbox();
    let output = pj(&home)
        .args(["clean", "--pattern", "nonexistent_process_xyz"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_version_command() {
    let home = sandbox();
    let output = pj(&home)
        .arg("version")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("proc-janitor"));
    assert!(stdout.contains("MIT"));
}

#[test]
fn test_config_validate() {
    let home = sandbox();
    let output = pj(&home)
        .args(["config", "validate"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // Either valid config or no config file (a sandboxed HOME has none)
    assert!(
        combined.contains("valid") || combined.contains("Valid") || combined.contains("not found"),
        "Expected validation output, got: {combined}"
    );
}

#[test]
fn test_doctor_command() {
    let home = sandbox();
    let output = pj(&home)
        .arg("doctor")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_daemon_foreground_dry_run() {
    // Start daemon in foreground + dry-run, kill it after 2 seconds
    let home = sandbox();
    let child = pj(&home)
        .args(["start", "--foreground", "--dry-run"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start daemon");

    std::thread::sleep(std::time::Duration::from_secs(2));

    // Send SIGTERM to stop gracefully
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }

    let output = child.wait_with_output().expect("Failed to wait for daemon");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // Should have started and stopped gracefully
    assert!(
        combined.contains("DRY-RUN")
            || combined.contains("foreground")
            || combined.contains("Daemon"),
        "Expected daemon output, got: {combined}"
    );
}

#[test]
fn test_scan_quiet_mode() {
    let home = sandbox();
    let output = pj(&home)
        .args(["--quiet", "scan"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    // Quiet mode should not contain hints or spinners
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Use 'proc-janitor"));
}

#[test]
fn test_clean_quiet_mode() {
    let home = sandbox();
    let output = pj(&home)
        .args(["--quiet", "clean"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_restart_when_not_running() {
    // Restart when daemon isn't running should just start (or fail gracefully)
    let home = sandbox();
    let output = pj(&home)
        .args(["restart", "--foreground", "--dry-run"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start");

    std::thread::sleep(std::time::Duration::from_secs(2));
    unsafe {
        libc::kill(output.id() as i32, libc::SIGTERM);
    }
    let result = output.wait_with_output().expect("Failed to wait");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        combined.contains("Restart") || combined.contains("DRY-RUN") || combined.contains("Daemon"),
        "Expected restart output, got: {combined}"
    );
}

#[test]
fn test_reload_when_not_running() {
    let home = sandbox();
    let output = pj(&home)
        .arg("reload")
        .output()
        .expect("Failed to execute command");

    // Should fail gracefully when daemon not running
    assert!(
        !output.status.success() || {
            let stderr = String::from_utf8_lossy(&output.stderr);
            stderr.contains("not running")
        }
    );
}

#[test]
fn test_stats_command() {
    let home = sandbox();
    let output = pj(&home)
        .args(["stats", "--days", "7"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Either shows stats or "No cleanup statistics"
    assert!(
        stdout.contains("Statistics") || stdout.contains("No cleanup"),
        "Expected stats output, got: {stdout}"
    );
}

#[test]
fn test_stats_json() {
    let home = sandbox();
    let output = pj(&home)
        .args(["--json", "stats"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should be valid JSON
    let _: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| panic!("Expected valid JSON, got: {stdout}"));
}

#[test]
fn test_clean_min_age() {
    let home = sandbox();
    let output = pj(&home)
        .args(["clean", "--min-age", "999999"])
        .output()
        .expect("Failed to execute command");

    // With min_age very high, nothing should be cleaned
    assert!(output.status.success());
}

#[test]
fn test_tree_with_pattern() {
    let home = sandbox();
    let output = pj(&home)
        .args(["tree", "--pattern", "nonexistent_xyz"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No processes matching") || stdout.contains("nonexistent_xyz"));
}

/// Regression test for the reload path: a config reload must not restart every
/// tracked orphan's grace period.
///
/// The daemon used to replace its `Scanner` wholesale on reload, dropping the
/// `first_seen` timestamps with it, so a config file touched more often than
/// `grace_period` postponed cleanup forever. Here the config is touched every
/// second while `grace_period` is 3s; the orphan must still be cleaned.
#[test]
fn test_reload_preserves_grace_period() {
    let home = sandbox();
    let cfg_dir = home.path().join(".config").join("proc-janitor");
    std::fs::create_dir_all(&cfg_dir).expect("Failed to create config dir");
    let cfg_path = cfg_dir.join("config.toml");

    // A unique marker so the pattern cannot match anything but our own child.
    let marker = format!("pj_reload_probe_{}", std::process::id());
    std::fs::write(
        &cfg_path,
        format!(
            "scan_interval = 1\n\
             grace_period = 3\n\
             sigterm_timeout = 2\n\
             targets = [\"{marker}\"]\n\
             whitelist = []\n\
             \n\
             [logging]\n\
             enabled = false\n\
             path = \"{}\"\n\
             retention_days = 7\n",
            home.path().join(".proc-janitor").join("logs").display()
        ),
    )
    .expect("Failed to write config");

    // An orphan (PPID=1) carrying the marker in its cmdline: a shell that
    // double-forks so the sleeping grandchild is reparented to init/launchd.
    // `: MARKER` keeps the marker in the inner shell's own cmdline and stops the
    // shell from exec'ing away (a lone simple command would replace the shell).
    let spawner = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "( sh -c 'sleep 30; : {marker}' >/dev/null 2>&1 & )"
        ))
        .status()
        .expect("Failed to spawn orphan");
    assert!(spawner.success(), "orphan spawner failed");

    // Let the intermediate subshell exit so the probe is reparented to PID 1.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let probe = Command::new("pgrep")
        .args(["-f", &marker])
        .output()
        .expect("Failed to run pgrep");
    assert!(
        !String::from_utf8_lossy(&probe.stdout).trim().is_empty(),
        "probe orphan did not start"
    );

    let daemon = pj(&home)
        .args(["start", "--foreground"])
        // In a container every process has PPID=1, so the daemon refuses to act.
        // The target pattern here is a marker unique to this test's own probe, so
        // overriding the guard cannot touch anything else.
        .env("PROC_JANITOR_ALLOW_CONTAINER", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start daemon");

    // Touch the config once per second for 8s: more often than grace_period.
    for _ in 0..8 {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let _ = filetime::set_file_mtime(&cfg_path, filetime::FileTime::now());
    }

    unsafe {
        libc::kill(daemon.id() as i32, libc::SIGTERM);
    }
    let out = daemon
        .wait_with_output()
        .expect("Failed to wait for daemon");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Reap the probe (and any leftovers) before asserting, so a failing
    // assertion never leaves a stray process behind.
    let survivors = Command::new("pgrep")
        .args(["-f", &marker])
        .output()
        .expect("Failed to run pgrep");
    let survivors = String::from_utf8_lossy(&survivors.stdout);
    for pid in survivors.split_whitespace() {
        if let Ok(pid) = pid.parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }

    // Make sure the scenario actually exercised the reload path.
    assert!(
        combined.contains("Config reloaded"),
        "expected at least one reload, got: {combined}"
    );
    assert!(
        combined.contains("terminated"),
        "orphan was never cleaned despite repeated reloads; daemon output: {combined}"
    );
    assert!(
        survivors.trim().is_empty(),
        "orphan survived repeated config reloads (pids: {})",
        survivors.trim()
    );
}

/// Count processes whose command line contains `marker`.
fn marker_count(marker: &str) -> usize {
    let out = Command::new("pgrep")
        .args(["-f", marker])
        .output()
        .expect("Failed to run pgrep");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .count()
}

fn kill_marker(marker: &str) {
    let out = Command::new("pgrep")
        .args(["-f", marker])
        .output()
        .expect("Failed to run pgrep");
    for pid in String::from_utf8_lossy(&out.stdout).split_whitespace() {
        if let Ok(pid) = pid.parse::<i32>() {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

/// `exec` must terminate the command's tree when its own parent dies.
///
/// This is the guarantee the subcommand exists to provide — macOS has no
/// `PR_SET_PDEATHSIG` — so it is exercised against real processes:
///
/// ```text
/// sh (intermediate) ──▶ proc-janitor exec ──▶ sh (marker) ──▶ sleep
/// ```
///
/// The intermediate `sh` is SIGKILLed, so it gets no chance to clean up after
/// itself: anything that dies afterwards died because `exec` killed it.
#[test]
fn test_exec_kills_command_when_parent_dies() {
    let home = sandbox();
    let marker = format!("pjexec_parent_{}", std::process::id());
    let binary = binary_path();

    // The trailing `; :` stops `sh` from exec'ing away, so it stays alive as the
    // parent of `proc-janitor exec`.
    let mut intermediate = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{} exec -- sh -c 'sleep 30; : {marker}' ; :",
            binary.display()
        ))
        .env("HOME", home.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn the intermediate shell");

    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert!(
        marker_count(&marker) > 0,
        "the supervised command never started"
    );

    // Terminal vanishes.
    unsafe {
        libc::kill(intermediate.id() as i32, libc::SIGKILL);
    }
    let _ = intermediate.wait();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut remaining = marker_count(&marker);
    while remaining > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(200));
        remaining = marker_count(&marker);
    }

    kill_marker(&marker);
    assert_eq!(
        remaining, 0,
        "the supervised command outlived its terminal: {remaining} process(es) still matching {marker}"
    );
}

/// `exec` must take the command down when *it* is told to stop, not only when its
/// parent dies.
///
/// A `kill` aimed at the wrapper (`kill <pid>`, `pkill -f proc-janitor`, a service
/// manager stopping the unit) used to kill the wrapper alone and leave the command
/// running with PPID=1 — precisely the state this subcommand exists to prevent.
/// Here the parent shell stays alive, so nothing but `exec` itself can be
/// responsible for the cleanup.
#[test]
fn test_exec_kills_command_when_signalled_itself() {
    let home = sandbox();
    let marker = format!("pjexec_signalled_{}", std::process::id());
    let binary = binary_path();

    let mut intermediate = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{} exec -- sh -c 'sleep 30; : {marker}' ; :",
            binary.display()
        ))
        .env("HOME", home.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn the intermediate shell");

    std::thread::sleep(std::time::Duration::from_millis(1200));
    assert!(
        marker_count(&marker) > 0,
        "the supervised command never started"
    );

    // Find the wrapper: the only child of the intermediate shell.
    let pgrep = Command::new("pgrep")
        .args(["-P", &intermediate.id().to_string()])
        .output()
        .expect("Failed to run pgrep");
    let wrapper: i32 = String::from_utf8_lossy(&pgrep.stdout)
        .split_whitespace()
        .next()
        .expect("no proc-janitor exec process under the intermediate shell")
        .parse()
        .expect("pgrep returned a non-numeric pid");

    // Signal the wrapper only. The parent shell is untouched and still running.
    unsafe {
        libc::kill(wrapper, libc::SIGTERM);
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut remaining = marker_count(&marker);
    while remaining > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(200));
        remaining = marker_count(&marker);
    }

    let parent_alive = unsafe { libc::kill(intermediate.id() as i32, 0) } == 0;
    kill_marker(&marker);
    unsafe {
        libc::kill(intermediate.id() as i32, libc::SIGKILL);
    }
    let _ = intermediate.wait();

    assert!(
        parent_alive,
        "the test is invalid: the parent shell died, so parent-death cleanup could \
         explain the result"
    );
    assert_eq!(
        remaining, 0,
        "the command survived a SIGTERM aimed at `proc-janitor exec` itself: \
         {remaining} process(es) still matching {marker}"
    );
}

/// The complement: while the parent is alive, `exec` must stay out of the way and
/// pass the command's exit status through unchanged.
#[test]
fn test_exec_is_transparent_while_parent_lives() {
    let home = sandbox();
    let output = pj(&home)
        .args(["exec", "--", "sh", "-c", "printf hello; exit 7"])
        .output()
        .expect("Failed to run exec");

    assert_eq!(
        output.status.code(),
        Some(7),
        "exec must propagate the command's exit code"
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello");
}

#[test]
fn test_exec_requires_a_command() {
    let home = sandbox();
    let output = pj(&home).arg("exec").output().expect("Failed to run exec");
    assert!(
        !output.status.success(),
        "exec with no command must fail instead of doing nothing"
    );
}

/// How the daemon learns that a process became an orphan.
///
/// On kqueue platforms it is an event: the daemon registers `NOTE_EXIT` on the
/// parents of target-matching processes, so killing the parent must clean the
/// orphan within seconds even with a 60s scan interval. If that path regressed
/// to plain polling, the test would need a full minute and fail.
///
/// Elsewhere there is no unprivileged way to be told an arbitrary PID exited, so
/// `ExitWaiter` is the plain interval sleep and reacting *before* the next scan
/// is not something the platform can offer. Asserting it there would be a false
/// claim, so the interval is shortened and the test degrades to what is actually
/// guaranteed: the orphan is cleaned on a subsequent scan.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
const SCAN_INTERVAL: u64 = 60;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
const SCAN_INTERVAL: u64 = 3;

#[test]
fn test_daemon_reacts_before_the_next_scan() {
    let home = sandbox();
    let cfg_dir = home.path().join(".config").join("proc-janitor");
    std::fs::create_dir_all(&cfg_dir).expect("Failed to create config dir");
    let cfg_path = cfg_dir.join("config.toml");

    let marker = format!("pjevent_probe_{}", std::process::id());
    std::fs::write(
        &cfg_path,
        format!(
            "scan_interval = {SCAN_INTERVAL}\n\
             grace_period = 0\n\
             sigterm_timeout = 2\n\
             targets = [\"{marker}\"]\n\
             whitelist = []\n\
             \n\
             [logging]\n\
             enabled = false\n\
             path = \"{}\"\n\
             retention_days = 7\n",
            home.path().join(".proc-janitor").join("logs").display()
        ),
    )
    .expect("Failed to write config");

    // A live parent holding a target-matching child. The daemon should register
    // `NOTE_EXIT` on the parent during its first scan.
    let mut parent = Command::new("sh")
        .arg("-c")
        .arg(format!("sh -c 'sleep 25; : {marker}' & sleep 120"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn the probe parent");

    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(marker_count(&marker) > 0, "the probe child never started");

    let daemon = pj(&home)
        .args(["start", "--foreground"])
        .env("PROC_JANITOR_ALLOW_CONTAINER", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to start daemon");

    // Let the first scan complete so the parent is registered for watching.
    std::thread::sleep(std::time::Duration::from_secs(2));

    // The terminal dies.
    let killed_at = std::time::Instant::now();
    unsafe {
        libc::kill(parent.id() as i32, libc::SIGKILL);
    }
    let _ = parent.wait();

    // Generous for the event path (milliseconds) and for a couple of ticks on
    // platforms that only poll.
    let budget = std::time::Duration::from_secs(15);
    let deadline = killed_at + budget;
    let mut child_procs = marker_count(&marker);
    while child_procs > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
        child_procs = marker_count(&marker);
    }
    let reacted_in = killed_at.elapsed();

    unsafe {
        libc::kill(daemon.id() as i32, libc::SIGTERM);
    }
    let out = daemon
        .wait_with_output()
        .expect("Failed to wait for daemon");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    kill_marker(&marker);

    let mechanism = if cfg!(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    )) {
        "kqueue NOTE_EXIT on the parent should have fired in milliseconds"
    } else {
        "this platform polls, so cleanup should happen on a subsequent scan"
    };
    assert_eq!(
        child_procs, 0,
        "orphan not cleaned within {budget:?} at scan_interval={SCAN_INTERVAL}s — \
         {mechanism}. Daemon output: {combined}"
    );
    assert!(
        reacted_in < budget,
        "reaction took {reacted_in:?}, expected under {budget:?} ({mechanism})"
    );
}

/// Write a config whose only target pattern is `marker`.
fn write_config(home: &TempDir, marker: &str) -> std::path::PathBuf {
    let cfg_dir = home.path().join(".config").join("proc-janitor");
    std::fs::create_dir_all(&cfg_dir).expect("Failed to create config dir");
    let cfg_path = cfg_dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "scan_interval = 5\n\
             grace_period = 0\n\
             sigterm_timeout = 2\n\
             targets = [\"{marker}\"]\n\
             whitelist = []\n\
             \n\
             [logging]\n\
             enabled = false\n\
             path = \"{}\"\n\
             retention_days = 7\n",
            home.path().join(".proc-janitor").join("logs").display()
        ),
    )
    .expect("Failed to write config");
    cfg_path
}

/// `session clean` on a session with nothing tracked must clean the parent's
/// target-matching descendants.
///
/// Without this the shell integration was ceremony: it registered a session and
/// ran `session clean` on shell exit, which had no tracked PIDs and therefore
/// killed nothing.
#[test]
fn test_session_clean_falls_back_to_target_patterns() {
    let home = sandbox();
    let marker = format!("pjsess_hit_{}", std::process::id());
    write_config(&home, &marker);

    // This test process stands in for the terminal: the probe is its child, so
    // `--parent-pid` points at something with a matching descendant.
    let mut probe = Command::new("sh")
        .arg("-c")
        .arg(format!("sleep 30; : {marker}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn the probe");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(marker_count(&marker) > 0, "probe did not start");

    let out = pj(&home)
        .args([
            "session",
            "register",
            "--id",
            "s1",
            "--source",
            "terminal",
            "--parent-pid",
            &std::process::id().to_string(),
        ])
        .output()
        .expect("register failed");
    assert!(out.status.success(), "register did not succeed");

    let out = pj(&home)
        .args(["session", "clean", "s1"])
        .output()
        .expect("clean failed");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while marker_count(&marker) > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let remaining = marker_count(&marker);
    kill_marker(&marker);
    let _ = probe.kill();
    let _ = probe.wait();

    assert_eq!(
        remaining, 0,
        "untracked session did not clean the matching descendant. Output: {combined}"
    );
}

/// The safety property of that fallback: with nothing tracked, a process the
/// target patterns do **not** match must survive.
///
/// `session clean` kills explicitly tracked PIDs without pattern filtering,
/// because naming a PID is consent. The fallback has no such consent, so it must
/// not become "kill everything in the terminal" — that would bypass the
/// target/whitelist model the rest of the tool is built on.
#[test]
fn test_session_clean_fallback_spares_unmatched_processes() {
    let home = sandbox();
    // The config targets this marker...
    let target_marker = format!("pjsess_t_{}", std::process::id());
    write_config(&home, &target_marker);
    // ...while the probe carries a different one, so it must not be touched.
    let bystander = format!("pjsess_bystander_{}", std::process::id());

    let mut probe = Command::new("sh")
        .arg("-c")
        .arg(format!("sleep 30; : {bystander}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn the bystander");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(marker_count(&bystander) > 0, "bystander did not start");

    assert!(pj(&home)
        .args([
            "session",
            "register",
            "--id",
            "s2",
            "--source",
            "terminal",
            "--parent-pid",
            &std::process::id().to_string(),
        ])
        .output()
        .expect("register failed")
        .status
        .success());

    let out = pj(&home)
        .args(["session", "clean", "s2"])
        .output()
        .expect("clean failed");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    std::thread::sleep(std::time::Duration::from_millis(1500));
    let survived = marker_count(&bystander) > 0;
    kill_marker(&bystander);
    let _ = probe.kill();
    let _ = probe.wait();

    assert!(
        survived,
        "the fallback killed a process no target pattern matches — it must not \
         bypass the target/whitelist model. Output: {combined}"
    );
}

/// `AGENTS.md` states: "Never introduce `unsafe` code or new `unwrap()` calls".
///
/// That rule was broken silently once — two `unsafe` blocks reached a release
/// before anyone noticed — so it is pinned here rather than left to review. A
/// stated invariant that nothing checks is a preference, not a rule.
///
/// If a future change genuinely needs `unsafe`, the honest move is to update
/// `AGENTS.md` and this test together, with the justification, instead of
/// quietly adding it.
#[test]
fn test_src_contains_no_unsafe_code() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();

    for entry in std::fs::read_dir(&src).expect("failed to read src/") {
        let path = entry.expect("bad dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("failed to read source file");
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            // Comments and doc comments may legitimately discuss `unsafe`.
            if code.starts_with("//") {
                continue;
            }
            // Only the keyword in a code position, not substrings like
            // `unsafely` or a string literal mentioning it.
            let is_keyword = code
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|token| token == "unsafe");
            if is_keyword {
                offenders.push(format!(
                    "{}:{}: {}",
                    path.file_name().unwrap().to_string_lossy(),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "src/ must contain no `unsafe` code (AGENTS.md), found:\n  {}",
        offenders.join("\n  ")
    );
}

/// A config that exists but cannot be loaded must stop the daemon, not be
/// replaced by the built-in defaults.
///
/// `Config::load()` returns empty targets when there is *no* config file, so an
/// error means the user has a config expressing intent that could not be
/// honoured. Substituting `Config::default()` turned "kill only my marker" into
/// "kill `node.*claude`, `claude`, `node.*mcp`" — the built-in patterns — after a
/// single missing comma. The daemon not running is loud and harmless; killing
/// processes the user never chose is neither.
#[test]
fn test_daemon_refuses_a_config_it_cannot_load() {
    let home = sandbox();
    let cfg_dir = home.path().join(".config").join("proc-janitor");
    std::fs::create_dir_all(&cfg_dir).expect("Failed to create config dir");
    // Missing comma in the array: an ordinary TOML typo.
    std::fs::write(
        cfg_dir.join("config.toml"),
        "scan_interval = 5\n\
         grace_period = 30\n\
         sigterm_timeout = 5\n\
         targets = [\n    \"my_specific_marker\"\n    \"second_pattern\"\n]\n\
         whitelist = []\n",
    )
    .expect("Failed to write config");

    // Spawn rather than `output()`: if this ever regresses, the daemon enters its
    // scan loop and never exits, and `output()` would block forever. A test that
    // hangs on regression is worse than one that fails, so the deadline is part
    // of the assertion.
    let mut child = pj(&home)
        .args(["start", "--foreground"])
        .env("PROC_JANITOR_ALLOW_CONTAINER", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to run start");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        match child.try_wait().expect("Failed to poll start") {
            Some(status) => break Some(status),
            None if std::time::Instant::now() >= deadline => break None,
            None => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    };

    let still_running = status.is_none();
    if still_running {
        let _ = child.kill();
    }
    let output = child
        .wait_with_output()
        .expect("Failed to collect start output");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !still_running,
        "the daemon is still running after 10s despite an unloadable config: {combined}"
    );
    let status = status.expect("checked above");
    assert!(
        !status.success(),
        "the daemon exited successfully despite an unloadable config: {combined}"
    );
    assert!(
        !combined.contains("Daemon started"),
        "the daemon entered its scan loop despite an unloadable config: {combined}"
    );
    assert!(
        combined.contains("Refusing to start"),
        "the error should say why it refused, got: {combined}"
    );
}
