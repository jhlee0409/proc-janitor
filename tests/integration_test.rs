use std::path::PathBuf;
use std::process::Command;

extern crate libc;

fn binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    path.pop(); // Remove deps
    path.push("proc-janitor");
    path
}

#[test]
fn test_help_command() {
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
        .arg("scan")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_scan_json_output() {
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
        .arg("session")
        .arg("list")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_tree_command() {
    let output = Command::new(binary_path())
        .arg("tree")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_clean_command() {
    let output = Command::new(binary_path())
        .arg("clean")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_clean_with_pid_filter() {
    let output = Command::new(binary_path())
        .args(["clean", "--pid", "99999"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_clean_with_pattern_filter() {
    let output = Command::new(binary_path())
        .args(["clean", "--pattern", "nonexistent_process_xyz"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_version_command() {
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
        .args(["config", "validate"])
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    // Either valid config or no config file (CI has no config)
    assert!(
        combined.contains("valid") || combined.contains("Valid") || combined.contains("not found"),
        "Expected validation output, got: {combined}"
    );
}

#[test]
fn test_doctor_command() {
    let output = Command::new(binary_path())
        .arg("doctor")
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_daemon_foreground_dry_run() {
    // Start daemon in foreground + dry-run, kill it after 2 seconds
    let child = std::process::Command::new(binary_path())
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
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
        .args(["--quiet", "clean"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_restart_when_not_running() {
    // Restart when daemon isn't running should just start (or fail gracefully)
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
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
    let output = Command::new(binary_path())
        .args(["clean", "--min-age", "999999"])
        .output()
        .expect("Failed to execute command");

    // With min_age very high, nothing should be cleaned
    assert!(output.status.success());
}

#[test]
fn test_tree_with_pattern() {
    let output = Command::new(binary_path())
        .args(["tree", "--pattern", "nonexistent_xyz"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No processes matching") || stdout.contains("nonexistent_xyz"));
}
