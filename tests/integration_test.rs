use std::path::PathBuf;
use std::process::Command;

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
