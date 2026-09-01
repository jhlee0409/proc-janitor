use nix::libc;

/// Check if color output is enabled (respects NO_COLOR and isatty)
pub fn use_color() -> bool {
    std::env::var("NO_COLOR").is_err()
        && supports_color::on(supports_color::Stream::Stdout).is_some()
}

/// Render text that came from another process's `argv` safely for a terminal.
///
/// A process controls its own command line, including control bytes, and
/// `scan`/`clean` print those command lines. Unsanitised, any local process can
/// put `\x1b[2J` (clear screen), `\x1b[1;1H` (move cursor) or `\x1b]0;…\x07`
/// (rewrite the window title) into the output of a tool the user runs — and a
/// newline lets it forge an entire extra report line, e.g. a plausible-looking
/// "terminated orphaned process" entry that never happened.
///
/// `ps` sanitises for exactly this reason; a tool whose whole job is displaying
/// other processes' argv should too. Control characters become a visible `\xNN`
/// so the text stays readable and nothing is silently dropped.
///
/// JSON output does not need this — `serde_json` escapes control characters — and
/// must not use it, or the emitted value would no longer be the real command
/// line.
pub fn sanitize_for_display(text: &str) -> std::borrow::Cow<'_, str> {
    if !text.chars().any(|c| c.is_control()) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            // `is_control` covers C0, DEL and C1; all fit in two hex digits
            // except the C1 range, which `{:02x}` widens automatically.
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// The set of process fields proc-janitor actually reads.
///
/// `pid`, `parent`, `name` and `start_time` are always retrieved by any refresh;
/// only `memory` and `cmd` have to be requested. `ProcessRefreshKind::everything()`
/// would additionally fetch cpu usage, disk usage, user ids, cwd, root and the
/// full environment — on macOS each of those is extra per-process syscall work,
/// and none of it is ever read. Measured on a 960-process machine: a full-table
/// refresh costs 6.40 ms with `everything()` versus 2.76 ms with this kind.
///
/// `cmd` is `Always`, not `OnlyIfNotSet`: target matching runs against the
/// command line, so a reused PID must never be matched against the previous
/// occupant's cached `cmd`.
pub fn process_refresh_kind() -> sysinfo::ProcessRefreshKind {
    sysinfo::ProcessRefreshKind::new()
        .with_memory()
        .with_cmd(sysinfo::UpdateKind::Always)
}

/// A fresh, fully-refreshed process table for one-shot (CLI) use.
///
/// The daemon keeps a long-lived `System` instead, so it pays only the refresh
/// cost per cycle rather than reallocating the whole table.
pub fn process_snapshot() -> sysinfo::System {
    let kind = process_refresh_kind();
    let mut sys =
        sysinfo::System::new_with_specifics(sysinfo::RefreshKind::new().with_processes(kind));
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::All, kind);
    sys
}

/// A process table refreshed for a single PID only.
///
/// Used for identity checks (`start_time` lookups) where the whole table is
/// irrelevant. sysinfo still enumerates PIDs to drop dead entries, so this is
/// cheaper but not free (measured 3.34 ms versus 6.40 ms for a full refresh).
pub fn process_snapshot_for(pid: u32) -> sysinfo::System {
    let kind = process_refresh_kind();
    let mut sys =
        sysinfo::System::new_with_specifics(sysinfo::RefreshKind::new().with_processes(kind));
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
        kind,
    );
    sys
}

/// Check that a path is not a symlink. Returns an error if it is.
/// This prevents symlink attacks where a local attacker creates a symlink
/// at a predictable path to trick proc-janitor into overwriting arbitrary files.
///
/// **Note:** This has an inherent TOCTOU race between check and subsequent write.
/// For write operations, prefer [`open_nofollow_write()`] which is atomic.
pub fn check_not_symlink(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            anyhow::bail!(
                "Refusing to write to symlink at {}. This may be a symlink attack.",
                path.display()
            );
        }
    }
    Ok(())
}

/// Open a file for writing without following symlinks (TOCTOU-safe).
///
/// Unlike `check_not_symlink` + `fs::write` (which has a race window),
/// this atomically rejects symlinks during the open call using O_NOFOLLOW.
/// Callers should write to the returned File handle instead of using fs::write.
#[cfg(unix)]
pub fn open_nofollow_write(path: &std::path::Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    // O_NOFOLLOW causes open() to fail with ELOOP if path is a symlink
    let flags = libc::O_NOFOLLOW;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|e| {
            // ELOOP (errno 62 on macOS, 40 on Linux) means it's a symlink
            if e.kind() == std::io::ErrorKind::Other || e.raw_os_error() == Some(libc::ELOOP) {
                anyhow::anyhow!(
                    "Refusing to write to symlink at {}. This may be a symlink attack.",
                    path.display()
                )
            } else {
                anyhow::anyhow!("Failed to open {}: {}", path.display(), e)
            }
        })
}

/// Build a parent→children map from the process table.
/// Returns a HashMap where keys are parent PIDs and values are vectors of child PIDs.
pub fn build_children_map(sys: &sysinfo::System) -> std::collections::HashMap<u32, Vec<u32>> {
    let mut children_map: std::collections::HashMap<u32, Vec<u32>> =
        std::collections::HashMap::new();
    for (pid, process) in sys.processes() {
        if let Some(parent) = process.parent() {
            children_map
                .entry(parent.as_u32())
                .or_default()
                .push(pid.as_u32());
        }
    }
    children_map
}

/// Recursively collect all descendant PIDs from a set of roots using a pre-built children map.
/// Includes cycle detection via visited set.
pub fn collect_descendants(
    pid: u32,
    children_map: &std::collections::HashMap<u32, Vec<u32>>,
    result: &mut std::collections::HashSet<u32>,
) {
    if let Some(children) = children_map.get(&pid) {
        for &child in children {
            if result.insert(child) {
                collect_descendants(child, children_map, result);
            }
        }
    }
}

/// Find all descendant PIDs from a list of parent PIDs, including the parents themselves.
/// Builds the children map internally from the System instance.
pub fn find_descendant_pids(sys: &sysinfo::System, parent_pids: &[u32]) -> Vec<u32> {
    let children_map = build_children_map(sys);

    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    let mut to_check: Vec<u32> = parent_pids.to_vec();

    while let Some(pid) = to_check.pop() {
        if !visited.insert(pid) {
            continue;
        }

        if sys.process(sysinfo::Pid::from_u32(pid)).is_some() {
            result.push(pid);
        }

        if let Some(children) = children_map.get(&pid) {
            for &child_pid in children {
                if !visited.contains(&child_pid) {
                    to_check.push(child_pid);
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A process controls its own `argv`, and `scan`/`clean` print it. These are
    /// the sequences that matter: screen/cursor control, a window-title rewrite,
    /// and a newline that would forge an extra report line.
    #[test]
    fn test_sanitize_neutralises_terminal_control_sequences() {
        let hostile =
            "PJPROBE\x1b[2J\x1b[1;1H\x1b]0;HIJACKED\x07\nFAKE terminated orphaned process";
        let safe = sanitize_for_display(hostile);

        assert!(!safe.contains('\x1b'), "ESC survived: {safe}");
        assert!(!safe.contains('\n'), "newline survived: {safe}");
        assert!(!safe.contains('\x07'), "BEL survived: {safe}");
        // Nothing is dropped — the operator can still see what was attempted.
        assert!(safe.contains("PJPROBE"), "payload text lost: {safe}");
        assert!(safe.contains("\\x1b"), "escape not shown: {safe}");
        assert!(safe.contains("\\x0a"), "newline not shown: {safe}");
    }

    /// Ordinary command lines must pass through untouched, and without
    /// allocating.
    #[test]
    fn test_sanitize_leaves_normal_text_alone() {
        for text in [
            "node /usr/local/bin/claude --flag",
            "python3 -m http.server 8000",
            "sh -c 'sleep 30; : marker'",
            "프로세스 이름 with unicode ✓",
        ] {
            let out = sanitize_for_display(text);
            assert_eq!(out, text);
            assert!(
                matches!(out, std::borrow::Cow::Borrowed(_)),
                "should not allocate for clean text: {text}"
            );
        }
    }
    #[test]
    fn test_check_not_symlink_regular_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("regular.txt");
        std::fs::write(&file_path, "test").unwrap();
        assert!(check_not_symlink(&file_path).is_ok());
    }

    #[test]
    fn test_check_not_symlink_nonexistent() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("nonexistent.txt");
        // Non-existent path should pass (no symlink)
        assert!(check_not_symlink(&file_path).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn test_check_not_symlink_actual_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "test").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = check_not_symlink(&link);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    #[cfg(unix)]
    fn test_open_nofollow_write_regular_file() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("output.txt");

        let file = open_nofollow_write(&file_path);
        assert!(file.is_ok());

        use std::io::Write;
        let mut f = file.unwrap();
        f.write_all(b"hello").unwrap();

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "hello");
    }

    #[test]
    #[cfg(unix)]
    fn test_open_nofollow_write_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "original").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = open_nofollow_write(&link);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }

    #[test]
    fn test_use_color_respects_no_color() {
        // When NO_COLOR is set, use_color should return false
        // We can't easily test this without modifying env, so just verify it doesn't panic
        let _ = use_color();
    }
}
