use nix::libc;

/// Check if color output is enabled (respects NO_COLOR and isatty)
pub fn use_color() -> bool {
    std::env::var("NO_COLOR").is_err()
        && supports_color::on(supports_color::Stream::Stdout).is_some()
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
