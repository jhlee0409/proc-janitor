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
#[allow(dead_code)] // Public API for callers needing TOCTOU-safe writes
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
