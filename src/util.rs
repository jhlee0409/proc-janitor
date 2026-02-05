/// Check if color output is enabled (respects NO_COLOR and isatty)
pub fn use_color() -> bool {
    std::env::var("NO_COLOR").is_err()
        && supports_color::on(supports_color::Stream::Stdout).is_some()
}

/// Check that a path is not a symlink. Returns an error if it is.
/// This prevents symlink attacks where a local attacker creates a symlink
/// at a predictable path to trick proc-janitor into overwriting arbitrary files.
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
