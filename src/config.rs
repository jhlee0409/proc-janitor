use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::util::use_color;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub scan_interval: u64,
    pub grace_period: u64,
    pub sigterm_timeout: u64,
    pub targets: Vec<String>,
    pub whitelist: Vec<String>,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub path: String,
    pub retention_days: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self::new_default().unwrap_or_else(|_| {
            eprintln!("Warning: HOME directory not found, using current directory");
            let log_path = PathBuf::from(".")
                .join(".proc-janitor")
                .join("logs")
                .to_string_lossy()
                .to_string();
            Self {
                scan_interval: 5,
                grace_period: 30,
                sigterm_timeout: 5,
                targets: vec![
                    "node.*claude".to_string(),
                    "claude".to_string(),
                    "node.*mcp".to_string(),
                ],
                whitelist: vec!["node.*server".to_string(), "pm2".to_string()],
                logging: LoggingConfig {
                    enabled: true,
                    path: log_path,
                    retention_days: 7,
                },
            }
        })
    }
}

impl Config {
    /// Create a new default configuration with proper error handling
    pub fn new_default() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?;
        let log_path = home
            .join(".proc-janitor")
            .join("logs")
            .to_string_lossy()
            .to_string();

        Ok(Self {
            scan_interval: 5,
            grace_period: 30,
            sigterm_timeout: 5,
            targets: vec![
                "node.*claude".to_string(),
                "claude".to_string(),
                "node.*mcp".to_string(),
            ],
            whitelist: vec!["node.*server".to_string(), "pm2".to_string()],
            logging: LoggingConfig {
                enabled: true,
                path: log_path,
                retention_days: 7,
            },
        })
    }

    /// Validate all regex patterns in the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate scan_interval range
        if self.scan_interval == 0 || self.scan_interval > 3600 {
            anyhow::bail!(
                "scan_interval must be between 1 and 3600 seconds, got {}",
                self.scan_interval
            );
        }

        // Validate grace_period range
        if self.grace_period > 3600 {
            anyhow::bail!(
                "grace_period must be between 0 and 3600 seconds, got {}",
                self.grace_period
            );
        }

        // Validate sigterm_timeout range
        if self.sigterm_timeout == 0 || self.sigterm_timeout > 60 {
            anyhow::bail!(
                "sigterm_timeout must be between 1 and 60 seconds, got {}",
                self.sigterm_timeout
            );
        }

        // Validate pattern counts
        if self.targets.len() > 100 {
            anyhow::bail!("Too many target patterns (max 100, got {})", self.targets.len());
        }
        if self.whitelist.len() > 100 {
            anyhow::bail!("Too many whitelist patterns (max 100, got {})", self.whitelist.len());
        }

        // Validate pattern lengths and compile regexes
        for pattern in self.targets.iter().chain(self.whitelist.iter()) {
            if pattern.len() > 1024 {
                anyhow::bail!("Pattern too long (max 1024 chars): {}...", &pattern[..50.min(pattern.len())]);
            }
        }

        for pattern in &self.targets {
            Regex::new(pattern).with_context(|| format!("Invalid target pattern: {pattern}"))?;
        }
        for pattern in &self.whitelist {
            Regex::new(pattern)
                .with_context(|| format!("Invalid whitelist pattern: {pattern}"))?;
        }
        Ok(())
    }

    /// Load configuration from ~/.config/proc-janitor/config.toml
    pub fn load() -> Result<Self> {
        let mut config = Self::load_from_file()?;

        // Apply environment variable overrides
        config.apply_env_overrides();

        // Validate regex patterns after overrides
        config.validate()?;

        Ok(config)
    }

    /// Load configuration from file without environment overrides
    fn load_from_file() -> Result<Self> {
        let path = config_path()?;

        if !path.exists() {
            // Return default config if file doesn't exist
            return Self::new_default();
        }

        let content = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        Ok(config)
    }

    /// Apply environment variable overrides to configuration
    fn apply_env_overrides(&mut self) {
        // Numeric settings with boundary validation
        if let Ok(val) = std::env::var("PROC_JANITOR_SCAN_INTERVAL") {
            if let Ok(v) = val.parse::<u64>() {
                if (1..=3600).contains(&v) {
                    self.scan_interval = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_SCAN_INTERVAL out of range (1-3600): {v}, using default");
                }
            } else {
                eprintln!("Warning: PROC_JANITOR_SCAN_INTERVAL is not a valid number: {val}");
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_GRACE_PERIOD") {
            if let Ok(v) = val.parse::<u64>() {
                if v <= 3600 {
                    self.grace_period = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_GRACE_PERIOD out of range (0-3600): {v}, using default");
                }
            } else {
                eprintln!("Warning: PROC_JANITOR_GRACE_PERIOD is not a valid number: {val}");
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_SIGTERM_TIMEOUT") {
            if let Ok(v) = val.parse::<u64>() {
                if (1..=60).contains(&v) {
                    self.sigterm_timeout = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_SIGTERM_TIMEOUT out of range (1-60): {v}, using default");
                }
            } else {
                eprintln!("Warning: PROC_JANITOR_SIGTERM_TIMEOUT is not a valid number: {val}");
            }
        }

        // Target patterns (comma-separated)
        if let Ok(val) = std::env::var("PROC_JANITOR_TARGETS") {
            self.targets = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Whitelist patterns (comma-separated)
        if let Ok(val) = std::env::var("PROC_JANITOR_WHITELIST") {
            self.whitelist = val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // Logging configuration
        if let Ok(val) = std::env::var("PROC_JANITOR_LOG_ENABLED") {
            if let Ok(v) = val.parse::<bool>() {
                self.logging.enabled = v;
            } else {
                eprintln!("Warning: PROC_JANITOR_LOG_ENABLED is not a valid boolean: {val}");
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_LOG_PATH") {
            if Self::is_safe_log_path(&val) {
                self.logging.path = val;
            } else {
                eprintln!("Warning: PROC_JANITOR_LOG_PATH rejected for security reasons: {val}, using default");
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_LOG_RETENTION_DAYS") {
            if let Ok(v) = val.parse::<u32>() {
                if v <= 365 {
                    self.logging.retention_days = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_LOG_RETENTION_DAYS out of range (0-365): {v}, using default");
                }
            } else {
                eprintln!("Warning: PROC_JANITOR_LOG_RETENTION_DAYS is not a valid number: {val}");
            }
        }
    }

    /// Validate log path to prevent directory traversal and system directory access
    fn is_safe_log_path(path: &str) -> bool {
        // Reject paths containing directory traversal
        if path.contains("..") {
            return false;
        }

        // Reject paths to system directories (case-insensitive)
        let lower_path = path.to_lowercase();
        let dangerous_prefixes = [
            "/etc/", "/usr/", "/bin/", "/sbin/", "/system/", "/boot/", "/root/", "/tmp/",
        ];

        for prefix in &dangerous_prefixes {
            if lower_path.starts_with(prefix) {
                return false;
            }
        }

        // Allow /var/log/ but block other /var/ subdirectories
        if lower_path.starts_with("/var/") && !lower_path.starts_with("/var/log/") {
            return false;
        }

        // For absolute paths, try to verify they're under user's home directory
        if path.starts_with('/') {
            if let Some(home) = dirs::home_dir() {
                let home_str = home.to_string_lossy();
                if !path.starts_with(home_str.as_ref()) {
                    return false;
                }
            }
        }

        true
    }

}

/// Get the configuration file path (~/.config/proc-janitor/config.toml on all platforms)
pub fn config_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?;
    Ok(home
        .join(".config")
        .join("proc-janitor")
        .join("config.toml"))
}

/// Ensure configuration directory exists
pub fn ensure_config_dir() -> Result<()> {
    let path = config_path()?;
    let dir = path.parent().context("Failed to get config directory")?;

    fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create config directory: {}", dir.display()))?;

    // Set directory permissions to 0o700 (rwx------)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Failed to set directory permissions: {}", dir.display()))?;
    }

    Ok(())
}

/// Commented config template (embedded at compile time)
const CONFIG_TEMPLATE: &str = include_str!("config_template.toml");

/// Known dev tool categories for smart detection
const DEV_CATEGORIES: &[(&str, &[&str], &[&str])] = &[
    // (category_name, process_name_patterns, suggested_target_regexes)
    ("Node.js", &["node", "npm", "npx", "yarn", "pnpm"], &["node"]),
    (
        "Claude Code",
        &["claude"],
        &["node.*claude", "claude", "node.*mcp"],
    ),
    ("Rust/Cargo", &["cargo", "rustc", "rustup"], &["cargo"]),
    ("Python", &["python", "python3", "pip", "pip3"], &["python"]),
    (
        "Bundlers",
        &["webpack", "vite", "esbuild", "turbopack"],
        &["webpack|vite|esbuild"],
    ),
    ("Java/JVM", &["java", "gradle", "mvn"], &["java|gradle"]),
    ("Go", &["go"], &["go"]),
    ("Ruby", &["ruby", "bundle", "rails"], &["ruby"]),
];

/// Preset configurations
struct Preset {
    targets: Vec<&'static str>,
    whitelist: Vec<&'static str>,
}

fn get_preset(name: &str) -> Result<Preset> {
    match name {
        "claude" => Ok(Preset {
            targets: vec!["node.*claude", "claude", "node.*mcp"],
            whitelist: vec!["node.*server", "pm2"],
        }),
        "dev" => Ok(Preset {
            targets: vec!["node", "cargo", "python", "webpack|vite|esbuild"],
            whitelist: vec!["node.*server", "pm2", "node.*next"],
        }),
        "minimal" => Ok(Preset {
            targets: vec![],
            whitelist: vec![],
        }),
        _ => anyhow::bail!(
            "Unknown preset: '{name}'. Available: claude, dev, minimal"
        ),
    }
}

/// Format a TOML array field with parameterized name
fn format_toml_field(name: &str, items: &[&str]) -> String {
    if items.is_empty() {
        return format!("{name} = []");
    }
    let formatted = items
        .iter()
        .map(|t| format!("    \"{t}\""))
        .collect::<Vec<_>>()
        .join(",\n");
    format!("{name} = [\n{formatted}\n]")
}

/// Render config template with targets, whitelist, and log path
fn render_template(targets: &[&str], whitelist: &[&str]) -> Result<String> {
    let log_path = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?
        .join(".proc-janitor")
        .join("logs")
        .to_string_lossy()
        .to_string();
    Ok(CONFIG_TEMPLATE
        .replace("{targets}", &format_toml_field("targets", targets))
        .replace("{whitelist}", &format_toml_field("whitelist", whitelist))
        .replace("{log_path}", &log_path))
}

/// Detect orphaned dev processes on the system
fn detect_orphan_categories() -> Vec<(String, Vec<String>, usize)> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};

    let mut sys =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let mut results = Vec::new();

    for &(category, name_patterns, suggested) in DEV_CATEGORIES {
        let mut matched_cmds = Vec::new();
        for process in sys.processes().values() {
            // Only orphans (PPID=1)
            let is_orphan = process.parent().map(|p| p.as_u32()) == Some(1);
            if !is_orphan {
                continue;
            }

            let pname = process.name().to_string_lossy().to_lowercase();
            if name_patterns.iter().any(|pat| pname.contains(pat)) {
                let cmdline = process
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                if !cmdline.is_empty() {
                    let display = if cmdline.chars().count() > 60 {
                        format!("{}...", cmdline.chars().take(57).collect::<String>())
                    } else {
                        cmdline
                    };
                    matched_cmds.push(display);
                }
            }
        }

        let count = matched_cmds.len();
        if count > 0 {
            results.push((
                category.to_string(),
                suggested.iter().map(|s| s.to_string()).collect(),
                count,
            ));
        }
    }

    results
}

/// Write config file and validate
fn write_config(path: &std::path::Path, content: &str) -> Result<()> {
    crate::util::check_not_symlink(path)?;
    fs::write(path, content)
        .with_context(|| format!("Failed to write config file: {}", path.display()))?;

    // Validate
    let config: Config = toml::from_str(content).context("Generated config is invalid")?;
    config.validate()?;

    Ok(())
}

/// Create config file with smart detection or preset
pub fn init(force: bool, preset: Option<String>, yes: bool) -> Result<()> {
    ensure_config_dir()?;
    let path = config_path()?;

    if path.exists() && !force {
        println!("Config file already exists: {}", path.display());
        println!("Use --force to overwrite.");
        return Ok(());
    }

    if let Some(preset_name) = preset {
        // Preset mode
        let p = get_preset(&preset_name)?;
        let content = render_template(&p.targets, &p.whitelist)?;
        write_config(&path, &content)?;
        println!("Config created with '{}' preset: {}", preset_name, path.display());
        println!("Edit with: proc-janitor config edit");
        return Ok(());
    }

    // Smart detection mode
    println!("Scanning for orphaned processes...\n");
    let detected = detect_orphan_categories();

    if detected.is_empty() {
        println!("No orphaned dev processes detected.");
        println!("Creating config with empty targets (add patterns manually).\n");
        let content = render_template(&[], &[])?;
        write_config(&path, &content)?;
        println!("Config file created: {}", path.display());
        println!("Edit with: proc-janitor config edit");
        println!("\nTip: Use a preset for quick setup:");
        println!("  proc-janitor config init --force --preset claude");
        println!("  proc-janitor config init --force --preset dev");
        return Ok(());
    }

    // Show detected orphans
    println!("Detected orphaned processes:");
    let mut all_targets: Vec<&str> = Vec::new();
    for (category, patterns, count) in &detected {
        let check_mark = if use_color() {
            format!("{}", "✓".green())
        } else {
            "✓".to_string()
        };
        println!("  {check_mark} {category} {count} orphan(s)");
        for p in patterns {
            all_targets.push(p);
        }
    }

    println!("\nSuggested target patterns:");
    for t in &all_targets {
        println!("  - \"{t}\"");
    }

    let confirmed = if yes {
        println!("\nAuto-accepting detected targets (--yes).");
        true
    } else {
        println!("\nApply these targets? [Y/n] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        input != "n" && input != "no"
    };

    if !confirmed {
        println!("Creating config with empty targets instead.");
        let content = render_template(&[], &[])?;
        write_config(&path, &content)?;
    } else {
        let whitelist: Vec<&str> = if all_targets.iter().any(|t| t.contains("node")) {
            vec!["node.*server", "pm2"]
        } else {
            vec![]
        };
        let content = render_template(&all_targets, &whitelist)?;
        write_config(&path, &content)?;
    }

    println!("\nConfig file created: {}", path.display());
    println!("Edit with: proc-janitor config edit");

    Ok(())
}

/// Open configuration file in editor
pub fn edit() -> Result<()> {
    ensure_config_dir()?;

    let path = config_path()?;

    // Create commented template if config doesn't exist
    if !path.exists() {
        let default_targets = &["node.*claude", "claude", "node.*mcp"];
        let default_whitelist = &["node.*server", "pm2"];
        let content = render_template(default_targets, default_whitelist)?;
        crate::util::check_not_symlink(&path)?;
        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
    }

    // Get editor from environment or use default
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());

    // Split editor command - first token is the executable, rest are args
    let parts: Vec<&str> = editor.split_whitespace().collect();
    let editor_bin = parts.first().copied().unwrap_or(&editor);

    // Validate executable name only (not flags)
    let safe_editor = editor_bin
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.');

    if !safe_editor {
        anyhow::bail!("Invalid EDITOR value: must contain only alphanumeric characters, hyphens, underscores, dots, or slashes");
    }

    // Open editor with args
    let mut cmd = std::process::Command::new(editor_bin);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }
    cmd.arg(&path);
    let _status = cmd.status()
        .with_context(|| format!("Failed to open editor for config: {}", path.display()))?;

    // Validate the edited config
    match Config::load() {
        Ok(_) => println!("Configuration validated successfully."),
        Err(e) => eprintln!("Warning: Configuration has errors: {e}"),
    }

    Ok(())
}

/// Show current configuration
pub fn show(json: bool) -> Result<()> {
    let config = Config::load()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else {
        let content = toml::to_string_pretty(&config)?;
        println!("Current configuration:");
        println!("----------------------");
        println!("{content}");
        println!("----------------------");
        println!("Config file: {}", config_path()?.display());
    }

    Ok(())
}

/// Show all available environment variable overrides
pub fn show_env() -> Result<()> {
    println!("Environment variable overrides for proc-janitor:");
    println!("================================================\n");
    println!("These override values from the config file ({}).\n", config_path()?.display());

    let env_vars = [
        ("PROC_JANITOR_SCAN_INTERVAL", "Scan interval in seconds", "1-3600", "5"),
        ("PROC_JANITOR_GRACE_PERIOD", "Grace period before killing (seconds)", "0-3600", "30"),
        ("PROC_JANITOR_SIGTERM_TIMEOUT", "SIGTERM timeout before SIGKILL (seconds)", "1-60", "5"),
        ("PROC_JANITOR_TARGETS", "Target patterns (comma-separated regexes)", "regex list", "node.*claude,claude,node.*mcp"),
        ("PROC_JANITOR_WHITELIST", "Whitelist patterns (comma-separated regexes)", "regex list", "node.*server,pm2"),
        ("PROC_JANITOR_LOG_ENABLED", "Enable file logging", "true/false", "true"),
        ("PROC_JANITOR_LOG_PATH", "Log file directory path", "path", "~/.proc-janitor/logs"),
        ("PROC_JANITOR_LOG_RETENTION_DAYS", "Log retention period in days", "0-365", "7"),
    ];

    for (name, desc, range, default) in &env_vars {
        let current = std::env::var(name).ok();
        println!("  {name}");
        println!("    Description: {desc}");
        println!("    Valid range:  {range}");
        println!("    Default:      {default}");
        if let Some(val) = current {
            println!("    Current:      {val} (set)");
        } else {
            println!("    Current:      (not set)");
        }
        println!();
    }

    println!("Usage: export PROC_JANITOR_SCAN_INTERVAL=10");
    println!("Priority: CLI flags > env vars > config file > defaults");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_default_config() {
        let config = Config::default();

        assert_eq!(config.scan_interval, 5);
        assert_eq!(config.grace_period, 30);
        assert_eq!(config.sigterm_timeout, 5);
        assert_eq!(config.targets.len(), 3);
        assert_eq!(config.whitelist.len(), 2);
        assert!(config.logging.enabled);
        assert_eq!(config.logging.retention_days, 7);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();

        assert_eq!(config.scan_interval, deserialized.scan_interval);
        assert_eq!(config.grace_period, deserialized.grace_period);
        assert_eq!(config.targets, deserialized.targets);
        assert_eq!(config.whitelist, deserialized.whitelist);
    }

    #[test]
    #[serial]
    fn test_env_overrides_numeric() {
        std::env::set_var("PROC_JANITOR_SCAN_INTERVAL", "10");
        std::env::set_var("PROC_JANITOR_GRACE_PERIOD", "60");
        std::env::set_var("PROC_JANITOR_SIGTERM_TIMEOUT", "15");

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(config.scan_interval, 10);
        assert_eq!(config.grace_period, 60);
        assert_eq!(config.sigterm_timeout, 15);

        // Cleanup
        std::env::remove_var("PROC_JANITOR_SCAN_INTERVAL");
        std::env::remove_var("PROC_JANITOR_GRACE_PERIOD");
        std::env::remove_var("PROC_JANITOR_SIGTERM_TIMEOUT");
    }

    #[test]
    #[serial]
    fn test_env_overrides_targets() {
        std::env::set_var("PROC_JANITOR_TARGETS", "pattern1,pattern2,pattern3");

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(config.targets, vec!["pattern1", "pattern2", "pattern3"]);

        // Cleanup
        std::env::remove_var("PROC_JANITOR_TARGETS");
    }

    #[test]
    #[serial]
    fn test_env_overrides_whitelist() {
        std::env::set_var("PROC_JANITOR_WHITELIST", "safe1,safe2");

        let mut config = Config::default();
        config.apply_env_overrides();

        assert_eq!(config.whitelist, vec!["safe1", "safe2"]);

        // Cleanup
        std::env::remove_var("PROC_JANITOR_WHITELIST");
    }

    #[test]
    #[serial]
    fn test_env_overrides_logging() {
        // Cleanup first to ensure clean state
        std::env::remove_var("PROC_JANITOR_LOG_ENABLED");
        std::env::remove_var("PROC_JANITOR_LOG_PATH");
        std::env::remove_var("PROC_JANITOR_LOG_RETENTION_DAYS");

        // Use a safe relative path instead of absolute path
        std::env::set_var("PROC_JANITOR_LOG_ENABLED", "false");
        std::env::set_var("PROC_JANITOR_LOG_PATH", "custom/logs");
        std::env::set_var("PROC_JANITOR_LOG_RETENTION_DAYS", "14");

        let mut config = Config::default();
        config.apply_env_overrides();

        assert!(!config.logging.enabled);
        assert_eq!(config.logging.path, "custom/logs");
        assert_eq!(config.logging.retention_days, 14);

        // Cleanup
        std::env::remove_var("PROC_JANITOR_LOG_ENABLED");
        std::env::remove_var("PROC_JANITOR_LOG_PATH");
        std::env::remove_var("PROC_JANITOR_LOG_RETENTION_DAYS");
    }

    #[test]
    #[serial]
    fn test_env_overrides_invalid_values() {
        // Clean up any existing env vars first
        std::env::remove_var("PROC_JANITOR_SCAN_INTERVAL");
        std::env::remove_var("PROC_JANITOR_LOG_ENABLED");

        std::env::set_var("PROC_JANITOR_SCAN_INTERVAL", "invalid");
        std::env::set_var("PROC_JANITOR_LOG_ENABLED", "not_a_bool");

        let original = Config::default();
        let mut config = original.clone();
        config.apply_env_overrides();

        // Invalid values should be ignored, keeping original values
        assert_eq!(config.scan_interval, original.scan_interval);
        assert_eq!(config.logging.enabled, original.logging.enabled);

        // Cleanup
        std::env::remove_var("PROC_JANITOR_SCAN_INTERVAL");
        std::env::remove_var("PROC_JANITOR_LOG_ENABLED");
    }

    #[test]
    #[serial]
    fn test_env_overrides_empty_lists() {
        // Clean up any existing env vars first
        std::env::remove_var("PROC_JANITOR_TARGETS");
        std::env::remove_var("PROC_JANITOR_WHITELIST");

        std::env::set_var("PROC_JANITOR_TARGETS", "");
        std::env::set_var("PROC_JANITOR_WHITELIST", ",,,");

        let mut config = Config::default();
        config.apply_env_overrides();

        // Empty strings should result in empty lists
        assert!(config.targets.is_empty());
        assert!(config.whitelist.is_empty());

        // Cleanup
        std::env::remove_var("PROC_JANITOR_TARGETS");
        std::env::remove_var("PROC_JANITOR_WHITELIST");
    }

    #[test]
    #[serial]
    fn test_env_overrides_with_spaces() {
        std::env::set_var("PROC_JANITOR_TARGETS", " pattern1 , pattern2 , pattern3 ");

        let mut config = Config::default();
        config.apply_env_overrides();

        // Spaces should be trimmed
        assert_eq!(config.targets, vec!["pattern1", "pattern2", "pattern3"]);

        // Cleanup
        std::env::remove_var("PROC_JANITOR_TARGETS");
    }
}
