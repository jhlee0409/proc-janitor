use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

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
        // For Default trait, we need a fallback since we can't return Result
        // This is only used in tests and edge cases
        let home = dirs::home_dir().unwrap_or_else(|| {
            eprintln!("Warning: HOME directory not found, using current directory");
            PathBuf::from(".")
        });
        let log_path = home
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
    }
}

impl Config {
    /// Create a new default configuration with proper error handling
    pub fn new_default() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("HOME directory not found"))?;
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
        for pattern in &self.targets {
            Regex::new(pattern)
                .with_context(|| format!("Invalid target pattern: {}", pattern))?;
        }
        for pattern in &self.whitelist {
            Regex::new(pattern)
                .with_context(|| format!("Invalid whitelist pattern: {}", pattern))?;
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
                if v >= 1 && v <= 3600 {
                    self.scan_interval = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_SCAN_INTERVAL out of range (1-3600): {}, using default", v);
                }
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_GRACE_PERIOD") {
            if let Ok(v) = val.parse::<u64>() {
                if v <= 3600 {
                    self.grace_period = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_GRACE_PERIOD out of range (0-3600): {}, using default", v);
                }
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_SIGTERM_TIMEOUT") {
            if let Ok(v) = val.parse::<u64>() {
                if v >= 1 && v <= 60 {
                    self.sigterm_timeout = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_SIGTERM_TIMEOUT out of range (1-60): {}, using default", v);
                }
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
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_LOG_PATH") {
            if Self::is_safe_log_path(&val) {
                self.logging.path = val;
            } else {
                eprintln!("Warning: PROC_JANITOR_LOG_PATH rejected for security reasons: {}, using default", val);
            }
        }

        if let Ok(val) = std::env::var("PROC_JANITOR_LOG_RETENTION_DAYS") {
            if let Ok(v) = val.parse::<u32>() {
                if v <= 365 {
                    self.logging.retention_days = v;
                } else {
                    eprintln!("Warning: PROC_JANITOR_LOG_RETENTION_DAYS out of range (0-365): {}, using default", v);
                }
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
            "/etc/", "/usr/", "/bin/", "/sbin/", "/system/",
            "/boot/", "/root/", "/var/", "/tmp/",
        ];

        for prefix in &dangerous_prefixes {
            if lower_path.starts_with(prefix) {
                return false;
            }
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

    /// Save configuration to ~/.config/proc-janitor/config.toml
    pub fn save(&self) -> Result<()> {
        ensure_config_dir()?;

        let path = config_path()?;
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize configuration")?;

        fs::write(&path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }
}

/// Get the configuration file path
pub fn config_path() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Config directory not found"))?
        .join("proc-janitor")
        .join("config.toml"))
}

/// Ensure configuration directory exists
pub fn ensure_config_dir() -> Result<()> {
    let path = config_path()?;
    let dir = path
        .parent()
        .context("Failed to get config directory")?;

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

/// Open configuration file in editor
pub fn edit() -> Result<()> {
    ensure_config_dir()?;

    let path = config_path()?;

    // Create default config if it doesn't exist
    if !path.exists() {
        let config = Config::new_default()?;
        config.save()?;
    }

    // Get editor from environment or use default
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vim".to_string());

    // Security: Validate editor to prevent command injection
    // Only allow safe characters: alphanumeric, hyphens, underscores, dots, and forward slashes
    if !editor.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '/' || c == '.') {
        anyhow::bail!("Invalid EDITOR value: must contain only alphanumeric characters, hyphens, underscores, dots, or slashes");
    }

    // Open editor
    std::process::Command::new(&editor)
        .arg(&path)
        .status()
        .with_context(|| format!("Failed to open editor for config: {}", path.display()))?;

    Ok(())
}

/// Show current configuration
pub fn show() -> Result<()> {
    let config = Config::load()?;
    let content = toml::to_string_pretty(&config)?;

    println!("Current configuration:");
    println!("----------------------");
    println!("{}", content);
    println!("----------------------");
    println!("Config file: {}", config_path()?.display());

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

        assert_eq!(config.logging.enabled, false);
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
