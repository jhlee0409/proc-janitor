use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "proc-janitor")]
#[command(about = "Automated process cleanup daemon for macOS", long_about = None)]
#[command(version)]
pub struct Cli {
    /// Output in JSON format
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the daemon
    Stop,

    /// Show daemon status
    Status,

    /// Run a single scan (dry-run by default)
    Scan {
        /// Actually perform cleanup actions
        #[arg(long)]
        execute: bool,
    },

    /// Clean up processes immediately
    Clean {
        /// Show what would be cleaned without actually doing it
        #[arg(long)]
        dry_run: bool,
    },

    /// Show process tree visualization
    Tree {
        /// Only show target processes
        #[arg(short, long)]
        targets_only: bool,
    },

    /// Open interactive dashboard in browser
    Dashboard {
        /// Auto-refresh mode: regenerate dashboard periodically
        #[arg(long)]
        live: bool,

        /// Refresh interval in seconds (used with --live, default: 5)
        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// View logs
    Logs {
        /// Follow log output
        #[arg(short, long)]
        follow: bool,

        /// Number of lines to show
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,
    },

    /// Session-based process tracking
    #[command(subcommand)]
    Session(SessionCommands),
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Create a configuration file (auto-detects orphaned processes)
    Init {
        /// Overwrite existing config file
        #[arg(long)]
        force: bool,

        /// Use a preset: claude, dev, minimal
        #[arg(long)]
        preset: Option<String>,
    },

    /// Edit configuration file
    Edit,

    /// Show current configuration
    Show,
}

#[derive(Subcommand, Debug)]
pub enum SessionCommands {
    /// Register a new session for tracking
    Register {
        /// Custom session ID (auto-generated if not provided)
        #[arg(short, long)]
        id: Option<String>,

        /// Human-readable session name
        #[arg(short, long)]
        name: Option<String>,

        /// Session source (claude-code, terminal, vscode, tmux, or custom)
        #[arg(short, long, default_value = "terminal")]
        source: String,

        /// Parent PID to track (defaults to current process)
        #[arg(short, long)]
        parent_pid: Option<u32>,
    },

    /// Track a PID under an existing session
    Track {
        /// Session ID
        session_id: String,

        /// Process ID to track
        pid: u32,
    },

    /// Clean up all processes in a session
    Clean {
        /// Session ID to clean
        session_id: String,

        /// Show what would be cleaned without doing it
        #[arg(long)]
        dry_run: bool,
    },

    /// List all active sessions
    List,

    /// Unregister a session without killing processes
    Unregister {
        /// Session ID to unregister
        session_id: String,
    },

    /// Auto-detect and clean orphaned sessions
    AutoClean {
        /// Show what would be cleaned without doing it
        #[arg(long)]
        dry_run: bool,
    },
}
