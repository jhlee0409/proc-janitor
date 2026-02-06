use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "proc-janitor")]
#[command(about = "Automated orphan process cleanup daemon for macOS/Linux")]
#[command(
    long_about = "proc-janitor detects and cleans up orphaned processes (PPID=1) matching\nconfigurable regex patterns. Use 'scan' to detect, 'clean' to kill,\nor 'start' to run as a background daemon.\n\nQuick start:\n  proc-janitor scan              Detect orphaned processes (safe, no killing)\n  proc-janitor clean             Kill all detected orphans\n  proc-janitor clean --pid 123   Kill specific orphan by PID\n  proc-janitor clean -m 'node'   Kill orphans matching pattern\n  proc-janitor config init       Set up with auto-detection\n  proc-janitor start             Start background daemon"
)]
#[command(version)]
pub struct Cli {
    /// Output in JSON format
    #[arg(long, short = 'j', global = true)]
    pub json: bool,

    /// Suppress non-essential output
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long, short = 'f')]
        foreground: bool,
    },

    /// Stop the daemon
    Stop,

    /// Show daemon status
    Status,

    /// Scan for orphaned processes (detection only, no killing)
    Scan,

    /// Clean up orphaned processes (kills all by default, use filters to be selective)
    Clean {
        /// Kill only specific PIDs (space-separated)
        #[arg(long, short = 'p', num_args = 1..)]
        pid: Vec<u32>,

        /// Kill only orphans whose command line matches this regex pattern
        #[arg(long, short = 'm')]
        pattern: Option<String>,
    },

    /// Show process tree visualization
    Tree {
        /// Only show target processes
        #[arg(short, long)]
        targets_only: bool,
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
        #[arg(short = 'n', long, default_value = "50", value_parser = clap::value_parser!(u64).range(1..))]
        lines: u64,
    },

    /// Session-based process tracking
    #[command(subcommand)]
    Session(SessionCommands),

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, powershell)
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Show version and build information
    Version,

    /// Diagnose common issues and check system health
    Doctor,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Create a configuration file (auto-detects orphaned processes)
    Init {
        /// Overwrite existing config file
        #[arg(long)]
        force: bool,

        /// Use a preset configuration:
        ///   claude   - Target Claude Code & MCP server processes
        ///   dev      - Target common dev tools (node, cargo, python, bundlers)
        ///   minimal  - Empty targets for fully manual configuration
        #[arg(long)]
        preset: Option<String>,

        /// List available presets and exit
        #[arg(long)]
        list_presets: bool,

        /// Skip confirmation prompts (auto-accept detected targets)
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Edit configuration file
    Edit,

    /// Show current configuration
    Show,

    /// Show all environment variable overrides
    Env,

    /// Validate configuration file
    Validate,
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
        #[arg(long, short = 'd')]
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
        #[arg(long, short = 'd')]
        dry_run: bool,
    },
}
