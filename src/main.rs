mod cleaner;
mod cli;
mod config;
mod daemon;
mod kill;
mod logger;
mod scanner;
mod session;
mod visualize;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, ConfigCommands, SessionCommands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { foreground } => {
            println!("Starting proc-janitor daemon...");
            daemon::start(foreground)?;
        }

        Commands::Stop => {
            println!("Stopping proc-janitor daemon...");
            daemon::stop()?;
        }

        Commands::Status => {
            daemon::status(cli.json)?;
        }

        Commands::Scan { execute } => {
            let result = scanner::scan(execute)?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.orphans.is_empty() {
                println!("No orphaned processes found.");
            } else {
                println!("Found {} orphaned process(es):", result.orphan_count);
                for orphan in &result.orphans {
                    println!(
                        "  PID {} - {}\n    Command: {}",
                        orphan.pid, orphan.name, orphan.cmdline
                    );
                }

                if execute {
                    println!("\nCleaned up {} process(es).", result.orphan_count);
                } else {
                    println!("\nDry-run mode. Use --execute to clean up these processes.");
                }
            }
        }

        Commands::Clean { dry_run } => {
            let result = cleaner::clean(dry_run)?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.total == 0 {
                println!("No orphaned processes found to clean.");
            } else {
                println!("Found {} orphaned process(es) to clean:", result.total);
                for res in &result.results {
                    println!("  PID {} - {}", res.pid, res.name);
                }

                if dry_run {
                    println!("\nDry-run mode. No processes were terminated.");
                } else {
                    println!("\nCleanup complete:");
                    println!("  Successful: {}", result.successful);
                    println!("  Failed: {}", result.failed);

                    for res in &result.results {
                        if !res.success {
                            println!("  Failed to clean PID {} ({})", res.pid, res.name);
                        }
                    }
                }
            }
        }

        Commands::Tree { targets_only } => {
            visualize::print_tree(targets_only)?;
        }

        Commands::Dashboard => {
            visualize::open_dashboard()?;
        }

        Commands::Config(config_cmd) => match config_cmd {
            ConfigCommands::Edit => {
                println!("Opening configuration editor...");
                config::edit()?;
            }
            ConfigCommands::Show => {
                config::show(cli.json)?;
            }
        },

        Commands::Logs { follow, lines } => {
            logger::show_logs(follow, lines)?;
        }

        Commands::Session(session_cmd) => match session_cmd {
            SessionCommands::Register {
                id,
                name,
                source,
                parent_pid,
            } => {
                session::register(id, name, source, parent_pid)?;
            }
            SessionCommands::Track { session_id, pid } => {
                session::track(&session_id, pid)?;
            }
            SessionCommands::Clean {
                session_id,
                dry_run,
            } => {
                session::clean_session(&session_id, dry_run)?;
            }
            SessionCommands::List => {
                session::list()?;
            }
            SessionCommands::Unregister { session_id } => {
                session::unregister(&session_id)?;
            }
            SessionCommands::AutoClean { dry_run } => {
                session::auto_clean(dry_run)?;
            }
        },
    }

    Ok(())
}
