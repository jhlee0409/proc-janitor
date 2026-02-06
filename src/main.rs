mod cleaner;
mod cli;
mod config;
mod daemon;
mod doctor;
mod kill;
mod logger;
mod scanner;
mod session;
mod util;
mod visualize;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, ConfigCommands, SessionCommands};
use owo_colors::OwoColorize;
use util::use_color;

fn run() -> Result<()> {
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

        Commands::Scan => {
            let spinner = if !cli.json && !cli.quiet {
                let sp = indicatif::ProgressBar::new_spinner();
                sp.set_message("Scanning for orphaned processes...");
                sp.enable_steady_tick(std::time::Duration::from_millis(100));
                Some(sp)
            } else {
                None
            };

            let result = scanner::scan()?;

            if let Some(sp) = spinner {
                sp.finish_and_clear();
            }

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.orphans.is_empty() {
                if !cli.quiet {
                    if use_color() {
                        println!("{}", "No orphaned processes found.".green());
                    } else {
                        println!("No orphaned processes found.");
                    }
                    if !result.targets_configured {
                        if use_color() {
                            println!(
                                "\n{}",
                                "No target patterns configured. Run 'proc-janitor config init' to set up targets."
                                    .yellow()
                            );
                        } else {
                            println!(
                                "\nNo target patterns configured. Run 'proc-janitor config init' to set up targets."
                            );
                        }
                    }
                }
            } else {
                println!("Found {} orphaned process(es):", result.orphan_count);
                for orphan in &result.orphans {
                    println!(
                        "  PID {} - {}\n    Command: {}",
                        orphan.pid, orphan.name, orphan.cmdline
                    );
                }
                if !cli.quiet && use_color() {
                    println!(
                        "\n{}",
                        "Use 'proc-janitor clean' to kill these processes.".yellow()
                    );
                } else if !cli.quiet {
                    println!("\nUse 'proc-janitor clean' to kill these processes.");
                }
            }
        }

        Commands::Clean { pid, pattern } => {
            let result = cleaner::clean_filtered(&pid, pattern.as_deref())?;

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.total == 0 {
                if !cli.quiet {
                    if use_color() {
                        println!("{}", "No orphaned processes found to clean.".green());
                    } else {
                        println!("No orphaned processes found to clean.");
                    }
                    if pid.is_empty() && pattern.is_none() && !result.targets_configured {
                        if use_color() {
                            println!(
                                "\n{}",
                                "No target patterns configured. Run 'proc-janitor config init' to set up targets."
                                    .yellow()
                            );
                        } else {
                            println!(
                                "\nNo target patterns configured. Run 'proc-janitor config init' to set up targets."
                            );
                        }
                    }
                }
            } else {
                if result.failed == 0 && use_color() {
                    println!("\n{}", "Cleanup complete:".green());
                } else {
                    println!("\nCleanup complete:");
                }
                println!("  Successful: {}", result.successful);
                println!("  Failed: {}", result.failed);

                for res in &result.results {
                    if !res.success {
                        if use_color() {
                            if let Some(ref err) = res.error_message {
                                println!(
                                    "  {}",
                                    format!(
                                        "Failed to clean PID {} ({}): {}",
                                        res.pid, res.name, err
                                    )
                                    .red()
                                );
                            } else {
                                println!(
                                    "  {}",
                                    format!("Failed to clean PID {} ({})", res.pid, res.name).red()
                                );
                            }
                        } else if let Some(ref err) = res.error_message {
                            println!("  Failed to clean PID {} ({}): {}", res.pid, res.name, err);
                        } else {
                            println!("  Failed to clean PID {} ({})", res.pid, res.name);
                        }
                    }
                }
            }
        }

        Commands::Tree { targets_only } => {
            visualize::print_tree(targets_only)?;
        }

        Commands::Config(config_cmd) => match config_cmd {
            ConfigCommands::Init {
                force,
                preset,
                list_presets,
                yes,
            } => {
                if list_presets {
                    println!("Available presets:");
                    println!("  claude   - Target Claude Code & MCP server processes");
                    println!("             Patterns: node.*claude, claude, node.*mcp");
                    println!("  dev      - Target common dev tools");
                    println!("             Patterns: node, cargo, python, webpack|vite|esbuild");
                    println!("  minimal  - Empty targets for fully manual configuration");
                    println!("\nUsage: proc-janitor config init --preset <name>");
                } else {
                    config::init(force, preset, yes)?;
                }
            }
            ConfigCommands::Edit => {
                println!("Opening configuration editor...");
                config::edit()?;
            }
            ConfigCommands::Show => {
                config::show(cli.json)?;
            }
            ConfigCommands::Env => {
                config::show_env()?;
            }
            ConfigCommands::Validate => {
                config::validate_cmd()?;
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

        Commands::Version => {
            println!("proc-janitor {}", env!("CARGO_PKG_VERSION"));
            println!("License: {}", env!("CARGO_PKG_LICENSE"));
            println!("Repository: {}", env!("CARGO_PKG_REPOSITORY"));
        }

        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "proc-janitor", &mut std::io::stdout());
        }

        Commands::Doctor => {
            doctor::run()?;
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        let err_str = format!("{e:#}");
        if use_color() {
            eprintln!("{} {}", "error:".red().bold(), err_str);
        } else {
            eprintln!("error: {err_str}");
        }

        let err_str_lower = err_str.to_lowercase();
        let code = if err_str_lower.contains("permission denied")
            || err_str_lower.contains("operation not permitted")
        {
            3
        } else if err_str_lower.contains("already running") {
            4
        } else if err_str_lower.contains("not running") || err_str_lower.contains("no such file") {
            5
        } else {
            1
        };
        std::process::exit(code);
    }
}
