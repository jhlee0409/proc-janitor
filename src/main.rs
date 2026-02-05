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

        Commands::Scan { execute } => {
            let spinner = if !cli.json {
                let sp = indicatif::ProgressBar::new_spinner();
                sp.set_message("Scanning for orphaned processes...");
                sp.enable_steady_tick(std::time::Duration::from_millis(100));
                Some(sp)
            } else {
                None
            };

            let result = scanner::scan(execute)?;

            if let Some(sp) = spinner {
                sp.finish_and_clear();
            }

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.orphans.is_empty() {
                if use_color() {
                    println!("{}", "No orphaned processes found.".green());
                } else {
                    println!("No orphaned processes found.");
                }
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
                } else if use_color() {
                    println!(
                        "\n{}",
                        "Dry-run mode. Use --execute to clean up these processes.".yellow()
                    );
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
                if use_color() {
                    println!("{}", "No orphaned processes found to clean.".green());
                } else {
                    println!("No orphaned processes found to clean.");
                }
            } else {
                println!("Found {} orphaned process(es) to clean:", result.total);
                for res in &result.results {
                    println!("  PID {} - {}", res.pid, res.name);
                }

                if dry_run {
                    if use_color() {
                        println!(
                            "\n{}",
                            "Dry-run mode. No processes were terminated.".yellow()
                        );
                    } else {
                        println!("\nDry-run mode. No processes were terminated.");
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
                                        format!(
                                            "Failed to clean PID {} ({})",
                                            res.pid, res.name
                                        )
                                        .red()
                                    );
                                }
                            } else if let Some(ref err) = res.error_message {
                                println!(
                                    "  Failed to clean PID {} ({}): {}",
                                    res.pid, res.name, err
                                );
                            } else {
                                println!("  Failed to clean PID {} ({})", res.pid, res.name);
                            }
                        }
                    }
                }
            }
        }

        Commands::Tree { targets_only } => {
            visualize::print_tree(targets_only)?;
        }

        Commands::Dashboard { live, interval } => {
            visualize::open_dashboard(live, interval)?;
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
        } else if err_str_lower.contains("not running")
            || err_str_lower.contains("no such file")
        {
            5
        } else {
            1
        };
        std::process::exit(code);
    }
}
