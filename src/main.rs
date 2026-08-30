mod cleaner;
mod cli;
mod config;
mod daemon;
mod doctor;
mod exec;
mod kill;
mod logger;
mod scanner;
mod session;
mod util;
mod visualize;
mod watch;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, ConfigCommands, SessionCommands};
use owo_colors::OwoColorize;
use util::use_color;

/// Runs the requested command.
///
/// `Ok(Some(code))` means the process must exit with exactly `code` — used by
/// `exec`, which has to be transparent about the wrapped command's status.
fn run() -> Result<Option<i32>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            foreground,
            dry_run,
        } => {
            if dry_run {
                println!(
                    "Starting proc-janitor daemon in DRY-RUN mode (no processes will be killed)..."
                );
            } else {
                println!("Starting proc-janitor daemon...");
            }
            daemon::start(foreground, dry_run)?;
        }

        Commands::Stop => {
            println!("Stopping proc-janitor daemon...");
            daemon::stop()?;
        }

        Commands::Restart {
            foreground,
            dry_run,
        } => {
            println!("Restarting proc-janitor daemon...");
            daemon::restart(foreground, dry_run)?;
        }

        Commands::Reload => {
            daemon::reload()?;
        }

        Commands::Status => {
            daemon::status(cli.json)?;
        }

        Commands::Scan { watch } => {
            let print_scan = |result: &scanner::ScanResult, json: bool, quiet: bool| {
                if json {
                    println!("{}", serde_json::to_string_pretty(result).unwrap());
                } else if result.orphans.is_empty() {
                    if !quiet {
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
                } else if quiet {
                    for orphan in &result.orphans {
                        println!("{}", orphan.pid);
                    }
                } else {
                    println!("Found {} orphaned process(es):", result.orphan_count);
                    for orphan in &result.orphans {
                        let mem = format_bytes(orphan.memory_bytes);
                        let uptime = format_duration(orphan.uptime_seconds);
                        println!(
                            "  PID {} - {} ({}  {}  {})\n    Command: {}",
                            orphan.pid,
                            orphan.name,
                            mem,
                            uptime,
                            orphan.evidence.label(),
                            orphan.cmdline
                        );
                    }
                    if use_color() {
                        println!(
                            "\n{}",
                            "Use 'proc-janitor clean' to kill these processes.".yellow()
                        );
                    } else {
                        println!("\nUse 'proc-janitor clean' to kill these processes.");
                    }
                }
            };

            if let Some(interval) = watch {
                let interval = interval.max(1); // minimum 1 second
                loop {
                    // Clear screen
                    print!("\x1B[2J\x1B[H");
                    if use_color() {
                        println!(
                            "{} (every {}s, Ctrl+C to stop)\n",
                            "proc-janitor watch".bold(),
                            interval
                        );
                    } else {
                        println!("proc-janitor watch (every {interval}s, Ctrl+C to stop)\n");
                    }
                    let result = scanner::scan()?;
                    print_scan(&result, cli.json, cli.quiet);
                    std::thread::sleep(std::time::Duration::from_secs(interval));
                }
            } else {
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

                print_scan(&result, cli.json, cli.quiet);
            }
        }

        Commands::Clean {
            pid,
            pattern,
            interactive,
            dry_run,
            yes,
            min_age,
        } => {
            let result = if dry_run {
                cleaner::clean_filtered(&pid, pattern.as_deref(), min_age, true, yes)?
            } else if interactive {
                cleaner::clean_interactive(&pid, pattern.as_deref(), min_age)?
            } else {
                cleaner::clean_filtered(&pid, pattern.as_deref(), min_age, false, yes)?
            };

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if result.aborted {
                // User declined at the confirmation prompt; cleaner already
                // printed a notice to stderr. Nothing more to report.
            } else if result.dry_run {
                if cli.quiet {
                    println!("{}", result.total);
                } else if result.total == 0 {
                    println!("[DRY-RUN] No orphaned processes would be killed.");
                } else {
                    println!(
                        "[DRY-RUN] {} orphaned process(es) would be killed:",
                        result.total
                    );
                    for res in &result.results {
                        println!("  PID {} - {}", res.pid, res.name);
                    }
                    println!("\nRun 'proc-janitor clean' (without --dry-run) to kill them.");
                }
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
            } else if cli.quiet {
                // Quiet mode: just counts for scripting
                println!("{}/{}", result.successful, result.total);
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

        Commands::Tree {
            targets_only,
            pattern,
        } => {
            visualize::print_tree(targets_only, pattern.as_deref())?;
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
                session::list(cli.json)?;
            }
            SessionCommands::Unregister { session_id } => {
                session::unregister(&session_id)?;
            }
            SessionCommands::AutoClean { dry_run } => {
                session::auto_clean(dry_run)?;
            }
        },

        Commands::Stats { days } => {
            daemon::show_stats(days, cli.json)?;
        }

        Commands::Version => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "license": env!("CARGO_PKG_LICENSE"),
                        "repository": env!("CARGO_PKG_REPOSITORY"),
                    }))?
                );
            } else {
                println!("proc-janitor {}", env!("CARGO_PKG_VERSION"));
                println!("License: {}", env!("CARGO_PKG_LICENSE"));
                println!("Repository: {}", env!("CARGO_PKG_REPOSITORY"));
            }
        }

        Commands::Completions { shell } => {
            use clap::CommandFactory;
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "proc-janitor", &mut std::io::stdout());
        }

        Commands::Doctor => {
            doctor::run()?;
        }

        Commands::Exec {
            command,
            sigterm_timeout,
        } => {
            exec::validate(&command)?;
            // Fall back to the configured timeout, and to the built-in default
            // when there is no usable config — `exec` must work before setup.
            let timeout = sigterm_timeout.unwrap_or_else(|| {
                config::Config::load()
                    .map(|c| c.sigterm_timeout)
                    .unwrap_or(5)
            });
            return Ok(Some(exec::run(&command, timeout)?));
        }
    }

    Ok(None)
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    } else if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

fn main() {
    match run() {
        // `exec` propagates the wrapped command's status verbatim.
        Ok(Some(code)) => std::process::exit(code),
        Ok(None) => {}
        Err(e) => {
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
}
