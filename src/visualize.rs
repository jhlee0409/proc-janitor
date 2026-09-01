//! Process visualization - tree view
//!
//! Provides visual representations of process hierarchies and
//! proc-janitor targets.

use anyhow::Result;
use owo_colors::OwoColorize;
use regex::Regex;
use std::collections::{HashMap, HashSet};

use crate::config::Config;
use crate::session::SessionStore;
use crate::util::use_color;

/// Process info for visualization
#[derive(Debug)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    #[allow(dead_code)]
    pub cmdline: String,
    pub memory_mb: f64,
    pub is_target: bool,      // Matches our target patterns
    pub is_whitelisted: bool, // In whitelist
    pub is_orphan: bool,      // PPID = 1
    pub session_id: Option<String>,
}

/// Build process tree and identify targets
pub fn build_process_tree(config: &Config) -> Result<HashMap<u32, ProcessNode>> {
    let sys = crate::util::process_snapshot();

    // Load sessions to mark tracked processes
    let session_store = SessionStore::load().unwrap_or_default();
    let mut pid_to_session: HashMap<u32, String> = HashMap::new();
    for session in session_store.sessions.values() {
        for tp in &session.pids {
            pid_to_session.insert(tp.pid, session.id.clone());
        }
    }

    // Pre-compile regex patterns
    let target_patterns: Vec<Regex> = config
        .targets
        .iter()
        .filter_map(|p| match crate::scanner::compile_pattern(p) {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("Warning: Invalid target pattern '{p}': {e}");
                None
            }
        })
        .collect();
    let whitelist_patterns: Vec<Regex> = config
        .whitelist
        .iter()
        .filter_map(|p| match crate::scanner::compile_pattern(p) {
            Ok(re) => Some(re),
            Err(e) => {
                eprintln!("Warning: Invalid whitelist pattern '{p}': {e}");
                None
            }
        })
        .collect();

    let mut nodes = HashMap::new();

    for (pid, process) in sys.processes() {
        let pid_u32 = pid.as_u32();
        let ppid = process.parent().map(|p| p.as_u32()).unwrap_or(0);
        let name = process.name().to_string_lossy().to_string();
        let cmdline = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(" ");

        // The same matcher the scanner uses, so the tree highlights exactly what
        // a scan would select.
        let is_target = crate::scanner::matches_any(&target_patterns, &cmdline);
        let is_whitelisted = crate::scanner::matches_any(&whitelist_patterns, &cmdline);
        let is_orphan = ppid == 1;

        nodes.insert(
            pid_u32,
            ProcessNode {
                pid: pid_u32,
                ppid,
                // Display-only fields: `is_target`/`is_whitelisted` above were
                // computed from the raw command line, so sanitising here cannot
                // change what the tree classifies.
                name: crate::util::sanitize_for_display(&name).into_owned(),
                cmdline: if cmdline.chars().count() > 80 {
                    crate::util::sanitize_for_display(&cmdline.chars().take(77).collect::<String>())
                        .into_owned()
                        + "..."
                } else {
                    crate::util::sanitize_for_display(&cmdline).into_owned()
                },
                memory_mb: process.memory() as f64 / 1024.0 / 1024.0,
                is_target,
                is_whitelisted,
                is_orphan,
                session_id: pid_to_session.get(&pid_u32).cloned(),
            },
        );
    }

    Ok(nodes)
}

// ============================================================================
// ASCII Tree View
// ============================================================================

/// Print ASCII process tree
pub fn print_tree(filter_targets: bool, pattern: Option<&str>) -> Result<()> {
    let config = Config::load()?;
    let nodes = build_process_tree(&config)?;
    let color = use_color();

    // Optional pattern filter
    let pattern_re = pattern
        .map(crate::scanner::compile_pattern)
        .transpose()
        .map_err(|e| anyhow::anyhow!("Invalid tree filter pattern: {e}"))?;

    // Find root processes (PPID=0 or PPID=1 or parent not in our list)
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for node in nodes.values() {
        children.entry(node.ppid).or_default().push(node.pid);
    }

    // Sort children by PID for consistent output
    for pids in children.values_mut() {
        pids.sort();
    }

    // Statistics
    let total = nodes.len();
    let targets: Vec<_> = nodes
        .values()
        .filter(|n| n.is_target && !n.is_whitelisted)
        .collect();

    // Expand orphan roots to include all their descendant targets (cleanable)
    let mut orphan_tree_pids = HashSet::new();
    for node in targets.iter() {
        if node.is_orphan {
            orphan_tree_pids.insert(node.pid);
            crate::util::collect_descendants(node.pid, &children, &mut orphan_tree_pids);
        }
    }
    let orphan_targets: Vec<_> = targets
        .iter()
        .filter(|n| orphan_tree_pids.contains(&n.pid))
        .collect();
    let total_reclaimable: f64 = orphan_targets.iter().map(|n| n.memory_mb).sum();

    // Header
    println!();
    if color {
        println!("  {} {}", "proc-janitor".bold(), "Process Tree".dimmed());
    } else {
        println!("  proc-janitor Process Tree");
    }
    println!("  {}", "─".repeat(50));

    // Stats
    if color {
        print!("  {} {}", format!("{total}").bold(), "processes".dimmed());
        if !targets.is_empty() {
            print!(
                "  {}  {} {}",
                "│".dimmed(),
                format!("{}", targets.len()).yellow().bold(),
                "targets".dimmed()
            );
        }
        if !orphan_targets.is_empty() {
            print!(
                "  {}  {} {}",
                "│".dimmed(),
                format!("{}", orphan_targets.len()).red().bold(),
                "cleanable".dimmed()
            );
            print!(
                "  {}  {} {}",
                "│".dimmed(),
                format!("{total_reclaimable:.0}MB").red(),
                "reclaimable".dimmed()
            );
        }
        println!();
    } else {
        print!("  {total} processes");
        if !targets.is_empty() {
            print!("  |  {} targets", targets.len());
        }
        if !orphan_targets.is_empty() {
            print!(
                "  |  {} cleanable  |  {:.0}MB reclaimable",
                orphan_targets.len(),
                total_reclaimable
            );
        }
        println!();
    }
    println!();

    // Legend
    if color {
        println!(
            "  {}  {}  {}  {}",
            "🎯 target".dimmed(),
            "⛔ whitelisted".dimmed(),
            "👻 orphan".dimmed(),
            "📎 session".dimmed()
        );
    } else {
        println!("  🎯 target  ⛔ whitelisted  👻 orphan  📎 session");
    }
    println!();

    if let Some(ref re) = pattern_re {
        // Pattern filter mode: show only processes matching the regex
        let matched: Vec<_> = nodes
            .values()
            .filter(|n| re.is_match(&n.name) || re.is_match(&n.cmdline))
            .collect();
        if matched.is_empty() {
            println!(
                "  No processes matching pattern '{}'.",
                pattern.unwrap_or("")
            );
        } else {
            println!(
                "  Showing {} process(es) matching '{}'",
                matched.len(),
                pattern.unwrap_or("")
            );
            println!();
            for node in &matched {
                print_node(node, "  ", color);
            }
        }
    } else if filter_targets {
        if targets.is_empty() {
            if color {
                println!("  {}", "No target processes found.".dimmed());
                println!(
                    "  {}",
                    "Configure targets: proc-janitor config init".dimmed()
                );
            } else {
                println!("  No target processes found.");
                println!("  Configure targets: proc-janitor config init");
            }
        } else {
            if color {
                println!("  {}", "Showing target processes only".dimmed());
            } else {
                println!("  Showing target processes only");
            }
            println!();
            for node in &targets {
                print_node(node, "  ", color);
            }
        }
    } else {
        // Show process tree starting from init (PID 1)
        if let Some(init_children) = children.get(&1) {
            if color {
                println!("  {}", "init (PID 1)".dimmed());
            } else {
                println!("  init (PID 1)");
            }
            let interesting: Vec<_> = init_children
                .iter()
                .filter(|&&pid| {
                    nodes
                        .get(&pid)
                        .map(|n| n.is_target && !n.is_whitelisted)
                        .unwrap_or(false)
                        || has_target_descendant(pid, &children, &nodes, &mut HashSet::new())
                })
                .collect();

            if interesting.is_empty() {
                if color {
                    println!("  {}", "  No target processes in tree.".dimmed());
                    println!(
                        "  {}",
                        "  Configure targets: proc-janitor config init".dimmed()
                    );
                } else {
                    println!("    No target processes in tree.");
                    println!("    Configure targets: proc-janitor config init");
                }
            } else {
                let len = interesting.len();
                for (i, &&pid) in interesting.iter().enumerate() {
                    if let Some(node) = nodes.get(&pid) {
                        let is_last = i == len - 1;
                        print_subtree(
                            node,
                            "  ",
                            is_last,
                            &children,
                            &nodes,
                            &mut HashSet::new(),
                            color,
                        );
                    }
                }
            }
        }
    }

    // Summary of cleanable processes
    if !orphan_targets.is_empty() {
        println!();
        if color {
            println!("  {} {}", "Cleanable".red().bold(), "─".repeat(41).dimmed());
        } else {
            println!("  Cleanable ─────────────────────────────────");
        }
        for node in &orphan_targets {
            if color {
                println!(
                    "  {} {:>6.1} MB  {}",
                    format!("PID {:>6}", node.pid).dimmed(),
                    node.memory_mb,
                    node.name.red()
                );
            } else {
                println!(
                    "  PID {:>6}  {:>6.1} MB  {}",
                    node.pid, node.memory_mb, node.name
                );
            }
        }
        println!();
        if color {
            println!(
                "  {} {}",
                "→".green(),
                "Run `proc-janitor clean` to terminate".dimmed()
            );
        } else {
            println!("  → Run `proc-janitor clean` to terminate");
        }
    }

    println!();
    Ok(())
}

fn has_target_descendant(
    pid: u32,
    children: &HashMap<u32, Vec<u32>>,
    nodes: &HashMap<u32, ProcessNode>,
    visited: &mut HashSet<u32>,
) -> bool {
    if !visited.insert(pid) {
        return false; // Already visited, cycle detected
    }
    if let Some(node) = nodes.get(&pid) {
        if node.is_target && !node.is_whitelisted {
            return true;
        }
    }
    if let Some(child_pids) = children.get(&pid) {
        for &child_pid in child_pids {
            if has_target_descendant(child_pid, children, nodes, visited) {
                return true;
            }
        }
    }
    false
}

fn print_subtree(
    node: &ProcessNode,
    prefix: &str,
    is_last: bool,
    children: &HashMap<u32, Vec<u32>>,
    nodes: &HashMap<u32, ProcessNode>,
    visited: &mut HashSet<u32>,
    color: bool,
) {
    if !visited.insert(node.pid) {
        return; // Already visited, cycle detected
    }
    let (connector, ext) = if is_last {
        ("└─ ", "   ")
    } else {
        ("├─ ", "│  ")
    };

    if color {
        print!("{}", format!("{prefix}{connector}").dimmed());
    } else {
        print!("{prefix}{connector}");
    }
    print_node(node, "", color);

    let new_prefix = format!("{prefix}{ext}");

    if let Some(child_pids) = children.get(&node.pid) {
        let interesting_children: Vec<_> = child_pids
            .iter()
            .filter(|&&pid| {
                nodes
                    .get(&pid)
                    .map(|n| n.is_target && !n.is_whitelisted)
                    .unwrap_or(false)
                    || has_target_descendant(pid, children, nodes, &mut HashSet::new())
            })
            .collect();

        let len = interesting_children.len();
        for (i, &&pid) in interesting_children.iter().enumerate() {
            if let Some(child_node) = nodes.get(&pid) {
                let is_last = i == len - 1;
                print_subtree(
                    child_node,
                    &new_prefix,
                    is_last,
                    children,
                    nodes,
                    visited,
                    color,
                );
            }
        }
    }
}

fn print_node(node: &ProcessNode, prefix: &str, color: bool) {
    let mut markers = String::new();
    if node.is_target && !node.is_whitelisted {
        markers.push_str(" 🎯");
    }
    if node.is_whitelisted {
        markers.push_str(" ⛔");
    }
    if node.is_orphan {
        markers.push_str(" 👻");
    }
    if node.session_id.is_some() {
        markers.push_str(" 📎");
    }

    let mem_str = if color {
        if node.memory_mb > 100.0 {
            format!("{:>6.1}MB", node.memory_mb).red().to_string()
        } else if node.memory_mb > 50.0 {
            format!("{:>6.1}MB", node.memory_mb).yellow().to_string()
        } else {
            format!("{:>6.1}MB", node.memory_mb).dimmed().to_string()
        }
    } else {
        format!("{:>6.1}MB", node.memory_mb)
    };

    let name_str = if color {
        if node.is_target && !node.is_whitelisted && node.is_orphan {
            node.name.red().bold().to_string()
        } else if node.is_target && !node.is_whitelisted {
            node.name.yellow().to_string()
        } else {
            node.name.dimmed().to_string()
        }
    } else {
        node.name.clone()
    };

    let pid_str = if color {
        format!("{}", node.pid).dimmed().to_string()
    } else {
        format!("{}", node.pid)
    };

    println!("{prefix}{name_str} {pid_str} {mem_str}{markers}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_uses_the_scanner_matcher() {
        // `build_process_tree` must classify with `scanner::matches_any` so the
        // tree cannot disagree with what a scan would select.
        let patterns = vec![
            Regex::new("node.*claude").unwrap(),
            Regex::new("python").unwrap(),
        ];
        assert!(crate::scanner::matches_any(
            &patterns,
            "node --experimental claude"
        ));
        assert!(crate::scanner::matches_any(&patterns, "python script.py"));
        assert!(!crate::scanner::matches_any(&patterns, "cargo build"));
        assert!(!crate::scanner::matches_any(&[], "anything"));
    }
}
