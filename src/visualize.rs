//! Process visualization - tree view
//!
//! Provides visual representations of process hierarchies and
//! proc-janitor targets.

use anyhow::Result;
use owo_colors::OwoColorize;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

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
    #[allow(dead_code)]
    pub cpu_percent: f32,
    pub is_target: bool,      // Matches our target patterns
    pub is_whitelisted: bool, // In whitelist
    pub is_orphan: bool,      // PPID = 1
    pub session_id: Option<String>,
}

/// Build process tree and identify targets
pub fn build_process_tree(config: &Config) -> Result<HashMap<u32, ProcessNode>> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All);

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
        .filter_map(|p| match Regex::new(p) {
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
        .filter_map(|p| match Regex::new(p) {
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

        let is_target = matches_patterns(&cmdline, &target_patterns);
        let is_whitelisted = matches_patterns(&cmdline, &whitelist_patterns);
        let is_orphan = ppid == 1;

        nodes.insert(
            pid_u32,
            ProcessNode {
                pid: pid_u32,
                ppid,
                name,
                cmdline: if cmdline.chars().count() > 80 {
                    format!("{}...", cmdline.chars().take(77).collect::<String>())
                } else {
                    cmdline
                },
                memory_mb: process.memory() as f64 / 1024.0 / 1024.0,
                cpu_percent: process.cpu_usage(),
                is_target,
                is_whitelisted,
                is_orphan,
                session_id: pid_to_session.get(&pid_u32).cloned(),
            },
        );
    }

    Ok(nodes)
}

fn matches_patterns(text: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|re| re.is_match(text))
}

/// Recursively collect all descendant PIDs of a given process
fn collect_orphan_tree(
    pid: u32,
    children: &HashMap<u32, Vec<u32>>,
    result: &mut HashSet<u32>,
) {
    if let Some(child_pids) = children.get(&pid) {
        for &child in child_pids {
            if result.insert(child) {
                collect_orphan_tree(child, children, result);
            }
        }
    }
}

// ============================================================================
// ASCII Tree View
// ============================================================================

/// Print ASCII process tree
pub fn print_tree(filter_targets: bool) -> Result<()> {
    let config = Config::load()?;
    let nodes = build_process_tree(&config)?;

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
            collect_orphan_tree(node.pid, &children, &mut orphan_tree_pids);
        }
    }
    let orphan_targets: Vec<_> = targets
        .iter()
        .filter(|n| orphan_tree_pids.contains(&n.pid))
        .collect();

    let stats_line = format!(
        "  Total: {}  |  Targets: {}  |  Orphan Targets: {} (cleanable)",
        total,
        targets.len(),
        orphan_targets.len()
    );
    let box_width = 78;
    let title = "proc-janitor Process Tree";
    let title_pad = (box_width - 2 - title.len()) / 2;
    println!("{}", "=".repeat(box_width));
    println!(
        "|{}{}{}|",
        " ".repeat(title_pad),
        title,
        " ".repeat(box_width - 2 - title_pad - title.len())
    );
    println!("{}", "=".repeat(box_width));
    let stats_pad = box_width - 2 - stats_line.len();
    if stats_pad > 0 {
        println!("|{}{}|", stats_line, " ".repeat(stats_pad));
    } else {
        println!("| {stats_line} |");
    }
    println!("{}", "=".repeat(box_width));
    println!();

    // Legend
    println!("Legend: 🎯 Target  ⛔ Whitelisted  👻 Orphan (PPID=1)  📎 Tracked Session");
    println!();

    if filter_targets {
        // Only show target processes and their ancestors
        println!("── Showing target processes only ──");
        println!();
        for node in &targets {
            print_node(node, "");
        }
    } else {
        // Show process tree starting from init (PID 1)
        if let Some(init_children) = children.get(&1) {
            println!("init (PID 1)");
            let len = init_children.len();
            for (i, &pid) in init_children.iter().enumerate() {
                if let Some(node) = nodes.get(&pid) {
                    // Skip non-interesting processes unless they're targets
                    if (!node.is_target || node.is_whitelisted)
                        && !has_target_descendant(pid, &children, &nodes, &mut HashSet::new())
                    {
                        continue;
                    }
                    let is_last = i == len - 1;
                    print_subtree(node, "", is_last, &children, &nodes, &mut HashSet::new());
                }
            }
        }
    }

    // Summary of cleanable processes
    if !orphan_targets.is_empty() {
        println!();
        let box_width = 78;
        println!("┌{}┐", "─".repeat(box_width - 2));
        let title = " Cleanable Orphan Processes";
        let title_pad = box_width - 2 - title.chars().count();
        println!("│{}{}│", title, " ".repeat(title_pad));
        println!("├{}┤", "─".repeat(box_width - 2));
        for node in orphan_targets {
            let line = format!(
                "  PID {:>6}  {:>6.1} MB  {}",
                node.pid,
                node.memory_mb,
                truncate(&node.name, 50)
            );
            let line_pad = box_width - 2 - line.chars().count();
            println!("│{}{}│", line, " ".repeat(line_pad));
        }
        println!("└{}┘", "─".repeat(box_width - 2));
        println!();
        println!("Run `proc-janitor clean` to terminate these processes.");
    }

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
) {
    if !visited.insert(node.pid) {
        return; // Already visited, cycle detected
    }
    let connector = if is_last { "└── " } else { "├── " };
    print_node(node, &format!("{prefix}{connector}"));

    let new_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });

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
                print_subtree(child_node, &new_prefix, is_last, children, nodes, visited);
            }
        }
    }
}

fn print_node(node: &ProcessNode, prefix: &str) {
    let mut markers = String::new();
    if node.is_target && !node.is_whitelisted {
        markers.push('🎯');
    }
    if node.is_whitelisted {
        markers.push('⛔');
    }
    if node.is_orphan {
        markers.push('👻');
    }
    if node.session_id.is_some() {
        markers.push('📎');
    }

    let mem_str = if use_color() {
        if node.memory_mb > 100.0 {
            format!("{:>6.1}MB", node.memory_mb).red().to_string()
        } else if node.memory_mb > 50.0 {
            format!("{:>6.1}MB", node.memory_mb).yellow().to_string()
        } else {
            format!("{:>6.1}MB", node.memory_mb)
        }
    } else {
        format!("{:>6.1}MB", node.memory_mb)
    };

    let name_colored = if use_color() && node.is_target && !node.is_whitelisted {
        if node.is_orphan {
            node.name.red().to_string()
        } else {
            node.name.yellow().to_string()
        }
    } else {
        node.name.clone()
    };

    println!(
        "{}{} [{}] {} {}",
        prefix, name_colored, node.pid, mem_str, markers
    );
}

fn truncate(s: &str, max_len: usize) -> String {
    if max_len < 4 {
        return s.chars().take(max_len).collect();
    }
    if s.chars().count() > max_len {
        format!("{}...", s.chars().take(max_len - 3).collect::<String>())
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        assert_eq!(truncate("hello world!", 8), "hello...");
        assert_eq!(truncate("abcdefghij", 7), "abcd...");
    }

    #[test]
    fn test_truncate_very_short_max() {
        assert_eq!(truncate("hello", 3), "hel");
        assert_eq!(truncate("hello", 1), "h");
    }

    #[test]
    fn test_truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_unicode() {
        // Unicode characters should be counted correctly
        assert_eq!(truncate("한글테스트입니다", 5), "한글...");
    }

    #[test]
    fn test_matches_patterns_basic() {
        let patterns = vec![
            Regex::new("node.*claude").unwrap(),
            Regex::new("python").unwrap(),
        ];
        assert!(matches_patterns("node --experimental claude", &patterns));
        assert!(matches_patterns("python script.py", &patterns));
        assert!(!matches_patterns("cargo build", &patterns));
    }

    #[test]
    fn test_matches_patterns_empty() {
        let patterns: Vec<Regex> = vec![];
        assert!(!matches_patterns("anything", &patterns));
    }
}
