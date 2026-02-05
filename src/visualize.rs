//! Process visualization - tree view and HTML dashboard
//!
//! Provides visual representations of process hierarchies and
//! proc-janitor targets.

use anyhow::Result;
use owo_colors::OwoColorize;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

use crate::config::Config;
use crate::session::SessionStore;
use crate::util::use_color;

/// Escape JSON for safe embedding inside HTML <script> tags.
/// Prevents XSS via `</script>` breakout by replacing `</` with `<\/`.
fn escape_json_for_script(json: &str) -> String {
    json.replace("</", "<\\/")
}

/// Escape HTML special characters to prevent XSS in vis-network tooltips.
/// vis-network renders `title` fields as HTML, so user-controlled content must be escaped.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Process info for visualization
#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub memory_mb: f64,
    #[allow(dead_code)] // May be used for future CPU-based filtering
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
    let orphan_targets: Vec<_> = targets.iter().filter(|n| n.is_orphan).collect();

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

fn print_node(
    node: &ProcessNode,
    prefix: &str,
) {
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

// ============================================================================
// HTML Dashboard
// ============================================================================

/// Generate HTML dashboard. If `refresh_secs` is Some, adds auto-refresh meta tag.
pub fn generate_dashboard(refresh_secs: Option<u64>) -> Result<PathBuf> {
    let config = Config::load()?;
    let nodes = build_process_tree(&config)?;
    let session_store = SessionStore::load().unwrap_or_default();

    // Build data for visualization
    let targets: Vec<_> = nodes
        .values()
        .filter(|n| n.is_target && !n.is_whitelisted)
        .collect();

    let orphan_targets: Vec<_> = targets.iter().filter(|n| n.is_orphan).collect();

    // Build edges for graph
    let mut edges = Vec::new();
    for node in nodes.values() {
        if node.ppid > 0 && nodes.contains_key(&node.ppid) {
            // Only include edges for target processes and their ancestors
            if node.is_target || targets.iter().any(|t| is_ancestor(node.pid, t.pid, &nodes)) {
                edges.push((node.ppid, node.pid));
            }
        }
    }

    // Generate nodes JSON
    let nodes_json: Vec<String> = targets
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": n.pid,
                "label": format!("{} ({})", escape_html(&n.name), n.pid),
                "title": format!("PID: {}\nMemory: {:.1}MB\nCmd: {}", n.pid, n.memory_mb, escape_html(&n.cmdline.replace('\n', " "))),
                "color": if n.is_orphan { "#e74c3c" } else { "#f39c12" },
                "shape": if n.is_orphan { "diamond" } else { "dot" },
                "size": (n.memory_mb / 10.0).clamp(10.0, 50.0).round() as i32
            }).to_string()
        })
        .collect();

    // Also add parent processes that connect targets
    let mut parent_nodes = Vec::new();
    for (ppid, _pid) in &edges {
        if !targets.iter().any(|t| t.pid == *ppid) {
            if let Some(parent) = nodes.get(ppid) {
                if !parent_nodes.iter().any(|p: &ProcessNode| p.pid == *ppid) {
                    parent_nodes.push(parent.clone());
                }
            }
        }
    }

    let parent_nodes_json: Vec<String> = parent_nodes
        .iter()
        .map(|n| {
            serde_json::json!({
                "id": n.pid,
                "label": format!("{} ({})", escape_html(&n.name), n.pid),
                "title": format!("PID: {}\nMemory: {:.1}MB", n.pid, n.memory_mb),
                "color": "#95a5a6",
                "shape": "dot",
                "size": 15
            }).to_string()
        })
        .collect();

    let all_nodes_json = [nodes_json, parent_nodes_json].concat().join(",\n        ");

    // Generate edges JSON
    let edges_json: Vec<String> = edges
        .iter()
        .filter(|(ppid, pid)| {
            targets.iter().any(|t| t.pid == *pid || t.pid == *ppid)
                || parent_nodes.iter().any(|p| p.pid == *ppid)
        })
        .map(|(from, to)| format!(r#"{{"from": {from}, "to": {to}}}"#))
        .collect();
    let edges_json_str = edges_json.join(",\n        ");

    // Sessions JSON
    let sessions_json: Vec<String> = session_store
        .sessions
        .values()
        .map(|s| {
            serde_json::json!({
                "id": s.id,
                "name": s.name.as_deref().unwrap_or(""),
                "source": s.source.to_string(),
                "pids": s.pids.iter().map(|tp| tp.pid).collect::<Vec<u32>>(),
                "created": s.created_at.format("%Y-%m-%d %H:%M:%S").to_string()
            }).to_string()
        })
        .collect();
    let sessions_json_str = sessions_json.join(",\n        ");

    // Escape all JSON for safe embedding in <script> tags (prevent </script> breakout)
    let all_nodes_json = escape_json_for_script(&all_nodes_json);
    let edges_json_str = escape_json_for_script(&edges_json_str);
    let sessions_json_str = escape_json_for_script(&sessions_json_str);

    // Stats
    let total_memory: f64 = orphan_targets.iter().map(|n| n.memory_mb).sum();

    let refresh_meta = match refresh_secs {
        Some(secs) => format!(r#"<meta http-equiv="refresh" content="{secs}">"#),
        None => String::new(),
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    {}
    <title>proc-janitor Dashboard</title>
    <script src="https://unpkg.com/vis-network@9.1.6/standalone/umd/vis-network.min.js" integrity="sha384-wF3MqOaDOoJh1GJRKfhPEOBpFAxbPKKGilSOGMrqJVoJWiHRjLsKP4hq3kYMlBh" crossorigin="anonymous"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
        }}
        .header {{
            background: rgba(0,0,0,0.3);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        .header h1 {{
            font-size: 24px;
            font-weight: 600;
        }}
        .header h1 span {{ color: #e74c3c; }}
        .stats {{
            display: flex;
            gap: 30px;
        }}
        .stat {{
            text-align: center;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .stat-value.danger {{ color: #e74c3c; }}
        .stat-value.warning {{ color: #f39c12; }}
        .stat-value.success {{ color: #2ecc71; }}
        .stat-label {{
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
        }}
        .container {{
            display: grid;
            grid-template-columns: 1fr 350px;
            gap: 20px;
            padding: 20px;
            height: calc(100vh - 100px);
        }}
        .panel {{
            background: rgba(255,255,255,0.05);
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.1);
            overflow: hidden;
        }}
        .panel-header {{
            padding: 15px 20px;
            background: rgba(0,0,0,0.2);
            font-weight: 600;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .panel-content {{
            padding: 15px;
            height: calc(100% - 50px);
            overflow-y: auto;
        }}
        #network {{
            width: 100%;
            height: 100%;
        }}
        .process-card {{
            background: rgba(0,0,0,0.2);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
            border-left: 3px solid #e74c3c;
        }}
        .process-card.tracked {{
            border-left-color: #3498db;
        }}
        .process-name {{
            font-weight: 600;
            margin-bottom: 5px;
        }}
        .process-detail {{
            font-size: 12px;
            color: #888;
        }}
        .process-badges {{
            display: flex;
            gap: 5px;
            margin-top: 8px;
        }}
        .badge {{
            font-size: 10px;
            padding: 2px 8px;
            border-radius: 10px;
            background: rgba(255,255,255,0.1);
        }}
        .badge.orphan {{ background: #e74c3c; }}
        .badge.target {{ background: #f39c12; }}
        .badge.tracked {{ background: #3498db; }}
        .session-card {{
            background: rgba(52, 152, 219, 0.2);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 10px;
            border-left: 3px solid #3498db;
        }}
        .legend {{
            display: flex;
            gap: 20px;
            font-size: 12px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        .btn {{
            background: #e74c3c;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
        }}
        .btn:hover {{ background: #c0392b; }}
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
        .empty-state .emoji {{ font-size: 48px; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🧹 proc-<span>janitor</span> Dashboard</h1>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Processes</div>
            </div>
            <div class="stat">
                <div class="stat-value warning">{}</div>
                <div class="stat-label">Targets</div>
            </div>
            <div class="stat">
                <div class="stat-value danger">{}</div>
                <div class="stat-label">Cleanable</div>
            </div>
            <div class="stat">
                <div class="stat-value danger">{:.0} MB</div>
                <div class="stat-label">Reclaimable</div>
            </div>
            <div class="stat">
                <div class="stat-value success">{}</div>
                <div class="stat-label">Sessions</div>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <span>Process Graph</span>
                <div class="legend">
                    <div class="legend-item">
                        <div class="legend-color" style="background: #e74c3c;"></div>
                        <span>Orphan (Cleanable)</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #f39c12;"></div>
                        <span>Target</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color" style="background: #95a5a6;"></div>
                        <span>Parent</span>
                    </div>
                </div>
            </div>
            <div class="panel-content">
                <div id="network"></div>
            </div>
        </div>

        <div style="display: flex; flex-direction: column; gap: 20px;">
            <div class="panel" style="flex: 1;">
                <div class="panel-header">
                    <span>Cleanable Processes</span>
                    <button class="btn" onclick="alert('Run: proc-janitor clean')">Clean All</button>
                </div>
                <div class="panel-content" id="process-list"></div>
            </div>

            <div class="panel" style="flex: 1;">
                <div class="panel-header">
                    <span>Active Sessions</span>
                </div>
                <div class="panel-content" id="session-list"></div>
            </div>
        </div>
    </div>

    <script>
        // Process data
        const nodes = new vis.DataSet([
        {}
        ]);

        const edges = new vis.DataSet([
        {}
        ]);

        const sessions = [
        {}
        ];

        const cleanableProcesses = [
        {}
        ];

        // Initialize network
        const container = document.getElementById('network');
        const data = {{ nodes: nodes, edges: edges }};
        const options = {{
            nodes: {{
                font: {{ color: '#fff', size: 12 }},
                borderWidth: 2,
            }},
            edges: {{
                color: {{ color: '#555', highlight: '#888' }},
                arrows: {{ to: {{ enabled: true, scaleFactor: 0.5 }} }},
                smooth: {{ type: 'cubicBezier' }}
            }},
            physics: {{
                enabled: true,
                barnesHut: {{
                    gravitationalConstant: -2000,
                    springLength: 150
                }}
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 100
            }}
        }};

        const network = new vis.Network(container, data, options);

        // Render process list
        const processList = document.getElementById('process-list');
        if (cleanableProcesses.length === 0) {{
            const emptyDiv = document.createElement('div');
            emptyDiv.className = 'empty-state';
            const emojiDiv = document.createElement('div');
            emojiDiv.className = 'emoji';
            emojiDiv.textContent = '✨';
            const textDiv = document.createElement('div');
            textDiv.textContent = 'No orphan processes found';
            emptyDiv.appendChild(emojiDiv);
            emptyDiv.appendChild(textDiv);
            processList.appendChild(emptyDiv);
        }} else {{
            cleanableProcesses.forEach(p => {{
                const card = document.createElement('div');
                card.className = 'process-card';
                const nameDiv = document.createElement('div');
                nameDiv.className = 'process-name';
                nameDiv.textContent = p.name;
                const detailDiv = document.createElement('div');
                detailDiv.className = 'process-detail';
                detailDiv.textContent = 'PID: ' + p.pid + ' | Memory: ' + p.memory.toFixed(1) + ' MB';
                const badges = document.createElement('div');
                badges.className = 'process-badges';
                const orphanBadge = document.createElement('span');
                orphanBadge.className = 'badge orphan';
                orphanBadge.textContent = 'Orphan';
                const targetBadge = document.createElement('span');
                targetBadge.className = 'badge target';
                targetBadge.textContent = 'Target';
                badges.appendChild(orphanBadge);
                badges.appendChild(targetBadge);
                card.appendChild(nameDiv);
                card.appendChild(detailDiv);
                card.appendChild(badges);
                processList.appendChild(card);
            }});
        }}

        // Render session list
        const sessionList = document.getElementById('session-list');
        if (sessions.length === 0) {{
            const emptyDiv = document.createElement('div');
            emptyDiv.className = 'empty-state';
            const emojiDiv = document.createElement('div');
            emojiDiv.className = 'emoji';
            emojiDiv.textContent = '📭';
            const textDiv = document.createElement('div');
            textDiv.textContent = 'No active sessions';
            emptyDiv.appendChild(emojiDiv);
            emptyDiv.appendChild(textDiv);
            sessionList.appendChild(emptyDiv);
        }} else {{
            sessions.forEach(s => {{
                const card = document.createElement('div');
                card.className = 'session-card';
                const nameDiv = document.createElement('div');
                nameDiv.className = 'process-name';
                nameDiv.textContent = s.name || s.id;
                const detailDiv1 = document.createElement('div');
                detailDiv1.className = 'process-detail';
                detailDiv1.textContent = 'Source: ' + s.source + ' | PIDs: ' + s.pids.length;
                const detailDiv2 = document.createElement('div');
                detailDiv2.className = 'process-detail';
                detailDiv2.textContent = 'Created: ' + s.created;
                card.appendChild(nameDiv);
                card.appendChild(detailDiv1);
                card.appendChild(detailDiv2);
                sessionList.appendChild(card);
            }});
        }}
    </script>
</body>
</html>"#,
        refresh_meta,
        nodes.len(),
        targets.len(),
        orphan_targets.len(),
        total_memory,
        session_store.sessions.len(),
        all_nodes_json,
        edges_json_str,
        sessions_json_str,
        escape_json_for_script(
            &orphan_targets
                .iter()
                .map(|n| serde_json::json!({
                    "pid": n.pid,
                    "name": n.name,
                    "memory": n.memory_mb
                }).to_string())
                .collect::<Vec<_>>()
                .join(",\n        ")
        )
    );

    // Write to temp file
    // Fallback to current directory if HOME not available (acceptable here)
    let output_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".proc-janitor")
        .join("dashboard.html");

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    } else {
        anyhow::bail!("Cannot determine parent directory for dashboard output path");
    }
    crate::util::check_not_symlink(&output_path)?;
    fs::write(&output_path, html)?;

    Ok(output_path)
}

fn is_ancestor(potential_ancestor: u32, target: u32, nodes: &HashMap<u32, ProcessNode>) -> bool {
    let mut current = target;
    let mut visited = HashSet::new();
    while let Some(node) = nodes.get(&current) {
        if !visited.insert(current) {
            break; // Cycle detected
        }
        if node.ppid == potential_ancestor {
            return true;
        }
        if node.ppid == 0 || node.ppid == current {
            break;
        }
        current = node.ppid;
    }
    false
}

/// Open dashboard in browser. If `live` is true, regenerate the HTML every `interval` seconds.
pub fn open_dashboard(live: bool, interval: u64) -> Result<()> {
    let refresh_secs = if live { Some(interval) } else { None };
    let path = generate_dashboard(refresh_secs)?;

    println!("Dashboard generated: {}", path.display());
    println!("Opening in browser...");

    #[cfg(target_os = "macos")]
    {
        let mut child = std::process::Command::new("open").arg(&path).spawn()?;
        // Wait briefly for the launcher to hand off to the browser
        let _ = child.wait();
    }

    #[cfg(target_os = "linux")]
    {
        let mut child = std::process::Command::new("xdg-open").arg(&path).spawn()?;
        let _ = child.wait();
    }

    if live {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .unwrap_or_else(|e| {
            eprintln!("Warning: Could not set Ctrl+C handler: {e}. Use 'kill' to stop live mode.");
        });

        println!(
            "Live mode: refreshing every {interval}s. Press Ctrl+C to stop."
        );
        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_secs(interval));
            if !running.load(Ordering::SeqCst) {
                break;
            }
            if let Err(e) = generate_dashboard(refresh_secs) {
                eprintln!("Warning: Failed to regenerate dashboard: {e}");
            }
        }
        println!("\nLive mode stopped.");
    }

    Ok(())
}
