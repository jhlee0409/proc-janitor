#!/bin/bash
# Claude Code + proc-janitor Integration Setup
# Automatically clean up orphan processes when Claude Code sessions end

set -e

CLAUDE_SETTINGS="$HOME/.claude/settings.json"
PROC_JANITOR_BIN="${PROC_JANITOR_BIN:-proc-janitor}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🧹 Claude Code + proc-janitor Integration Setup"
echo "================================================"
echo ""

# Check if proc-janitor is installed
if ! command -v "$PROC_JANITOR_BIN" &> /dev/null; then
    echo -e "${RED}Error: proc-janitor not found in PATH${NC}"
    echo "Please install proc-janitor first:"
    echo "  cargo install --path ."
    echo "  # or"
    echo "  ./scripts/install.sh --install"
    exit 1
fi

echo -e "${GREEN}✓${NC} proc-janitor found: $(which $PROC_JANITOR_BIN)"

# Check if Claude settings directory exists
if [ ! -d "$HOME/.claude" ]; then
    echo -e "${YELLOW}Creating ~/.claude directory...${NC}"
    mkdir -p "$HOME/.claude"
fi

# Backup existing settings
if [ -f "$CLAUDE_SETTINGS" ]; then
    BACKUP_FILE="$CLAUDE_SETTINGS.backup.$(date +%Y%m%d_%H%M%S)"
    cp "$CLAUDE_SETTINGS" "$BACKUP_FILE"
    echo -e "${GREEN}✓${NC} Backed up existing settings to: $BACKUP_FILE"
fi

# Create or update settings with hooks
# Using a temporary file and jq-like manipulation with pure bash/python
HOOK_SCRIPT=$(cat << 'HOOKEOF'
import json
import sys
import os

settings_path = os.path.expanduser("~/.claude/settings.json")
proc_janitor = os.environ.get("PROC_JANITOR_BIN", "proc-janitor")

# Load existing settings or create new
if os.path.exists(settings_path):
    with open(settings_path, 'r') as f:
        try:
            settings = json.load(f)
        except json.JSONDecodeError:
            settings = {}
else:
    settings = {}

# Ensure hooks structure exists
if "hooks" not in settings:
    settings["hooks"] = {}

# Define the Stop hook for proc-janitor
stop_hook = {
    "matcher": "",
    "hooks": [
        {
            "type": "command",
            "command": f"{proc_janitor} session auto-clean"
        }
    ]
}

# Add or update Stop hook
# Check if Stop hook already exists with proc-janitor
existing_stop = settings["hooks"].get("Stop", [])
has_proc_janitor = False

for hook_config in existing_stop:
    for hook in hook_config.get("hooks", []):
        if "proc-janitor" in hook.get("command", ""):
            has_proc_janitor = True
            break

if not has_proc_janitor:
    existing_stop.append(stop_hook)
    settings["hooks"]["Stop"] = existing_stop
    print("Added proc-janitor Stop hook")
else:
    print("proc-janitor Stop hook already exists")

# Also add PreToolUse hook for session tracking (optional, tracks subprocess spawning)
pretooluse_hook = {
    "matcher": "Bash",
    "hooks": [
        {
            "type": "command",
            "command": f"PROC_JANITOR_SESSION=${{CLAUDE_SESSION_ID:-default}} {proc_janitor} session track $PROC_JANITOR_SESSION $$ 2>/dev/null || true"
        }
    ]
}

# Save settings
with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2)

print("Settings saved successfully")
HOOKEOF
)

# Run the Python script
if command -v python3 &> /dev/null; then
    PROC_JANITOR_BIN="$PROC_JANITOR_BIN" python3 -c "$HOOK_SCRIPT"
elif command -v python &> /dev/null; then
    PROC_JANITOR_BIN="$PROC_JANITOR_BIN" python -c "$HOOK_SCRIPT"
else
    echo -e "${RED}Error: Python not found. Please install Python 3.${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✓ Integration setup complete!${NC}"
echo ""
echo "How it works:"
echo "  1. When Claude Code starts, a session is registered"
echo "  2. Child processes (MCP servers, etc.) are tracked"
echo "  3. When Claude Code stops, orphaned processes are cleaned"
echo ""
echo "Manual commands:"
echo "  proc-janitor session list        # List active sessions"
echo "  proc-janitor session auto-clean  # Clean orphaned sessions"
echo ""
echo "To test, restart Claude Code and check:"
echo "  proc-janitor session list"
