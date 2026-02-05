#!/bin/bash
# Shell Integration for proc-janitor
# Add this to your .bashrc or .zshrc for automatic session tracking
#
# Usage: source this file or copy the relevant section to your shell config

# ============================================================================
# Auto-register terminal sessions
# ============================================================================

# Register a proc-janitor session when opening a new terminal
_proc_janitor_register_session() {
    if command -v proc-janitor &> /dev/null; then
        # Generate session ID from TTY and timestamp
        local tty_name=$(tty 2>/dev/null | tr '/' '_')
        local session_id="${tty_name:-term}_$$"

        # Register session silently
        proc-janitor session register \
            --id "$session_id" \
            --source terminal \
            --parent-pid $$ \
            2>/dev/null

        # Export for child processes
        export PROC_JANITOR_SESSION="$session_id"
    fi
}

# Clean up session when terminal closes
_proc_janitor_cleanup_session() {
    if [ -n "$PROC_JANITOR_SESSION" ] && command -v proc-janitor &> /dev/null; then
        proc-janitor session clean "$PROC_JANITOR_SESSION" 2>/dev/null
    fi
}

# ============================================================================
# Shell-specific setup
# ============================================================================

# Detect shell and set up appropriately
if [ -n "$ZSH_VERSION" ]; then
    # Zsh
    autoload -Uz add-zsh-hook
    add-zsh-hook precmd _proc_janitor_register_session
    add-zsh-hook zshexit _proc_janitor_cleanup_session

    # Only register once
    if [ -z "$PROC_JANITOR_SESSION" ]; then
        _proc_janitor_register_session
    fi
elif [ -n "$BASH_VERSION" ]; then
    # Bash
    trap _proc_janitor_cleanup_session EXIT

    # Only register once
    if [ -z "$PROC_JANITOR_SESSION" ]; then
        _proc_janitor_register_session
    fi
fi

# ============================================================================
# Helper functions
# ============================================================================

# Track a specific command's processes
pj-track() {
    if [ -z "$PROC_JANITOR_SESSION" ]; then
        echo "No proc-janitor session active"
        return 1
    fi

    # Run command and track its PID
    "$@" &
    local pid=$!
    proc-janitor session track "$PROC_JANITOR_SESSION" $pid
    echo "Tracking PID $pid under session $PROC_JANITOR_SESSION"
    wait $pid
}

# Show current session info
pj-status() {
    if [ -n "$PROC_JANITOR_SESSION" ]; then
        echo "Current session: $PROC_JANITOR_SESSION"
        proc-janitor session list 2>/dev/null | grep -A5 "$PROC_JANITOR_SESSION" || echo "Session not found in store"
    else
        echo "No proc-janitor session active"
    fi
}

# Clean current session
pj-clean() {
    if [ -n "$PROC_JANITOR_SESSION" ]; then
        proc-janitor session clean "$PROC_JANITOR_SESSION" "$@"
    else
        echo "No proc-janitor session active"
    fi
}

# ============================================================================
# Installation instructions
# ============================================================================

: << 'INSTALL_INSTRUCTIONS'
To enable shell integration, add one of the following to your shell config:

For Zsh (~/.zshrc):
    source /path/to/proc-janitor/integrations/shell-integration.sh

For Bash (~/.bashrc):
    source /path/to/proc-janitor/integrations/shell-integration.sh

Or copy the functions directly into your shell config file.

After sourcing, you'll have:
- Automatic session registration per terminal
- Automatic cleanup on terminal close
- pj-track <command>  - Run and track a command
- pj-status           - Show current session
- pj-clean            - Clean current session's processes
INSTALL_INSTRUCTIONS
