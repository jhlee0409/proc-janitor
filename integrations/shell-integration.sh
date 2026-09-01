#!/bin/bash
# Shell Integration for proc-janitor
# Add this to your .bashrc or .zshrc.
#
# What it does: registers one session per shell, recording the shell as the
# session's parent, and runs `session clean` when the shell exits.
#
# What `session clean` then kills: descendants of this shell whose command line
# matches a target pattern in your config and is not whitelisted — the same rule
# `proc-janitor scan` uses. Nothing else in the terminal is touched. If no target
# patterns are configured, it kills nothing.
#
# Use `pj-track` (below) only to clean up something the patterns do NOT match.
#
# Usage: source this file or copy the relevant section to your shell config

# ============================================================================
# Auto-register terminal sessions
# ============================================================================

# Register a proc-janitor session when opening a new terminal.
# Guarded: registration is a subprocess that takes an exclusive lock on
# sessions.json and rewrites it, so it must run once per shell, not per command.
_proc_janitor_register_session() {
    [ -n "$PROC_JANITOR_SESSION" ] && return 0
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
    add-zsh-hook zshexit _proc_janitor_cleanup_session

    # Register once at shell startup. Do NOT hook this into `precmd`: that runs
    # before every prompt, and each run spawns proc-janitor and takes an
    # exclusive lock on sessions.json — measurably slower prompts (~11ms) plus
    # lock contention across open terminals, for no benefit.
    _proc_janitor_register_session
elif [ -n "$BASH_VERSION" ]; then
    # Bash
    trap _proc_janitor_cleanup_session EXIT

    _proc_janitor_register_session
fi

# ============================================================================
# Helper functions
# ============================================================================

# Track a specific command so `session clean` kills it even if no target pattern
# matches it. Explicitly tracked PIDs are killed with their whole subtree and
# without pattern filtering — naming a PID is consent.
#
# Note: the command is run in the background and waited on, so it does not get
# the terminal's foreground process group. Use it for background/non-interactive
# work (dev servers, watchers); an interactive program will not receive Ctrl-C
# properly through it.
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
