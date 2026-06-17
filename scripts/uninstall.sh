#!/bin/sh
# Standalone uninstaller for proc-janitor.
#
# Works regardless of how it was installed (scripts/install.sh LaunchAgent,
# Homebrew, `cargo install`, the binary installer, or Linux systemd). Each step
# is best-effort and independent — missing components are skipped quietly.
set -e

say() { printf '%s\n' "$*"; }

# 1) Stop the daemon if it's running.
if command -v proc-janitor >/dev/null 2>&1; then
    proc-janitor stop 2>/dev/null || true
fi

# 2) macOS LaunchAgent (installed by scripts/install.sh).
PLIST="${HOME}/Library/LaunchAgents/com.proc-janitor.plist"
if [ -f "$PLIST" ]; then
    launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    say "Removed LaunchAgent: $PLIST"
fi

# 3) Linux systemd --user service.
if command -v systemctl >/dev/null 2>&1; then
    if systemctl --user list-unit-files 2>/dev/null | grep -q '^proc-janitor\.service'; then
        systemctl --user disable --now proc-janitor 2>/dev/null || true
        say "Disabled systemd --user service"
    fi
    rm -f "${HOME}/.config/systemd/user/proc-janitor.service"
    systemctl --user daemon-reload 2>/dev/null || true
fi

# 4) Homebrew (service + formula).
if command -v brew >/dev/null 2>&1 && brew list proc-janitor >/dev/null 2>&1; then
    brew services stop proc-janitor 2>/dev/null || true
    brew uninstall proc-janitor 2>/dev/null || true
    say "Removed Homebrew install"
fi

# 5) Remove the binary from wherever it lives (Homebrew paths handled above).
BIN="$(command -v proc-janitor 2>/dev/null || true)"
if [ -n "$BIN" ] && [ -e "$BIN" ]; then
    case "$BIN" in
        *Cellar*|*/homebrew/*) : ;; # managed by brew, already uninstalled
        *)
            if [ -w "$BIN" ] || [ -w "$(dirname "$BIN")" ]; then
                rm -f "$BIN" && say "Removed binary: $BIN"
            else
                sudo rm -f "$BIN" && say "Removed binary (sudo): $BIN"
            fi
            ;;
    esac
fi

# 6) Optionally remove config and data (prompt only on an interactive terminal).
CONFIG_DIR="${HOME}/.config/proc-janitor"
DATA_DIR="${HOME}/.proc-janitor"
if [ -d "$CONFIG_DIR" ] || [ -d "$DATA_DIR" ]; then
    if [ -t 0 ]; then
        printf 'Remove configuration and data (%s, %s)? [y/N] ' "$CONFIG_DIR" "$DATA_DIR"
        read -r reply || reply=""
        case "$reply" in
            [Yy]*) rm -rf "$CONFIG_DIR" "$DATA_DIR" && say "Removed config and data" ;;
            *) say "Kept config and data" ;;
        esac
    else
        say "Kept config and data ($CONFIG_DIR, $DATA_DIR) — remove manually if desired."
    fi
fi

say "proc-janitor uninstalled."
