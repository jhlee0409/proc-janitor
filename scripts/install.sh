#!/bin/bash
set -e

# Color output support
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    RESET=''
fi

# Constants
BINARY_NAME="proc-janitor"
INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
PLIST_NAME="com.proc-janitor.plist"
LAUNCHAGENT_DIR="${HOME}/Library/LaunchAgents"
LAUNCHAGENT_PATH="${LAUNCHAGENT_DIR}/${PLIST_NAME}"
CONFIG_DIR="${HOME}/.config/proc-janitor"
DATA_DIR="${HOME}/.proc-janitor"
LOGS_DIR="${DATA_DIR}/logs"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"

# Function: Print colored message
info() {
    echo -e "${BLUE}${1}${RESET}"
}

success() {
    echo -e "  ${GREEN}✓${RESET} ${1}"
}

error() {
    echo -e "${RED}✗ Error: ${1}${RESET}" >&2
}

warning() {
    echo -e "${YELLOW}⚠ Warning: ${1}${RESET}"
}

# Function: Check if running on macOS
check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        error "This installer is for macOS only"
        exit 1
    fi
}

# Function: Uninstall
uninstall() {
    info "🗑️  Uninstalling proc-janitor..."

    # Unload and remove LaunchAgent
    if [ -f "${LAUNCHAGENT_PATH}" ]; then
        if launchctl list | grep -q "com.proc-janitor"; then
            launchctl unload "${LAUNCHAGENT_PATH}" 2>/dev/null || true
            success "Unloaded LaunchAgent"
        fi
        rm -f "${LAUNCHAGENT_PATH}"
        success "Removed LaunchAgent"
    fi

    # Remove binary
    if [ -f "${INSTALL_PATH}" ]; then
        sudo rm -f "${INSTALL_PATH}"
        success "Removed binary"
    fi

    # Ask about config removal
    if [ -d "${CONFIG_DIR}" ] || [ -d "${DATA_DIR}" ]; then
        echo ""
        read -p "Remove configuration and data? [y/N] " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "${CONFIG_DIR}"
            rm -rf "${DATA_DIR}"
            success "Removed configuration and data"
        fi
    fi

    echo ""
    info "🎉 Uninstallation complete!"
    exit 0
}

# Function: Install
install() {
    local is_upgrade=$1

    if [ "${is_upgrade}" = true ]; then
        info "🔄 Upgrading proc-janitor..."
    else
        info "🔧 Installing proc-janitor..."
    fi

    # Create config directories
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${LOGS_DIR}"
    success "Created config directory"

    # Create default config if it doesn't exist
    if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
        cat > "${CONFIG_DIR}/config.toml" << EOF
# proc-janitor configuration
scan_interval = 5
grace_period = 30
sigterm_timeout = 5

# Target process patterns (regex)
targets = ["node.*claude", "claude", "node.*mcp"]

# Whitelist patterns (regex) - processes matching these won't be killed
whitelist = ["node.*server", "pm2"]

[logging]
enabled = true
path = "${HOME}/.proc-janitor/logs"
retention_days = 7
EOF
        success "Created default config"
    fi

    # Build binary
    if [ ! -f "${PROJECT_ROOT}/target/release/${BINARY_NAME}" ]; then
        info "Building binary..."
        cd "${PROJECT_ROOT}"
        cargo build --release
    fi

    # Install binary
    sudo cp "${PROJECT_ROOT}/target/release/${BINARY_NAME}" "${INSTALL_PATH}"
    sudo chmod +x "${INSTALL_PATH}"
    success "Installed binary to ${INSTALL_PATH}"

    # Install LaunchAgent
    mkdir -p "${LAUNCHAGENT_DIR}"

    # Unload if already loaded (for upgrade)
    if [ "${is_upgrade}" = true ] && launchctl list | grep -q "com.proc-janitor"; then
        launchctl unload "${LAUNCHAGENT_PATH}" 2>/dev/null || true
    fi

    # Replace __HOME__ placeholder with actual $HOME path
    sed "s|__HOME__|${HOME}|g" "${PROJECT_ROOT}/resources/${PLIST_NAME}" > "${LAUNCHAGENT_PATH}"
    success "Installed LaunchAgent"

    # Load service
    launchctl load "${LAUNCHAGENT_PATH}"
    success "Loaded service"

    echo ""
    if [ "${is_upgrade}" = true ]; then
        info "🎉 Upgrade complete!"
    else
        info "🎉 Installation complete!"
    fi
    echo ""
    info "Run '${BINARY_NAME} status' to check the daemon."
}

# Parse arguments
case "${1:-}" in
    --uninstall)
        check_macos
        uninstall
        ;;
    --upgrade)
        check_macos
        install true
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  (none)        Install proc-janitor"
        echo "  --upgrade     Upgrade existing installation"
        echo "  --uninstall   Uninstall proc-janitor"
        echo "  --help        Show this help message"
        exit 0
        ;;
    "")
        check_macos
        install false
        ;;
    *)
        error "Unknown option: $1"
        echo "Run '$0 --help' for usage information"
        exit 1
        ;;
esac
