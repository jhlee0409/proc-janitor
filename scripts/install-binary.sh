#!/bin/sh
# proc-janitor binary installer
# Usage: curl -fsSL https://raw.githubusercontent.com/jhlee0409/proc-janitor/main/scripts/install-binary.sh | sh
set -e

REPO="jhlee0409/proc-janitor"
BINARY="proc-janitor"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
detect_platform() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Darwin) os="apple-darwin" ;;
        Linux)  os="unknown-linux-gnu" ;;
        *)
            echo "Error: Unsupported OS: $os" >&2
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)  arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        *)
            echo "Error: Unsupported architecture: $arch" >&2
            exit 1
            ;;
    esac

    echo "${arch}-${os}"
}

# Get latest release tag from GitHub
get_latest_version() {
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    elif command -v wget > /dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    else
        echo "Error: curl or wget is required" >&2
        exit 1
    fi
}

# Download and extract
download() {
    url="$1"
    dest="$2"

    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget > /dev/null 2>&1; then
        wget -qO "$dest" "$url"
    fi
}

main() {
    platform="$(detect_platform)"
    version="$(get_latest_version)"

    if [ -z "$version" ]; then
        echo "Error: Could not determine latest version" >&2
        exit 1
    fi

    echo "Installing proc-janitor ${version} for ${platform}..."

    archive="${BINARY}-${version}-${platform}.tar.gz"
    url="https://github.com/${REPO}/releases/download/${version}/${archive}"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    echo "Downloading ${url}..."
    download "$url" "${tmpdir}/${archive}"

    echo "Extracting..."
    tar xzf "${tmpdir}/${archive}" -C "$tmpdir"

    # Find the binary in extracted directory
    binary_path="$(find "$tmpdir" -name "$BINARY" -type f | head -1)"

    if [ -z "$binary_path" ]; then
        echo "Error: Binary not found in archive" >&2
        exit 1
    fi

    chmod +x "$binary_path"

    # Install - try without sudo first, then with sudo
    if [ -w "$INSTALL_DIR" ]; then
        cp "$binary_path" "${INSTALL_DIR}/${BINARY}"
    else
        echo "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo cp "$binary_path" "${INSTALL_DIR}/${BINARY}"
    fi

    echo ""
    echo "proc-janitor ${version} installed to ${INSTALL_DIR}/${BINARY}"
    echo ""
    echo "Get started:"
    echo "  proc-janitor config init    # Create config (auto-detects orphans)"
    echo "  proc-janitor scan           # Detect orphaned processes"
    echo "  proc-janitor start          # Start the daemon"
    echo ""
    echo "For macOS LaunchAgent setup, run:"
    echo "  proc-janitor doctor          # Check system health"
}

main
