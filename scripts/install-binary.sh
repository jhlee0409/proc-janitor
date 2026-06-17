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

# Verify the downloaded archive against its published .sha256 checksum.
# Aborts on mismatch. Warns (but continues) if the checksum file or a sha256
# tool is unavailable, so installs don't break on minimal systems / old releases.
verify_checksum() {
    archive_path="$1"
    sha_url="$2"
    sha_file="${archive_path}.sha256"

    if ! download "$sha_url" "$sha_file" 2>/dev/null || [ ! -s "$sha_file" ]; then
        echo "Warning: checksum file unavailable (${sha_url}); skipping integrity check." >&2
        return 0
    fi

    expected="$(awk '{print $1}' "$sha_file" | head -1)"
    if [ -z "$expected" ]; then
        echo "Warning: could not read expected checksum; skipping integrity check." >&2
        return 0
    fi

    if command -v sha256sum > /dev/null 2>&1; then
        actual="$(sha256sum "$archive_path" | awk '{print $1}')"
    elif command -v shasum > /dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
    else
        echo "Warning: no sha256 tool (sha256sum/shasum) found; skipping integrity check." >&2
        return 0
    fi

    if [ "$expected" != "$actual" ]; then
        echo "Error: SHA256 checksum verification FAILED" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        echo "Refusing to install a binary that does not match its published checksum." >&2
        exit 1
    fi
    echo "Checksum verified (sha256)."
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

    echo "Verifying checksum..."
    verify_checksum "${tmpdir}/${archive}" "${url}.sha256"

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
    echo "Next steps (nothing is killed until you configure targets):"
    echo "  proc-janitor config init      # Choose what to clean up"
    echo "  proc-janitor scan             # Detect orphaned processes (safe)"
    echo "  proc-janitor clean --dry-run  # Preview what would be cleaned"
    echo ""
    echo "Note: this installer only installs the binary; it does NOT set up"
    echo "auto-start. To run proc-janitor as a background service on boot:"
    case "$platform" in
        *apple-darwin)
            echo "  macOS:  brew services start proc-janitor   (Homebrew), or install"
            echo "          the LaunchAgent via the repo's scripts/install.sh"
            ;;
        *linux*)
            echo "  Linux:  see the README 'Linux (systemd)' section — remember"
            echo "          'loginctl enable-linger \$USER' so it survives reboots"
            ;;
    esac
    echo ""
    echo "  proc-janitor doctor           # Check system health"
}

main
