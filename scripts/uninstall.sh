#!/bin/bash
# Convenience wrapper for uninstalling proc-janitor
# Full uninstall logic lives in install.sh --uninstall

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -f "${SCRIPT_DIR}/install.sh" ]; then
    exec bash "${SCRIPT_DIR}/install.sh" --uninstall
else
    echo "Error: install.sh not found in ${SCRIPT_DIR}" >&2
    exit 1
fi
