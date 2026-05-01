#!/usr/bin/env bash
# wp-shell-hunter installer
# Idempotent. Re-running it upgrades in place.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SOMA9-Cloud/wp-shell-hunter/main/install.sh | sudo bash
#
# Or, with a specific version tag:
#   curl -fsSL ".../install.sh" | sudo bash -s -- --version v0.1.0
#
# License: MIT
# Copyright (c) 2026 SOMA9™ Holdings, LLC

set -euo pipefail

REPO="SOMA9-Cloud/wp-shell-hunter"
INSTALL_DIR="${INSTALL_DIR:-/opt/wp-shell-hunter}"
BIN_LINK="${BIN_LINK:-/usr/local/bin/wp-shell-hunter}"
VERSION="${VERSION:-main}"

# Allow overriding via flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --prefix)
            INSTALL_DIR="$2"
            BIN_LINK="$2/../bin/wp-shell-hunter"
            shift 2
            ;;
        --help)
            cat <<USAGE
Usage: install.sh [--version <tag>] [--prefix <dir>]
USAGE
            exit 0
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

# --- pre-flight ---------------------------------------------------------------

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[install] needs root (re-run with sudo)" >&2
    exit 1
fi

for cmd in python3 curl tar; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[install] missing required tool: $cmd" >&2
        exit 1
    fi
done

PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 8) else 0)')
if [[ "$PY_OK" != "1" ]]; then
    echo "[install] python3 >= 3.8 required" >&2
    exit 1
fi

# --- fetch --------------------------------------------------------------------

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

URL="https://codeload.github.com/${REPO}/tar.gz/${VERSION}"
echo "[install] fetching ${URL}"
if ! curl -fsSL "$URL" -o "$TMP/release.tar.gz"; then
    echo "[install] download failed" >&2
    exit 1
fi

tar -xzf "$TMP/release.tar.gz" -C "$TMP"
SRC_DIR="$(find "$TMP" -maxdepth 1 -type d -name 'wp-shell-hunter-*' | head -1)"
if [[ -z "$SRC_DIR" ]]; then
    echo "[install] could not locate extracted source directory" >&2
    exit 1
fi

# --- install ------------------------------------------------------------------

echo "[install] installing to ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"
# Atomic-ish replace: copy into staging then mv
STAGE="${INSTALL_DIR}.new"
rm -rf "$STAGE"
cp -a "$SRC_DIR/." "$STAGE"
rm -rf "${INSTALL_DIR}.old" 2>/dev/null || true
[[ -d "$INSTALL_DIR" ]] && mv "$INSTALL_DIR" "${INSTALL_DIR}.old"
mv "$STAGE" "$INSTALL_DIR"
rm -rf "${INSTALL_DIR}.old" 2>/dev/null || true

chmod +x "${INSTALL_DIR}/bin/wp-shell-hunter"

# --- symlink ------------------------------------------------------------------

mkdir -p "$(dirname "$BIN_LINK")"
ln -sfn "${INSTALL_DIR}/bin/wp-shell-hunter" "$BIN_LINK"

# --- verify -------------------------------------------------------------------

if "$BIN_LINK" --version >/dev/null 2>&1; then
    INSTALLED_VERSION="$("$BIN_LINK" --version)"
    echo "[install] ok: ${INSTALLED_VERSION}"
    echo "[install] try: ${BIN_LINK} --help"
else
    echo "[install] launcher did not run cleanly; check ${INSTALL_DIR}" >&2
    exit 1
fi
