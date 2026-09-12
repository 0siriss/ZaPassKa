#!/usr/bin/env bash
# Installs the ZaPassKa binary, its icon and its launcher entry for one user.
# Run from the directory holding the downloaded ZaPassKa binary and icon.png.
set -euo pipefail

BIN_DIR="${HOME}/.local/bin"
ICON_DIR="${HOME}/.local/share/icons/hicolor/128x128/apps"
DESKTOP_DIR="${HOME}/.local/share/applications"

mkdir -p "$BIN_DIR" "$ICON_DIR" "$DESKTOP_DIR"

install -m 755 ZaPassKa "$BIN_DIR/ZaPassKa"
install -m 644 icon.png "$ICON_DIR/zapasska.png"

sed "s|^Exec=.*|Exec=${BIN_DIR}/ZaPassKa|" ZaPassKa.desktop > "$DESKTOP_DIR/ZaPassKa.desktop"
chmod 644 "$DESKTOP_DIR/ZaPassKa.desktop"

# Panels cache the launcher list; ask them to reread it.
command -v update-desktop-database >/dev/null && \
    update-desktop-database "$DESKTOP_DIR" || true
command -v gtk-update-icon-cache >/dev/null && \
    gtk-update-icon-cache -f -t "${HOME}/.local/share/icons/hicolor" || true

echo "Installed. ZaPassKa should now appear in the application menu."
