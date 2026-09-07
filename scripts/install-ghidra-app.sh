#!/usr/bin/env bash
# Install / refresh Ghidra.app into /Applications (Mac Mini lab).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/macos/Ghidra.app"
DEST="/Applications/Ghidra.app"

if [[ ! -d "$SRC" ]]; then
  echo "Missing $SRC — rebuild icons/launcher first." >&2
  exit 1
fi

chmod +x "$SRC/Contents/MacOS/Ghidra"

# Fresh copy into Applications
rm -rf "$DEST"
cp -R "$SRC" "$DEST"
chmod +x "$DEST/Contents/MacOS/Ghidra"

# Clear quarantine so Gatekeeper doesn't block first launch awkwardly
xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true

# Refresh LaunchServices / Dock icon cache hint
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$DEST" 2>/dev/null || true

echo "[+] Installed $DEST"
echo "    Double-click from Applications / Spotlight: Ghidra"
echo "    Opens project: ~/Ghidra/mcp-lab (if present)"
echo "    Logs: ~/Library/Logs/Ghidra/launcher.log"
echo
echo "Tip: drag Ghidra to Dock for one-click launch."

# Open Applications folder focused on the app (optional)
open -R "$DEST"
