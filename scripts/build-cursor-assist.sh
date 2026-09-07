#!/usr/bin/env bash
# Build + install GhidraCursorAssist into the user Ghidra Extensions dir.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT_DIR="$ROOT/ghidra-cursor-assist"
GHIDRA_USER_EXT="${GHIDRA_USER_EXT:-$HOME/Library/ghidra/ghidra_12.1.3_PUBLIC/Extensions}"
BREW_EXT="${GHIDRA_INSTALL_DIR:-/opt/homebrew/opt/ghidra/libexec}/Extensions/Ghidra"
JAVA_HOME_DEFAULT="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"

export JAVA_HOME="${JAVA_HOME:-$JAVA_HOME_DEFAULT}"
export PATH="$JAVA_HOME/bin:/opt/homebrew/bin:$PATH"

cd "$EXT_DIR"
echo "[*] Building GhidraCursorAssist…"
mvn -q -DskipTests clean package

ZIP=$(ls -1 target/GhidraCursorAssist-*.zip | head -1)
echo "[+] Built $ZIP"

mkdir -p "$GHIDRA_USER_EXT"
# Unzip into user Extensions (replace existing)
rm -rf "$GHIDRA_USER_EXT/GhidraCursorAssist"
unzip -q -o "$ZIP" -d "$GHIDRA_USER_EXT"
echo "[+] Installed to $GHIDRA_USER_EXT/GhidraCursorAssist"

# Also drop the zip where File → Install Extensions can find it
mkdir -p "$BREW_EXT"
cp -f "$ZIP" "$BREW_EXT/"
echo "[+] Copied zip to $BREW_EXT/$(basename "$ZIP")"

cat <<EOF

Next in Ghidra:
  1) Restart Ghidra (or File → Install Extensions if first time)
  2) CodeBrowser → File → Configure → enable "GhidraCursorAssistPlugin"
  3) Window → Cursor Assist
  4) Edit → Tool Options → Cursor Assist (agent path / workspace)

EOF
