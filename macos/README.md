# macOS Ghidra.app launcher

Double-clickable app for this lab’s Homebrew Ghidra install (no terminal).

## Install

```bash
./scripts/install-ghidra-app.sh
```

Creates `/Applications/Ghidra.app` with the official NSA Ghidra dragon icons
(`GhidraIcon*.png` from the Ghidra GitHub tree, Apache-2.0).

## Behavior

- Sets `JAVA_HOME` → OpenJDK 21 (Homebrew)
- Sets `GHIDRA_MAXMEM=4G` (Mac Mini 16 GB)
- Runs `/opt/homebrew/opt/ghidra/libexec/ghidraRun`
- Auto-opens `~/Ghidra/mcp-lab` when that project exists
- Logs to `~/Library/Logs/Ghidra/launcher.log`

Override via env before launch if needed: `GHIDRA_LAB_PROJECT`, `GHIDRA_MAXMEM`.

## Source tree

```
macos/Ghidra.app/
  Contents/
    Info.plist
    MacOS/Ghidra          # launcher script
    Resources/AppIcon.icns
macos/icons/GhidraIcon256.png
```
