#!/usr/bin/env bash
#
# DARK NETWORK SCANNER - run wrapper
#
# A thin convenience wrapper so the tool can be launched the same way on
# every supported platform (Termux, rootless NetHunter, Kali, Arch Linux)
# without remembering whether "python" or "python3" is on PATH.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
  PY="python3"
elif command -v python >/dev/null 2>&1; then
  PY="python"
else
  echo "[x] Python was not found. Run ./install.sh first." >&2
  exit 1
fi

exec "$PY" "$SCRIPT_DIR/dark_network_scanner.py" "$@"
