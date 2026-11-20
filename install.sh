#!/usr/bin/env bash
#
# DARK NETWORK SCANNER - installer
#
# Detects the platform (Termux, rootless NetHunter, Kali Linux, Arch Linux
# ARM64/AMD64, or a generic Debian/Arch box) and installs the only two
# runtime requirements: python3 (3.8+) and, optionally, iputils-ping (the
# scanner works without it, falling back to a TCP probe, but real ICMP
# ping is faster and more accurate where it's allowed).
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
set -euo pipefail

BOLD="$(tput bold 2>/dev/null || true)"
GREEN="$(tput setaf 2 2>/dev/null || true)"
CYAN="$(tput setaf 6 2>/dev/null || true)"
YELLOW="$(tput setaf 3 2>/dev/null || true)"
RESET="$(tput sgr0 2>/dev/null || true)"

info()  { printf '%s[*]%s %s\n' "$CYAN" "$RESET" "$1"; }
ok()    { printf '%s[+]%s %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$RESET" "$1"; }
die()   { printf '%s[x] %s%s\n' "$YELLOW" "$1" "$RESET" >&2; exit 1; }

detect_platform() {
  if [ -n "${TERMUX_VERSION:-}" ] || [ -d "/data/data/com.termux" ]; then
    echo "termux"
  elif [ -f /etc/os-release ] && grep -qi '^ID=kali' /etc/os-release; then
    echo "kali"
  elif [ -f /etc/os-release ] && grep -qiE '^ID(_LIKE)?=.*arch' /etc/os-release; then
    echo "arch"
  elif command -v apt-get >/dev/null 2>&1; then
    echo "debian"
  elif command -v pacman >/dev/null 2>&1; then
    echo "arch"
  else
    echo "unknown"
  fi
}

PLATFORM="$(detect_platform)"
ARCH="$(uname -m)"
info "Detected platform: ${BOLD}${PLATFORM}${RESET} (arch: ${ARCH})"

case "$PLATFORM" in
  termux)
    info "Installing python via pkg (Termux / NetHunter rootless)..."
    pkg update -y
    pkg install -y python
    ;;
  kali|debian)
    info "Installing python3 via apt..."
    if [ "$(id -u)" -eq 0 ]; then
      apt-get update -y
      apt-get install -y python3 iputils-ping
    else
      sudo apt-get update -y
      sudo apt-get install -y python3 iputils-ping
    fi
    ;;
  arch)
    info "Installing python via pacman (Arch Linux ARM64/AMD64)..."
    if [ "$(id -u)" -eq 0 ]; then
      pacman -Sy --noconfirm python iputils
    else
      sudo pacman -Sy --noconfirm python iputils
    fi
    ;;
  *)
    warn "Unrecognized platform. Make sure Python 3.8+ is installed manually."
    ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  die "python3 not found after install. Please install Python 3.8+ manually and re-run."
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
ok "python3 ${PY_VERSION} is available."

if command -v ping >/dev/null 2>&1; then
  ok "ping is available — host discovery will use real ICMP where permitted."
else
  warn "ping not found — host discovery will fall back to a TCP probe. This is fine; it just means discovery is a little less precise."
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/dark_network_scanner.py" "$SCRIPT_DIR/run.sh" 2>/dev/null || true

echo
ok "Setup complete."
echo "  Try it now:"
echo "    ${BOLD}./run.sh --help${RESET}"
echo "    ${BOLD}python3 dark_network_scanner.py 192.168.1.1 --yes${RESET}"
echo
warn "Reminder: only scan systems/networks you own or are explicitly authorized to test."
