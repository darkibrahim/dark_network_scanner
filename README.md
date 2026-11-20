# DARK NETWORK SCANNER

A professional, dependency-free **network discovery and TCP port scanner**, written in Python with a small Bash tooling layer, built to run identically on **Termux, rootless NetHunter, Kali Linux, and Arch Linux (ARM64/AMD64)**.

> ## ⚠️ Authorized use only
> Only scan hosts and networks **you own or have explicit written permission to test**. Unauthorized scanning — even just discovery or a port scan, with no further action — can violate computer-misuse laws in most countries. This tool will not run against a target until you confirm authorization (`--yes`, or the interactive prompt).

## Author

**DARK IBRAHIM** — Cyber Security Expert

## Release model: Open Source + Premium

| | Free (MIT, this repo) | Premium |
| --- | --- | --- |
| Host discovery (ping + TCP fallback) | ✅ | ✅ |
| TCP connect port scanning | ✅ | ✅ |
| CIDR range sweeps | ✅ | ✅ |
| Service banner grabbing | ✅ | ✅ |
| Colored terminal UI, phone-friendly compact mode | ✅ | ✅ |
| JSON / CSV / HTML report export | ❌ | ✅ |
| Unlock | — | local license key (see below) |

The full scanning engine is 100% open source under the MIT license — nothing about *scanning* is paywalled. Premium only gates convenience features (saved reports). See [`scanner/premium.py`](scanner/premium.py) — the gate is a simple, documented local check, not hidden telemetry or DRM.

```bash
python3 dark_network_scanner.py --demo-key          # print a working demo key
python3 dark_network_scanner.py --activate <KEY>    # unlock Premium locally
```

## Features

- **Host discovery** — ICMP ping (via the system `ping`, no raw sockets/root needed) with an automatic TCP-probe fallback for platforms that block unprivileged ping (common on Android/Termux).
- **Port scanning** — plain TCP connect-scan (`socket.connect_ex`), the same call any normal client makes. No raw packets, no SYN-stealth tricks, no root required.
- **CIDR sweeps** — scan a whole subnet (`192.168.1.0/24`) with a sane size cap to keep scans fast and considerate.
- **Banner grabbing** — reads what a service already announces, or sends a plain `HEAD` request for HTTP-like ports. Nothing more than a normal client would send.
- **Threaded** — hundreds of concurrent connection attempts via `concurrent.futures`.
- **Cross-platform** — pure Python standard library, zero third-party dependencies. Works on Termux, rootless NetHunter, Kali, Arch ARM64/AMD64, and any desktop Linux/macOS/Windows with Python 3.8+.
- **Phone-aware terminal UI** — the banner adapts to narrow screens automatically.
- **Built-in authorization gate** — the scan does not start until you confirm you're authorized.

## What this tool does **not** do

- No exploitation, no vulnerability scanning, no credential brute-forcing.
- No raw-socket SYN/stealth scans (by design — connect-scan keeps it usable without root everywhere, and indistinguishable from a normal client).
- No bypassing of firewalls, IDS/IPS, or authentication.

This is a **discovery and inventory** tool — the same category as `nmap -sT`, used for network administration and authorized security assessments.

## Requirements

- Python 3.8 or newer. No third-party packages — the standard library only.
- Optional: a working `ping` binary (for faster/more accurate host discovery). Not required; the tool falls back automatically.

## Installation

```bash
git clone https://github.com/darkibrahim/dark_network_scanner.git
cd dark_network_scanner
chmod +x install.sh run.sh
./install.sh
```

`install.sh` detects your platform (Termux, Kali, Arch, or generic Debian) and installs Python (and `ping`, where available) with the right package manager (`pkg`, `apt`, or `pacman`).

### Platform notes

| Platform | Package manager used | Notes |
| --- | --- | --- |
| Termux | `pkg` | Also covers rootless NetHunter, which runs inside a Termux-based environment |
| Kali Linux | `apt` | |
| Arch Linux (ARM64/AMD64) | `pacman` | Covers Arch Linux ARM on phones/SBCs and desktop Arch |
| Generic Debian/Ubuntu | `apt` | Fallback path |

## Quick start

```bash
# Scan one host's common ports (asks you to confirm authorization)
python3 dark_network_scanner.py 192.168.1.1

# Skip the interactive prompt once you've confirmed you're authorized
python3 dark_network_scanner.py 192.168.1.1 --yes

# Discover which hosts in a subnet are up, without port-scanning them
python3 dark_network_scanner.py 192.168.1.0/24 --discover-only --yes

# Scan a specific port range and grab banners
python3 dark_network_scanner.py 192.168.1.1 -p 1-1024 --banners --yes

# Using the Bash wrapper (same on every supported platform)
./run.sh 192.168.1.1 --yes
```

## Usage

```
usage: dark_network_scanner [-h] [-p SPEC] [--discover-only] [--scan-all]
                             [--banners] [-t SEC] [-w N] [--yes]
                             [--json PATH] [--csv PATH] [--html PATH]
                             [--raw] [--no-banner] [--no-color]
                             [--activate KEY] [--demo-key] [-V]
                             [target]
```

| Option | Description |
| --- | --- |
| `target` | Host, hostname, or CIDR range (e.g. `192.168.1.0/24`) |
| `-p`, `--ports SPEC` | Ports to scan, e.g. `22,80,443` or `1-1024` (default: ~37 common ports) |
| `--discover-only` | Only discover live hosts, skip the port scan |
| `--scan-all` | In a CIDR sweep, port-scan every address even if discovery marked it unresponsive |
| `--banners` | Attempt to grab a service banner on every open port |
| `-t`, `--timeout SEC` | Per-probe timeout (default: 0.75s) |
| `-w`, `--threads N` | Max concurrent connections (default: 200) |
| `--yes` | Confirm you are authorized to scan the target (skips the interactive prompt) |
| `--json PATH` / `--csv PATH` / `--html PATH` | Write a report to PATH (Premium) |
| `--raw` | Minimal, script-friendly output |
| `--no-banner` / `--no-color` | Hide the banner / disable colors |
| `--activate KEY` | Activate a Premium license key and exit |
| `--demo-key` | Print a working demo Premium key and exit |
| `-V`, `--version` | Show the version |
| `-h`, `--help` | Show help |

## Why a single host is scanned even if "discovery" says it's down

Some platforms (notably Termux) block unprivileged ICMP, and a host might simply have none of the handful of fallback ports (`80/443/22/445`) open. For a **single host target**, the tool scans your requested ports anyway and just tells you discovery couldn't confirm the host was alive — it doesn't silently skip a real target. For a **CIDR sweep**, only hosts discovery found alive are scanned by default (to keep subnet scans fast); pass `--scan-all` to scan every address regardless.

## Example output

```
╭──────────────────────────────────────────────────────────────────╮
│                 ██████╗  █████╗ ██████╗ ██╗  ██╗                 │
│                 ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝                 │
│                 ██║  ██║███████║██████╔╝█████╔╝                  │
│                 ██║  ██║██╔══██║██╔══██╗██╔═██╗                  │
│                 ██████╔╝██║  ██║██║  ██║██║  ██╗                 │
│                 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝                 │
│                  N E T W O R K   S C A N N E R                   │
│               AUTHORIZED DISCOVERY & PORT SCANNING               │
├──────────────────────────────────────────────────────────────────┤
│ ◈ AUTHOR   : DARK IBRAHIM                                        │
│ ◈ VERSION  : v1.0.0                                               │
│ ◈ LICENSE  : MIT                                                  │
│ ◈ TIER     : FREE / OPEN SOURCE                                  │
╰──────────────────────────────────────────────────────────────────╯

  ╭─── OPEN PORTS on 192.168.1.1 ──────────────────────────────────
  │ 22     ssh
  │ 80     http            Server: nginx
  │ 443    https
  ╰─────────────────────────────────────────────────────────────
```

## Running the tests

All 44 tests mock every socket call — no real network access is required or performed:

```bash
python3 -m unittest -v
```

## Project layout

```
dark_network_scanner/
├── dark_network_scanner.py   # CLI entry point, banner, authorization gate
├── scanner/
│   ├── discovery.py          # host discovery (ping + TCP fallback, CIDR expansion)
│   ├── portscan.py           # threaded TCP connect-scan engine
│   ├── banner.py             # service banner grabbing
│   ├── services.py           # common port/service table + port-spec parser
│   ├── premium.py            # open-core Premium license gate
│   └── report.py             # JSON / CSV / HTML report formatting
├── test_dark_network_scanner.py
├── install.sh                 # platform-detecting dependency installer
├── run.sh                     # cross-platform launcher
├── LICENSE
└── README.md
```

## License

The scanning engine is released under the [MIT License](LICENSE). Premium report-export features are a separate local add-on (see `scanner/premium.py`); the license gate itself is open source and documented, not hidden.
