#!/usr/bin/env python3
"""
DARK NETWORK SCANNER - authorized network discovery & port scanning toolkit.

Scans only networks and hosts you own or are explicitly authorized to test.
Unauthorized scanning of systems you do not control can be illegal in most
jurisdictions. This tool will not run against a target until you confirm
authorization (see --yes / the interactive prompt).

Copyright (c) 2026 DARK IBRAHIM. Released under the MIT License (see LICENSE).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import __version__  # noqa: E402
from scanner.discovery import discover  # noqa: E402
from scanner.portscan import scan_ports  # noqa: E402
from scanner.premium import activate, is_premium, make_demo_key  # noqa: E402
from scanner.report import results_to_dict, to_csv, to_html, to_json  # noqa: E402
from scanner.services import TOP_PORTS, parse_port_spec  # noqa: E402

__author__ = "DARK IBRAHIM"

EXAMPLES = """\
examples:
  dark_network_scanner.py 192.168.1.1 --yes
  dark_network_scanner.py 192.168.1.0/24 --discover-only --yes
  dark_network_scanner.py example.com -p 1-1024 --yes
  dark_network_scanner.py 10.0.0.5 -p 22,80,443 --banners --yes
  dark_network_scanner.py 10.0.0.0/28 --json report.json --yes   (Premium)

Always get written authorization before scanning a network you do not own.
"""

EXIT_OK, EXIT_ERROR, EXIT_INTERRUPTED, EXIT_NOT_AUTHORIZED = 0, 1, 130, 3

# ==========================================================
#  THEME (shared look & feel with the rest of the toolkit)
# ==========================================================
GREEN, CYAN, PINK = 46, 51, 201
RED, ORANGE, YELLOW, WHITE, GRAY = 196, 208, 226, 255, 244
WIDTH = 66
GRADIENT = [51, 50, 49, 48, 47, 46]

ANSI_RE = __import__("re").compile(r"\033\[[0-9;]*m")
USE_COLOR = False


def init_color(force_off: bool = False) -> None:
    global USE_COLOR
    USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ and not force_off
    if USE_COLOR and os.name == "nt":
        os.system("")


def paint(text: str, color: int | None = None, bold: bool = False) -> str:
    if not USE_COLOR:
        return text
    codes = "\033[1m" if bold else ""
    if color is not None:
        codes += f"\033[38;5;{color}m"
    return f"{codes}{text}\033[0m"


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def is_compact() -> bool:
    return term_width() < WIDTH + 2


FONT = {
    "D": ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "K": ["██╗  ██╗", "██║ ██╔╝", "█████╔╝ ", "██╔═██╗ ", "██║  ██╗", "╚═╝  ╚═╝"],
}


def render_word(word: str) -> list[str]:
    return ["".join(FONT[ch][i] for ch in word) for i in range(6)]


def box_row(content: str = "", center: bool = False) -> str:
    pad = WIDTH - visible_len(content)
    left = pad // 2 if center else 1
    right = max(pad - left, 0)
    edge = paint("│", CYAN)
    return f"{edge}{' ' * left}{content}{' ' * right}{edge}"


def banner() -> None:
    premium_tag = paint(" PREMIUM", PINK, bold=True) if is_premium() else paint(" FREE", GRAY)
    if is_compact():
        rule = paint("─" * max(10, min(term_width() - 4, 38)), GRAY)
        print(f"  {paint('◆ DARK NETWORK SCANNER ◆', GREEN, bold=True)}{premium_tag}")
        print(f"  {paint('Authorized Discovery & Port Scanning', CYAN)}")
        print(f"  {paint('v' + __version__ + ' · MIT', GRAY)}")
        print(f"  {rule}\n")
        return

    print(paint("╭" + "─" * WIDTH + "╮", CYAN))
    print(box_row())
    for i, line in enumerate(render_word("DARK")):
        print(box_row(paint(line, GRADIENT[i], bold=True), center=True))
    print(box_row())
    print(box_row(paint("NETWORK SCANNER", CYAN, bold=True), center=True) if False else
          box_row(paint("N E T W O R K   S C A N N E R", CYAN, bold=True), center=True))
    print(box_row(paint("AUTHORIZED DISCOVERY & PORT SCANNING", GRAY), center=True))
    print(box_row(paint("─ ◆ ─", GRAY), center=True))
    print(paint("├" + "─" * WIDTH + "┤", CYAN))
    tier = paint("PREMIUM", PINK, bold=True) if is_premium() else paint("FREE / OPEN SOURCE", GRAY)
    info = [
        ("AUTHOR", __author__, GREEN),
        ("VERSION", "v" + __version__, CYAN),
        ("LICENSE", "MIT", CYAN),
        ("TIER", None, None),
    ]
    for key, value, color in info:
        label = paint(f"{key:<8}", GRAY)
        shown = tier if key == "TIER" else paint(value, color, bold=True)
        line = f"{paint('◈', PINK)} {label} {paint(':', GRAY)} {shown}"
        print(box_row(line))
    print(paint("╰" + "─" * WIDTH + "╯", CYAN))
    print()


def success(message: str) -> None:
    print(f"  {paint('✔', GREEN, bold=True)} {paint(message, WHITE)}")


def warn(message: str) -> None:
    print(f"  {paint('!', YELLOW, bold=True)} {paint(message, YELLOW)}")


def error(message: str) -> None:
    print(f"\n  {paint('✖', RED, bold=True)} {paint(message, RED, bold=True)}\n", file=sys.stderr)


class ToolError(Exception):
    pass


# ==========================================================
#  AUTHORIZATION GATE
# ==========================================================
AUTH_NOTICE = """\
  You are about to scan: {target}

  Only scan systems and networks you OWN or have EXPLICIT WRITTEN
  PERMISSION to test. Scanning systems without authorization is illegal
  in most countries, even if no "attack" is performed — discovery and
  port scans alone can violate computer-misuse laws.
"""


def confirm_authorization(target: str, assume_yes: bool) -> bool:
    print(paint(AUTH_NOTICE.format(target=target), YELLOW))
    if assume_yes:
        success("Authorization confirmed via --yes")
        return True
    if not sys.stdin.isatty():
        error("Refusing to scan without authorization. Re-run with --yes if you are authorized.")
        return False
    try:
        reply = input(paint("  Type 'yes' to confirm you are authorized to scan this target: ", WHITE)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return reply == "yes"


# ==========================================================
#  SCAN ORCHESTRATION
# ==========================================================
def run_discovery(target: str, timeout: float, quiet: bool):
    hosts = []
    if not quiet:
        print(paint(f"  ◇ Discovering hosts in {target} ...", CYAN))
    for status in discover(target, timeout=timeout, progress=None):
        hosts.append(status)
    hosts.sort(key=lambda h: h.host)
    if not quiet:
        alive = [h for h in hosts if h.alive]
        for h in hosts:
            if h.alive:
                print(f"    {paint('●', GREEN, bold=True)} {h.host:<16} {paint('UP', GREEN, bold=True)} ({h.method})")
        print(f"\n  {paint(str(len(alive)), GREEN, bold=True)} of {len(hosts)} host(s) responding\n")
    return hosts


def run_port_scan(host: str, ports: list[int], timeout: float, threads: int, banners: bool, quiet: bool):
    if not quiet:
        print(paint(f"  ◇ Scanning {len(ports)} port(s) on {host} ...", CYAN))
    results = scan_ports(host, ports, timeout=timeout, max_workers=threads, grab_banner=banners)
    open_ports = [r for r in results if r.open]
    if not quiet:
        if open_ports:
            print()
            print(paint(f"  ╭─── OPEN PORTS on {host} " + "─" * max(2, WIDTH - 20 - len(host)), CYAN))
            for r in open_ports:
                extra = f"  {paint(r.banner, GRAY)}" if r.banner else ""
                print(paint("  │ ", CYAN) + f"{paint(str(r.port), GREEN, bold=True):<6} {r.service:<14}{extra}")
            print(paint("  ╰" + "─" * (WIDTH - 4), CYAN))
        else:
            warn(f"No open ports found on {host} in the scanned range.")
        print()
    return results


# ==========================================================
#  CLI
# ==========================================================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dark_network_scanner",
        description="Authorized network discovery and TCP port scanner.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="host, hostname, or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", metavar="SPEC", default=None,
                        help="ports to scan, e.g. '22,80,443' or '1-1024' (default: top common ports)")
    parser.add_argument("--discover-only", action="store_true", help="only discover live hosts, skip port scan")
    parser.add_argument("--scan-all", action="store_true",
                        help="in a CIDR range, port-scan every address even if discovery found it unresponsive "
                             "(discovery can miss hosts that block ping and have no open fallback port)")
    parser.add_argument("--banners", action="store_true", help="attempt to grab service banners on open ports")
    parser.add_argument("-t", "--timeout", type=float, default=0.75, metavar="SEC", help="per-probe timeout (default: 0.75)")
    parser.add_argument("-w", "--threads", type=int, default=200, metavar="N", help="max concurrent connections (default: 200)")
    parser.add_argument("--yes", action="store_true", help="confirm you are authorized to scan the target (skips the prompt)")
    parser.add_argument("--json", metavar="PATH", help="write a JSON report to PATH (Premium)")
    parser.add_argument("--csv", metavar="PATH", help="write a CSV report to PATH (Premium)")
    parser.add_argument("--html", metavar="PATH", help="write an HTML report to PATH (Premium)")
    parser.add_argument("--raw", action="store_true", help="minimal output, script friendly")
    parser.add_argument("--no-banner", action="store_true", help="hide the banner")
    parser.add_argument("--no-color", action="store_true", help="disable colors")
    parser.add_argument("--activate", metavar="KEY", help="activate a Premium license key and exit")
    parser.add_argument("--demo-key", action="store_true", help="print a working demo Premium key and exit")
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = sys.argv[1:] if argv is None else argv

    if not argv:
        init_color()
        banner()
        parser.print_help()
        return EXIT_OK

    args = parser.parse_args(argv)
    init_color(force_off=args.no_color or args.raw)

    if args.demo_key:
        print(make_demo_key())
        return EXIT_OK
    if args.activate:
        print("Activated." if activate(args.activate) else "Invalid key.")
        return EXIT_OK if activate else EXIT_ERROR

    if not args.target:
        error("A target is required. See --help for usage.")
        return EXIT_ERROR

    premium_requested = any([args.json, args.csv, args.html])
    if premium_requested and not is_premium():
        error(
            "Report export (--json/--csv/--html) is a Premium feature.\n"
            "  Run with --demo-key to see a working key, then:\n"
            "  dark_network_scanner.py --activate <KEY>"
        )
        return EXIT_ERROR

    if not args.raw and not args.no_banner:
        banner()

    if not confirm_authorization(args.target, args.yes):
        error("Not authorized — aborting.")
        return EXIT_NOT_AUTHORIZED

    try:
        ports = parse_port_spec(args.ports) if args.ports else list(TOP_PORTS)
    except ValueError as exc:
        error(str(exc))
        return EXIT_ERROR

    started = time.perf_counter()
    try:
        hosts = run_discovery(args.target, args.timeout, quiet=args.raw)
    except ValueError as exc:
        error(str(exc))
        return EXIT_ERROR

    is_single_host = len(hosts) == 1
    port_results = {}
    if not args.discover_only:
        for h in hosts:
            should_scan = h.alive or is_single_host or args.scan_all
            if should_scan:
                if not h.alive and not args.raw:
                    warn(
                        f"{h.host} did not respond to discovery (ping/common ports), "
                        "scanning anyway — it may still have other open ports."
                        if is_single_host else
                        f"{h.host} did not respond to discovery, scanning anyway (--scan-all)."
                    )
                port_results[h.host] = run_port_scan(h.host, ports, args.timeout, args.threads, args.banners, quiet=args.raw)

    elapsed = time.perf_counter() - started
    if args.raw:
        for h in hosts:
            tag = "UP" if h.alive else "DOWN"
            print(f"{tag}\t{h.host}\t{h.method}")
            for r in port_results.get(h.host, []):
                if r.open:
                    print(f"OPEN\t{h.host}\t{r.port}\t{r.service}\t{r.banner or ''}")
    elif not args.discover_only:
        success(f"Scan finished in {elapsed:.2f}s")

    if premium_requested:
        data = results_to_dict(args.target, hosts, port_results)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(to_json(data))
            success(f"JSON report saved to {args.json}")
        if args.csv:
            with open(args.csv, "w", encoding="utf-8", newline="") as fh:
                fh.write(to_csv(data))
            success(f"CSV report saved to {args.csv}")
        if args.html:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(to_html(data))
            success(f"HTML report saved to {args.html}")

    return EXIT_OK


def _use_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


if __name__ == "__main__":
    _use_utf8_streams()
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n  Interrupted by user.", file=sys.stderr)
        sys.exit(EXIT_INTERRUPTED)
    except BrokenPipeError:
        sys.exit(EXIT_OK)
