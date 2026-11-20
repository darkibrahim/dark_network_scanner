"""Host discovery: find which hosts in a target are online.

Two independent, non-destructive probes are used, since not every platform
(Termux, rootless NetHunter, containers) allows unprivileged ICMP:

1. A single ICMP echo via the system's own `ping` binary (no raw sockets,
   no root required on most modern Linux/Android kernels).
2. A quick TCP-connect probe against a few very common ports, used only as
   a fallback if `ping` is unavailable or blocked.

Neither probe sends more than a handful of packets per host.
"""
from __future__ import annotations

import ipaddress
import platform
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

FALLBACK_PROBE_PORTS = (80, 443, 22, 445)
_PING_BIN = shutil.which("ping")


@dataclass
class HostStatus:
    host: str
    alive: bool
    method: str  # "ping", "tcp-probe", or "unreachable"


def _ping_once(host: str, timeout: float) -> bool:
    if not _PING_BIN:
        return False
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    timeout_flag = "-w" if platform.system() == "Windows" else "-W"
    wait_value = str(int(timeout * 1000)) if platform.system() == "Windows" else str(max(1, int(timeout)))
    cmd = [_PING_BIN, count_flag, "1", timeout_flag, wait_value, host]
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1.5
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _tcp_probe(host: str, timeout: float) -> bool:
    for port in FALLBACK_PROBE_PORTS:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def probe_host(host: str, timeout: float = 1.0) -> HostStatus:
    if _ping_once(host, timeout):
        return HostStatus(host, True, "ping")
    if _tcp_probe(host, timeout):
        return HostStatus(host, True, "tcp-probe")
    return HostStatus(host, False, "unreachable")


MAX_TARGETS = 1024


def expand_targets(spec: str) -> list[str]:
    """Expand a single host, or an IPv4/IPv6 CIDR range, into a list of addresses.

    Rejects ranges larger than MAX_TARGETS *before* building the list, so a
    huge range (e.g. a /8, ~16 million addresses) fails instantly instead of
    exhausting memory or hanging — important on resource-limited platforms
    like phones.
    """
    spec = spec.strip()
    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR range: '{spec}' ({exc})") from exc
        if network.num_addresses > MAX_TARGETS:
            raise ValueError(
                f"That range contains {network.num_addresses} addresses — pass a smaller "
                f"CIDR (e.g. /24 or smaller, max {MAX_TARGETS} addresses) to keep scans "
                "fast and considerate."
            )
        hosts = [str(ip) for ip in network.hosts()]
        if not hosts:  # /31 or /32
            hosts = [str(network.network_address)]
        return hosts
    return [spec]


def discover(
    spec: str,
    timeout: float = 1.0,
    max_workers: int = 64,
    progress=None,
) -> list[HostStatus]:
    """Probe every host in `spec` (single host or CIDR) and return their status."""
    targets = expand_targets(spec)
    results: list[HostStatus] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(targets)))) as pool:
        futures = {pool.submit(probe_host, h, timeout): h for h in targets}
        for future in as_completed(futures):
            status = future.result()
            results.append(status)
            if progress:
                progress(status)
    results.sort(key=lambda s: tuple(int(p) for p in s.host.split(".")) if s.host.count(".") == 3 else (0,))
    return results
