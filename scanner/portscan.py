"""TCP connect-scan engine.

Uses plain `socket.connect_ex`, the same call a normal client application
makes to open a connection — no raw sockets, no crafted packets, no SYN
stealth tricks. This keeps the scanner usable without root on every target
platform (Termux, rootless NetHunter, Kali, Arch Linux ARM/AMD64) and keeps
its behavior indistinguishable from an ordinary client connecting.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .services import service_name


@dataclass
class PortResult:
    port: int
    open: bool
    service: str
    banner: str | None = None


def scan_port(host: str, port: int, timeout: float = 0.75, grab_banner: bool = False) -> PortResult:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = None
            if grab_banner:
                from .banner import read_banner  # local import avoids a cycle

                banner = read_banner(sock, port, host, timeout)
            return PortResult(port, True, service_name(port), banner)
    except (OSError, socket.timeout):
        return PortResult(port, False, service_name(port))


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 0.75,
    max_workers: int = 200,
    grab_banner: bool = False,
    progress=None,
) -> list[PortResult]:
    results: list[PortResult] = []
    workers = max(1, min(max_workers, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, host, p, timeout, grab_banner): p for p in ports
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if progress:
                progress(result)
    results.sort(key=lambda r: r.port)
    return results
