"""A small, dependency-free table of well-known TCP ports and service names.

This is intentionally a short, widely-published list (the kind printed in
any networking textbook) — not a fingerprinting database and not a list of
known-vulnerable versions. It exists only to label open ports in reports.
"""
from __future__ import annotations

COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1723: "pptp",
    2049: "nfs",
    3000: "dev-http",
    3306: "mysql",
    3389: "rdp",
    5000: "dev-http",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "dev-http",
    9200: "elasticsearch",
    27017: "mongodb",
}

# A sensible default scan range: the ports above, deduplicated and sorted.
TOP_PORTS: list[int] = sorted(COMMON_PORTS)


def service_name(port: int) -> str:
    """Return a best-effort service label for a port number."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        import socket

        return socket.getservbyport(port, "tcp")
    except (OSError, socket.error, Exception):  # noqa: BLE001 - best effort only
        return "unknown"


def parse_port_spec(spec: str) -> list[int]:
    """Parse "22,80,8000-8010" style specs into a sorted list of unique ports."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, _, end_s = chunk.partition("-")
            try:
                start, end = int(start_s), int(end_s)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: '{chunk}'") from exc
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(chunk))
            except ValueError as exc:
                raise ValueError(f"Invalid port: '{chunk}'") from exc

    for p in ports:
        if not (0 < p <= 65535):
            raise ValueError(f"Port out of range (1-65535): {p}")
    return sorted(ports)
