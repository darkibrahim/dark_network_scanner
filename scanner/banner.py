"""Best-effort service banner grabbing.

Many services announce themselves as soon as a client connects (SSH, FTP,
SMTP). Others, like HTTP, only reply after a request. This module sends
nothing more than what any normal client would send (e.g. a plain HTTP
HEAD request) and only reads what the service offers back — there is no
exploitation, fuzzing, or protocol abuse here.
"""
from __future__ import annotations

import socket

_HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000, 9000}
_MAX_BANNER_BYTES = 256


def _clean(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace").strip()
    text = " ".join(text.split())  # collapse newlines/whitespace to one line
    return text[:_MAX_BANNER_BYTES]


def read_banner(sock: socket.socket, port: int, host: str, timeout: float) -> str | None:
    sock.settimeout(timeout)
    try:
        if port in _HTTP_PORTS or port == 443 or port == 8443:
            request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode("ascii", errors="ignore"))
        data = sock.recv(_MAX_BANNER_BYTES)
        return _clean(data) if data else None
    except (OSError, socket.timeout):
        return None
