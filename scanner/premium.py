"""Open-core feature gate for the Premium tier.

DARK NETWORK SCANNER ships as open source (MIT) with the full scanning
engine included. A small set of *convenience* features — HTML reports,
saved scan history, and higher default thread/port presets — are offered
as a paid "Premium" add-on, unlocked locally by a license key.

This module is a simple, honest placeholder for that mechanism: it is not
DRM and does not phone home. Replace `_valid_checksum` with a real
verification call (e.g. to your own license server) before selling keys.
"""
from __future__ import annotations

import hashlib
import os

_SALT = "dark-network-scanner-v1"  # change this before issuing real keys
_LICENSE_FILE = os.path.expanduser("~/.config/dark_network_scanner/license.key")
_ENV_VAR = "DNS_PREMIUM_KEY"


def _valid_checksum(key: str) -> bool:
    """Toy validator: accepts keys shaped XXXX-XXXX-XXXX-XXXX whose last
    group is a truncated SHA-256 checksum of the first three groups.
    Good enough to demonstrate the gate; not meant to resist tampering.
    """
    parts = key.strip().upper().split("-")
    if len(parts) != 4 or not all(parts):
        return False
    payload = "-".join(parts[:3])
    expected = hashlib.sha256((_SALT + payload).encode()).hexdigest()[:4].upper()
    return parts[3] == expected


def make_demo_key(seed: str = "DARK-IBRA-HIM1") -> str:
    """Generate a working demo key for local testing / documentation."""
    checksum = hashlib.sha256((_SALT + seed).encode()).hexdigest()[:4].upper()
    return f"{seed}-{checksum}"


def _read_key() -> str | None:
    if os.environ.get(_ENV_VAR):
        return os.environ[_ENV_VAR]
    if os.path.isfile(_LICENSE_FILE):
        try:
            with open(_LICENSE_FILE, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return None
    return None


def is_premium() -> bool:
    key = _read_key()
    return bool(key) and _valid_checksum(key)


def activate(key: str) -> bool:
    """Validate and store a license key for future runs. Returns success."""
    if not _valid_checksum(key):
        return False
    os.makedirs(os.path.dirname(_LICENSE_FILE), exist_ok=True)
    with open(_LICENSE_FILE, "w", encoding="utf-8") as fh:
        fh.write(key.strip().upper())
    return True
