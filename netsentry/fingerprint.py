"""Turn a raw service banner into a (service, version) guess."""

from __future__ import annotations

import re

# Each pattern captures the version string in group 1.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenSSH", re.compile(r"SSH-\d\.\d-OpenSSH[_-]([\w.]+)", re.I)),
    ("Apache", re.compile(r"Apache/([\d.]+)", re.I)),
    ("nginx", re.compile(r"nginx/([\d.]+)", re.I)),
    ("vsftpd", re.compile(r"vsftpd\s+([\d.]+)", re.I)),
    ("ProFTPD", re.compile(r"ProFTPD\s+([\d.]+)", re.I)),
    ("MySQL", re.compile(r"([\d.]+)-MariaDB|mysql_native_password.*?([\d.]+)", re.I)),
    ("OpenSSL", re.compile(r"OpenSSL/([\d.\w]+)", re.I)),
    ("Microsoft-IIS", re.compile(r"Microsoft-IIS/([\d.]+)", re.I)),
    ("Postfix", re.compile(r"Postfix\s*\(([\d.]+)\)", re.I)),
    ("Exim", re.compile(r"Exim\s+([\d.]+)", re.I)),
    ("Redis", re.compile(r"redis_version:([\d.]+)", re.I)),
]


def fingerprint(banner: str) -> dict:
    """Return {'service': str, 'version': str|None, 'banner': str} best-effort."""
    banner = (banner or "").strip()
    for service, pattern in PATTERNS:
        m = pattern.search(banner)
        if m:
            version = next((g for g in m.groups() if g), None)
            return {"service": service, "version": version, "banner": banner}
    return {"service": None, "version": None, "banner": banner}
