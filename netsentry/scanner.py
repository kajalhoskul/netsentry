"""TCP port scanning and banner grabbing."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 3306, 3389, 5432, 6379, 8080, 8443]

# For services that don't speak first (HTTP-like), send a probe to elicit a banner.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: probe\r\nConnection: close\r\n\r\n"
_PROBE_PORTS = {80, 443, 8080, 8443, 8000, 8888}


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in _PROBE_PORTS:
                try:
                    sock.sendall(HTTP_PROBE)
                except OSError:
                    pass
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""
            return data.decode(errors="ignore")
    except OSError:
        return ""


def scan_host(host: str, ports: list[int] | None = None, timeout: float = 1.0, max_workers: int = 50) -> list[dict]:
    """Return a list of {'port': int, 'open': bool, 'banner': str} for each port."""
    ports = ports or COMMON_PORTS
    results: dict[int, dict] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(is_port_open, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            p = futures[future]
            results[p] = {"port": p, "open": future.result(), "banner": ""}

    open_ports = [p for p, r in results.items() if r["open"]]
    if open_ports:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(grab_banner, host, p, timeout): p for p in open_ports}
            for future in as_completed(futures):
                p = futures[future]
                results[p]["banner"] = future.result()

    return [results[p] for p in sorted(results)]


def parse_port_range(spec: str) -> list[int]:
    """Parse '22,80,1000-1010' style specs into a sorted list of ints."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(ports)
