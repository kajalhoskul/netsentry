"""
A small, static, illustrative table of known-vulnerable service versions.

This is NOT a substitute for a real vulnerability feed (NVD/CVE API,
vulners.com, Nessus, etc.) -- it exists to demonstrate how version
fingerprints get turned into actionable findings. Each entry maps a
service name to a list of (constraint, CVE, severity, description) rules.

Constraint syntax: "<X.Y.Z" / "<=X.Y.Z" / "==X.Y.Z" compared against the
fingerprinted version using a simple dotted-tuple comparison.
"""

from __future__ import annotations

from dataclasses import dataclass


def _parse_version(v: str) -> tuple:
    parts = []
    for chunk in v.replace("-", ".").split("."):
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _satisfies(version: str, constraint: str) -> bool:
    for op in ("<=", ">=", "==", "<", ">"):
        if constraint.startswith(op):
            target = _parse_version(constraint[len(op):])
            v = _parse_version(version)
            # pad to equal length for a fair tuple comparison
            n = max(len(v), len(target))
            v = v + (0,) * (n - len(v))
            target = target + (0,) * (n - len(target))
            if op == "<=":
                return v <= target
            if op == ">=":
                return v >= target
            if op == "==":
                return v == target
            if op == "<":
                return v < target
            if op == ">":
                return v > target
    return False


@dataclass
class VulnRule:
    constraint: str
    cve: str
    severity: str
    description: str


VULN_DB: dict[str, list[VulnRule]] = {
    "OpenSSH": [
        VulnRule("<7.4", "CVE-2016-10009", "HIGH", "Untrusted search path / agent socket bugs in older OpenSSH."),
        VulnRule("<6.7", "CVE-2015-5600", "MEDIUM", "Weak keyboard-interactive auth allows brute-force amplification."),
    ],
    "Apache": [
        VulnRule("==2.4.49", "CVE-2021-41773", "CRITICAL", "Path traversal / RCE in mod_cgi (actively exploited)."),
        VulnRule("==2.4.50", "CVE-2021-42013", "CRITICAL", "Incomplete fix for CVE-2021-41773, still exploitable."),
        VulnRule("<2.4.41", "CVE-2019-0211", "HIGH", "Local privilege escalation via worker processes."),
    ],
    "nginx": [
        VulnRule("<1.20.1", "CVE-2021-23017", "HIGH", "DNS resolver off-by-one heap write."),
    ],
    "vsftpd": [
        VulnRule("==2.3.4", "CVE-2011-2523", "CRITICAL", "Backdoored source (smiley-face backdoor) gives remote shell."),
    ],
    "ProFTPD": [
        VulnRule("<=1.3.3", "CVE-2010-4221", "HIGH", "Stack buffer overflow in telnet option handling."),
        VulnRule("==1.3.5", "CVE-2015-3306", "CRITICAL", "mod_copy lets unauthenticated users copy files remotely."),
    ],
    "Microsoft-IIS": [
        VulnRule("<=6.0", "CVE-2017-7269", "CRITICAL", "Buffer overflow in WebDAV ScStoragePathFromUrl (RCE)."),
    ],
    "Postfix": [
        VulnRule("<3.4.14", "CVE-2020-24977", "MEDIUM", "Out-of-bounds read in the queue manager."),
    ],
    "Redis": [
        VulnRule("<5.0", "CVE-2019-10192", "HIGH", "Heap buffer overflow via crafted ziplist headers."),
    ],
    "OpenSSL": [
        VulnRule("==1.0.1", "CVE-2014-0160", "CRITICAL", "Heartbleed: out-of-bounds read leaks process memory."),
    ],
}


def lookup(service: str | None, version: str | None) -> list[dict]:
    if not service or not version or service not in VULN_DB:
        return []
    findings = []
    for rule in VULN_DB[service]:
        if _satisfies(version, rule.constraint):
            findings.append(
                {
                    "cve": rule.cve,
                    "severity": rule.severity,
                    "description": rule.description,
                    "matched_constraint": rule.constraint,
                }
            )
    return findings
