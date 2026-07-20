"""NetSentry CLI.

Usage:
    python -m netsentry.cli --host 127.0.0.1 --ports 20-25,80,443 --json out.json --html out.html
"""

from __future__ import annotations

import argparse
import sys

from netsentry.report import build_report, to_html, to_json
from netsentry.scanner import COMMON_PORTS, parse_port_range, scan_host

DISCLAIMER = (
    "NetSentry is for authorized security testing and learning only.\n"
    "Only scan hosts you own or have explicit written permission to test."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lightweight network recon & known-vuln scanner.")
    parser.add_argument("--host", required=True, help="Target host/IP (must be authorized)")
    parser.add_argument("--ports", default=None, help="e.g. '22,80,443' or '1-1024'. Default: common ports")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--json", dest="json_out", default=None, help="Write JSON report to this path")
    parser.add_argument("--html", dest="html_out", default=None, help="Write HTML report to this path")
    parser.add_argument("--i-have-authorization", action="store_true", help="Confirm you are authorized to scan this host")
    args = parser.parse_args(argv)

    print(DISCLAIMER, file=sys.stderr)
    if not args.i_have_authorization:
        print("\nRefusing to scan: pass --i-have-authorization to confirm you own/have permission "
              "to test this host.", file=sys.stderr)
        return 1

    ports = parse_port_range(args.ports) if args.ports else COMMON_PORTS
    print(f"Scanning {args.host} on {len(ports)} port(s)...", file=sys.stderr)

    scan_results = scan_host(args.host, ports=ports, timeout=args.timeout)
    report = build_report(args.host, scan_results)

    print(f"\nOpen ports: {report['open_ports']}  |  Findings: {report['total_findings']}\n")
    for r in report["results"]:
        print(f"  [{r['port']}] {r['service'] or 'unknown'} {r['version'] or ''}")
        for v in r["vulnerabilities"]:
            print(f"      -> [{v['severity']}] {v['cve']}: {v['description']}")

    if args.json_out:
        to_json(report, args.json_out)
        print(f"\nJSON report written to {args.json_out}")
    if args.html_out:
        to_html(report, args.html_out)
        print(f"HTML report written to {args.html_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
