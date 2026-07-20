"""Build and render scan reports (dict -> JSON / HTML)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from netsentry.fingerprint import fingerprint
from netsentry.vuln_db import lookup

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_report(host: str, scan_results: list[dict]) -> dict:
    findings = []
    for r in scan_results:
        if not r["open"]:
            continue
        fp = fingerprint(r["banner"])
        vulns = lookup(fp["service"], fp["version"])
        findings.append(
            {
                "port": r["port"],
                "service": fp["service"],
                "version": fp["version"],
                "banner": fp["banner"],
                "vulnerabilities": sorted(vulns, key=lambda v: SEVERITY_ORDER.get(v["severity"], 9)),
            }
        )
    total_vulns = sum(len(f["vulnerabilities"]) for f in findings)
    return {
        "host": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "open_ports": len(findings),
        "total_findings": total_vulns,
        "results": findings,
    }


def to_json(report: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


HTML_TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>NetSentry report: {host}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; }}
h1 {{ margin-bottom: 0; }}
.meta {{ color: #666; margin-bottom: 20px; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
th, td {{ padding: 8px 12px; border-bottom: 1px solid #ddd; text-align: left; vertical-align: top; }}
th {{ background: #f5f5f5; }}
.sev-CRITICAL {{ color: #b71c1c; font-weight: bold; }}
.sev-HIGH {{ color: #e65100; font-weight: bold; }}
.sev-MEDIUM {{ color: #f9a825; }}
.sev-LOW {{ color: #558b2f; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; }}
</style></head>
<body>
<h1>NetSentry scan report</h1>
<p class="meta">Host: <strong>{host}</strong> &middot; Scanned: {scanned_at} &middot;
Open ports: {open_ports} &middot; Findings: {total_findings}</p>
<table>
<tr><th>Port</th><th>Service</th><th>Version</th><th>Vulnerabilities</th></tr>
{rows}
</table>
</body></html>
"""


def to_html(report: dict, path: str) -> None:
    rows = []
    for r in report["results"]:
        vulns = r["vulnerabilities"]
        if vulns:
            vuln_html = "<br>".join(
                f'<span class="sev-{v["severity"]}">[{v["severity"]}] {v["cve"]}</span>: {v["description"]}'
                for v in vulns
            )
        else:
            vuln_html = "<em>none known</em>"
        rows.append(
            f"<tr><td>{r['port']}</td><td>{r['service'] or '?'}</td>"
            f"<td>{r['version'] or '?'}</td><td>{vuln_html}</td></tr>"
        )
    html = HTML_TEMPLATE.format(
        host=report["host"],
        scanned_at=report["scanned_at"],
        open_ports=report["open_ports"],
        total_findings=report["total_findings"],
        rows="\n".join(rows) or "<tr><td colspan=4>No open ports found.</td></tr>",
    )
    with open(path, "w") as f:
        f.write(html)
