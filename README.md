# 🛡️ NetSentry

A lightweight network reconnaissance and known-vulnerability scanner.
It TCP-connect-scans a host, grabs service banners, fingerprints the
service/version, cross-references a small CVE table, and writes a
JSON/HTML report.

> ⚠️ **Authorized use only.** Only scan hosts you own or have explicit
> written permission to test. Scanning systems without authorization is
> illegal in most jurisdictions. The CLI requires an explicit
> `--i-have-authorization` flag and refuses to run without it.

## Why this project

Recon + fingerprinting + vulnerability matching is the core loop behind
tools like Nmap's `--script vuln` or Nessus, simplified into ~300 lines
of readable Python — good for demonstrating socket programming,
concurrency, and security fundamentals.

## Project layout

```
netsentry/
├── netsentry/
│   ├── scanner.py      # threaded TCP connect scan + banner grabbing
│   ├── fingerprint.py  # banner -> (service, version)
│   ├── vuln_db.py      # static service-version -> CVE lookup table
│   ├── report.py       # build JSON/HTML reports
│   └── cli.py          # argparse entrypoint
├── tests/
└── examples/
    ├── sample_report.json
    └── sample_report.html
```

## Quickstart

```bash
pip install -r requirements.txt

# scan localhost's common ports (requires explicit authorization flag)
python -m netsentry.cli --host 127.0.0.1 --i-have-authorization

# scan a custom port range and write reports
python -m netsentry.cli --host 127.0.0.1 --ports 1-1024 \
    --i-have-authorization --json report.json --html report.html
```

## Example output

Against two local test services (a fake vsftpd 2.3.4 and an old OpenSSH 6.6):

```
Open ports: 2  |  Findings: 3

  [9021] vsftpd 2.3.4
      -> [CRITICAL] CVE-2011-2523: Backdoored source (smiley-face backdoor) gives remote shell.
  [9022] OpenSSH 6.6
      -> [HIGH] CVE-2016-10009: Untrusted search path / agent socket bugs in older OpenSSH.
      -> [MEDIUM] CVE-2015-5600: Weak keyboard-interactive auth allows brute-force amplification.
```

See `examples/sample_report.html` for the rendered report.

## About the vulnerability database

`vuln_db.py` is a small, hand-curated, illustrative table (OpenSSH,
Apache, nginx, vsftpd, ProFTPD, IIS, Postfix, Redis, OpenSSL) — it exists
to show the matching mechanism, not to be an exhaustive feed. For real
use, swap `lookup()` to query the NVD/CVE API or a feed like vulners.com.

## Tests

```bash
pytest tests/
```

Tests spin up throwaway local TCP servers that emit known banners
(fake vsftpd/OpenSSH/Apache), so they run fully offline with no real
network scanning involved.

## Possible extensions

- UDP scanning, OS fingerprinting (TTL/window-size heuristics)
- Plug in a live CVE feed instead of the static table
- Rate limiting / stealth-scan timing options
- Export to SARIF for CI security-gate integration

## Publishing to GitHub

1. Create a new **empty** repo at https://github.com/new (e.g. name it `netsentry`) — don't add a README/license, this folder already has one.
2. From inside this folder:

```bash
git init
git add .
git commit -m "Initial commit: NetSentry network recon & vuln scanner"
git branch -M main
git remote add origin https://github.com/kajalhoskul/netsentry.git
git push -u origin main
```
