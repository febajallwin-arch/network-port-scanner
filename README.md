# 🔍 Network Port Scanner

**Multithreaded TCP/IP port scanner with service fingerprinting**  
Built by [Feba J Allwin](https://github.com/febajallwin-arch) — Cybersecurity & Cloud Portfolio

---

## Features

| Feature | Details |
|---|---|
| **Speed** | 1,000+ ports scanned in under 60 seconds (200 threads) |
| **Fingerprinting** | 70+ services identified via port database + banner grabbing |
| **OS Detection** | TTL-based OS hint (Linux / Windows / Network device) |
| **Reports** | Export to HTML, JSON, CSV, TXT |
| **Risk Scoring** | CRITICAL / HIGH / MEDIUM / LOW / INFO per open port |
| **Real-time output** | Live progress bar + instant open-port display |
| **Zero dependencies** | Pure Python 3 stdlib — no pip install needed |

---

## Quick Start

```bash
# Clone / download the project
git clone https://github.com/febajallwin-arch/network-port-scanner
cd network-port-scanner

# Basic scan (ports 1–1024)
python cli.py scanme.nmap.org

# Full port scan (1–65535)
python cli.py 192.168.1.1 -p all

# Custom range with 500 threads
python cli.py 10.0.0.1 -p 1-10000 -t 500

# Specific ports + HTML report
python cli.py example.com -p 22,80,443,3306,8080 -o report.html

# Fast scan (no banners)
python cli.py 192.168.1.1 -p common --no-banner
```

---

## CLI Reference

```
usage: netscan [-h] [-p PORTS] [-t N] [--timeout SEC] [--no-banner] [-o FILE] target

positional arguments:
  target          Target hostname, IP address

options:
  -p, --ports     Port specification (default: common)
                    common     → 1-1024
                    all        → 1-65535
                    80-8080    → custom range
                    22,80,443  → specific ports
  -t, --threads   Worker threads (default: 200, max: 1000)
  --timeout       Per-port timeout in seconds (default: 1.0)
  --no-banner     Skip banner grabbing (faster)
  -o, --output    Save report: report.html / .json / .csv / .txt
  --no-color      Disable ANSI colors (for logging/piping)
```

---

## Output Example

```
  PORT    STATE       SERVICE         DESCRIPTION                                   LATENCY    SEVERITY
  ──────  ──────────  ──────────────  ────────────────────────────────────────────  ─────────  ──────────
  22      OPEN        SSH             Secure Shell                                   12.3ms    [INFO]
  80      OPEN        HTTP            HyperText Transfer Protocol                     8.7ms    [INFO]
  443     OPEN        HTTPS           HTTP Secure / TLS                               9.1ms    [INFO]
  3306    OPEN        MySQL           MySQL Database                                 18.2ms    [MEDIUM]
  2375    OPEN        Docker          Docker Daemon (unencrypted)                     5.0ms    [CRITICAL]
```

---

## Project Structure

```
network_port_scanner/
├── scanner.py       — Core scanning engine (PortScanner class)
├── cli.py           — CLI interface with progress bars + colors
├── reporter.py      — Report generator (HTML, JSON, CSV, TXT)
├── tests.py         — Unit tests (25+ test cases)
├── requirements.txt — Dependencies (none required)
└── README.md        — This file
```

---

## Architecture

```
cli.py  ──────────►  PortScanner (scanner.py)
  │                        │
  │                   Thread Pool (200 workers)
  │                        │
  │                   _scan_port()
  │                        ├── TCP connect_ex()
  │                        ├── SERVICE_DB lookup
  │                        ├── _grab_banner()
  │                        └── _fingerprint_banner()
  │
  └──────────►  Reporter (reporter.py)
                    ├── to_html()
                    ├── to_json()
                    ├── to_csv()
                    └── to_txt()
```

---

## Service Fingerprinting

The scanner uses a two-layer approach:

1. **Port Database** — 70+ known port-to-service mappings (FTP, SSH, HTTP, MySQL, Redis, MongoDB, Kubernetes, Docker, etc.)
2. **Active Banner Grabbing** — Connects and reads the service banner to identify:
   - SSH version strings
   - HTTP server headers
   - SMTP EHLO responses
   - Database identification strings

---

## Risk Scoring

| Severity | Example Ports | Meaning |
|---|---|---|
| CRITICAL | 2375 (Docker), 4444 | Immediate security risk |
| HIGH | 23 (Telnet), 6379 (Redis), 27017 (MongoDB) | Dangerous if exposed |
| MEDIUM | 3306 (MySQL), 3389 (RDP) | Sensitive — restrict access |
| LOW | Non-standard services | Review recommended |
| INFO | 80 (HTTP), 443 (HTTPS) | Standard open ports |

---

## Running Tests

```bash
python tests.py
```

Expected output:
```
test_all_entries_have_name_and_desc ... ok
test_database_not_empty ... ok
test_well_known_ports ... ok
test_banner_truncated ... ok
test_to_dict ... ok
...
Ran 17 tests in 0.08s
OK
```

---

## Legal Notice

> This tool is built for **authorized security testing and educational purposes only**.  
> Never scan hosts or networks without **explicit written permission**.  
> The author assumes no responsibility for misuse.

---

## Author

**Feba J Allwin**  
B.Tech Information Technology | St. Peter's CET, Chennai  
📧 febajallwin@gmail.com  
🔗 [linkedin.com/in/feba-j-allwin-2b4198354](https://linkedin.com/in/feba-j-allwin-2b4198354)  
💻 [github.com/febajallwin-arch](https://github.com/febajallwin-arch)

---

*Part of the Cybersecurity & Cloud Portfolio — targeting SOC Analyst, Security Analyst & DevSecOps Intern roles.*