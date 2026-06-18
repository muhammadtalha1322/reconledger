# reconledger

A modular, pipeline-driven reconnaissance framework for authorized penetration testing engagements. ReconLedger runs a structured 14-phase scan against a target domain or IP and produces a comprehensive single-file HTML report with an executive summary, timeline view, PDF export, and JSON export.

---

## Contents

```
reconledger/
├── reconledger.sh           # Scanner — 14-phase recon pipeline
├── reconledger_report.py    # Report generator — HTML output from scan folder
├── README.md
├── LICENSE                  # MIT
├── requirements.txt
├── .gitignore
└── examples/
    └── README.md
```

---

## Requirements

### Operating System

Kali Linux is the intended and tested platform. The scanner auto-installs missing tools via `nala` or `apt-get` on first run.

### Python

Python 3.8 or later. The report generator uses the standard library only — no pip installs required.

### Wordlists

The scanner uses [SecLists](https://github.com/danielmiessler/SecLists) for subdomain brute-force and directory discovery. SecLists is installed automatically if missing. Default paths used:

| Purpose | Path |
|---|---|
| Subdomain brute-force | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Directory discovery | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| Fallback directory | `/usr/share/wordlists/dirb/common.txt` |

If SecLists is not installed and auto-install fails, install it manually:

```bash
sudo apt install seclists
```

---

## Installation

```bash
git clone https://github.com/yourusername/reconledger.git
cd reconledger
chmod +x reconledger.sh
```

No further setup is required. Run the scanner as root and it installs missing tools on first run.

---

## Usage

### Scanner

```bash
sudo bash reconledger.sh [--quick|--full|--stealth] <target>
```

| Flag | Description |
|---|---|
| `--full` | Default. Comprehensive scan with vuln scripts. Estimated runtime: 30–90 minutes. |
| `--quick` | Fast scan: top 1000 ports, no vuln scripts, no UDP. Estimated runtime: 5–15 minutes. |
| `--stealth` | Slow timing (T2), reduced packet rate, minimal noise on the wire. |

Examples:

```bash
sudo bash reconledger.sh example.com
sudo bash reconledger.sh --quick 192.168.1.10
sudo bash reconledger.sh --stealth target.internal
```

Scan output is saved to:

```
~/Documents/reconledger_<target>_<timestamp>/
```

At the end of every scan, the script asks whether to generate an HTML report immediately.

### Report Generator

```bash
python3 reconledger_report.py <scan_folder>
```

Example:

```bash
python3 reconledger_report.py ~/Documents/reconledger_example.com_20260101_120000
```

The report is written as `REPORT_<timestamp>.html` inside the scan folder. Open it in any modern browser. No web server is required.

---

## Scan Phases

The scanner runs in strict recon methodology order. Each phase feeds its output into the next where applicable.

| Phase | Description |
|---|---|
| 1 | Tool check and auto-install |
| 2 | Target validation and IP resolution |
| 3 | CDN / WAF detection (before active traffic hits the target) |
| 4 | Passive OSINT — WHOIS, theHarvester, crt.sh |
| 5 | DNS enumeration — dig, dnsrecon, dnsenum, fierce, subfinder, amass, AXFR |
| 6 | Port scanning — masscan full sweep → targeted nmap sV/sC/OS |
| 7 | Service-specific nmap scripts — SSH, SMB, FTP, MySQL (port-gated) |
| 8 | Web fingerprinting — whatweb, wafw00f |
| 9 | Web content discovery — gobuster, ffuf, nikto, sensitive path probes |
| 10 | SSL/TLS analysis — sslscan, openssl, security header audit |
| 11 | Metadata extraction — exiftool, emails, links |
| 12 | WordPress detection and full WP suite (conditional) |
| 13 | Vulnerability scanning — nuclei, searchsploit, sqlmap, hydra |
| 14 | Summary report generation |

---

## Report Features

The HTML report is a single self-contained file with no external dependencies.

- **Executive Summary** — plain-English paragraph auto-generated from all findings
- **Overview Dashboard** — stat cards for critical/high/medium/low counts, ports, subdomains, emails, and more
- **Vulnerability Table** — nuclei findings sorted by severity with deduplication
- **Timeline View** — each scan phase with timestamp and timeout extracted from the log
- **PDF Export** — browser print-to-PDF via the Print button in the report header. No additional tools required
- **JSON Export** — downloads all parsed findings as a structured `.json` file
- **Sticky Navigation** — jump directly to any section
- **Print Stylesheet** — clean, readable output when printed or saved as PDF

Sections covered: Executive Summary, Overview, Vulnerabilities (Nuclei), Ports and Services, Web Recon (gobuster + ffuf + nikto + probes), DNS Enumeration, SSL/TLS, OSINT, Metadata, Exploit Matching (searchsploit + sqlmap + hydra), WordPress (conditional), Nikto, Timeline, and raw Logs.

---

## Tool Coverage

### Scanner tools (auto-installed)

`nmap`, `masscan`, `dnsrecon`, `dnsenum`, `fierce`, `subfinder`, `amass`, `gobuster`, `ffuf`, `nikto`, `sslscan`, `whatweb`, `wafw00f`, `theHarvester`, `wpscan`, `nuclei`, `searchsploit`, `sqlmap`, `hydra`, `exiftool`, `curl`, `dig`, `whois`, `wget`, `traceroute`

### Report parsers

| Tool | What is parsed |
|---|---|
| nuclei | Severity, template name, URL — deduplicated on template+URL key |
| wpscan | Warnings and info lines from full enumeration output |
| nmap | Open TCP/UDP ports, service names, version strings |
| gobuster | Directory paths and HTTP status codes |
| ffuf | Directory paths, status codes, response length — JSON output preferred |
| amass | Passive subdomain list — merged with subfinder output |
| sqlmap | Injection findings from log files or text output |
| hydra | Successful login attempts |
| searchsploit | Exploit titles and paths, aggregated per detected service version |
| nikto | All lines starting with `+` |

---

## WordPress Handling

WordPress is detected using four independent signals: `wp-login.php` HTTP status, `wp-content` in page source, `wp-json/` REST API availability, and the generator meta tag. Two or more signals trigger the full WP suite.

When WordPress is detected, the scanner runs:

- wpscan full enumeration with `--request-timeout 120 --connect-timeout 60` to handle slow remote instances
- wpscan vulnerable plugin and theme checks
- REST API user enumeration
- `?author=` parameter walk
- Plugin and theme detection from page source
- Sensitive path probes covering 20 WP-specific endpoints
- XML-RPC analysis
- Nuclei WordPress templates

wpscan database is updated automatically before each scan. If the update fails (outdated gem), the scanner attempts a gem reinstall before continuing.

---

## CDN / WAF Awareness

CDN and WAF detection runs in Phase 3, before any active port scanning. If Cloudflare, Akamai, Fastly, Sucuri, or Imperva is detected, the scanner prints a warning and records it in `network/cdn_check.txt`. Port scan results in CDN-protected environments reflect edge infrastructure rather than the origin server. The report flags this in the executive summary.

---

## Output Structure

```
~/Documents/reconledger_<target>_<timestamp>/
├── dns/                DNS records, AXFR attempts, subdomain lists
├── network/            masscan output, nmap targeted/vuln/UDP, service scripts, banners
├── web/                whatweb, wafw00f, nikto, gobuster, ffuf, sensitive path probes
├── ssl/                sslscan, openssl cert, security header analysis
├── osint/              WHOIS, theHarvester (per source), crt.sh
├── metadata/           emails, links, URLs, exiftool
├── vuln/               nuclei findings, searchsploit per service, sqlmap, hydra
├── wordpress/          wpscan, WP detection, version, users, paths, REST API, XML-RPC
├── raw/                raw page source (index.html)
├── SUMMARY.txt         plain-text summary generated at end of scan
├── reconledger.log     full execution log with timestamps
└── REPORT_<ts>.html    generated HTML report
```

---

## Legal Notice

ReconLedger is intended exclusively for use against systems you own or have explicit written authorization to test. Unauthorized use is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent legislation in other jurisdictions. The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE).
