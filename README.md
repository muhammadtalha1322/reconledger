# reconledger

**Professional Automated Reconnaissance Script** for Debian/Kali Linux.

`reconledger` is a clean, well-structured, and reliable reconnaissance tool that performs systematic information gathering and generates professional HTML reports.

---

## Features

- Structured reconnaissance in logical phases (Passive OSINT → DNS → Ports → Web → WordPress → Vulnerabilities)
- Proper output organization: `~/Documents/reconledger_TARGET_TIMESTAMP/`
- Increased timeouts for reliable scanning of slow tools (WPScan, Nuclei, Nikto, etc.)
- Automatic WPScan database update
- Professional HTML report generation with executive summary, severity tables, and clean UI
- Support for `--quick`, `--full`, and `--stealth` modes
- Detailed logging

---

## Installation

```bash
# Clone the repository
git clone https://github.com/muhammadtalha1322/reconledger.git
cd reconledger

# Make scripts executable
chmod +x reconledger.sh reconledger_report.py
```

---

## Usage

```bash
# Basic usage (recommended)
sudo bash reconledger.sh example.com

# With mode
sudo bash reconledger.sh --full example.com
sudo bash reconledger.sh --quick example.com
sudo bash reconledger.sh --stealth example.com
```

After the scan completes, you will be asked whether to generate the HTML report.

You can also generate the report manually:

```bash
python3 reconledger_report.py ~/Documents/reconledger_example.com_20260616_XXXXXX
```

---

## Output Structure

```
reconledger_TARGET_TIMESTAMP/
├── dns/              → DNS records, subdomains, zone transfers
├── network/          → Port scans (masscan + nmap), banners
├── web/              → WhatWeb, Wafw00f, Gobuster, Nikto, probes
├── ssl/              → SSLScan, certificates, headers
├── osint/            → WHOIS, crt.sh, theHarvester
├── metadata/         → Emails, links, exiftool
├── wordpress/        → WP detection and full scanning
├── vuln/             → Nuclei findings, services
├── raw/              → Raw page sources
├── SUMMARY.txt
├── reconledger.log
└── REPORT_*.html     → Professional HTML report
```

---

## Requirements

- **Root privileges** (required for masscan, nmap, etc.)
- Kali Linux / Debian-based system
- Tools: `nmap`, `masscan`, `gobuster`, `nuclei`, `wpscan`, `subfinder`, `dnsrecon`, etc. (auto-installed if missing)

---

## Author

**Muhammad Talha**  
GitHub: [muhammadtalha1322](https://github.com/muhammadtalha1322)

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

This tool is intended for **authorized security testing and educational purposes only**.  
Unauthorized scanning of targets without explicit permission is illegal.
