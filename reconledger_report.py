#!/usr/bin/env python3
"""
reconledger — Professional HTML Report Generator
Reads output from reconledger.sh and generates a clean, professional report.

Usage:
    python3 reconledger_report.py <recon_folder>
"""

import os
import re
import sys
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def read_file(path, max_lines=None):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            if max_lines:
                lines = content.splitlines()[:max_lines]
                return "\n".join(lines)
            return content.strip()
    except Exception:
        return ""

def read_lines(path):
    content = read_file(path)
    return [line.strip() for line in content.splitlines() if line.strip()]

def parse_nuclei(content):
    findings = []
    severity_pattern = re.compile(r'\[(critical|high|medium|low|info)\]', re.IGNORECASE)
    template_pattern = re.compile(r'^\[([^\]]+)\]')
    url_pattern = re.compile(r'(https?://[^\s\]]+)')

    for line in content.splitlines():
        line = line.strip()
        if not line or any(line.startswith(x) for x in ["[INF]", "[WRN]", "[ERR]"]):
            continue
        sev_match = severity_pattern.search(line)
        if not sev_match:
            continue
        sev = sev_match.group(1).upper()

        tpl_match = template_pattern.match(line)
        tpl = tpl_match.group(1) if tpl_match else "unknown"

        url_match = url_pattern.search(line)
        url = url_match.group(1) if url_match else "N/A"

        findings.append({"severity": sev, "template": tpl, "url": url, "raw": line})
    return findings

def parse_wpscan(content):
    findings = []
    for line in content.splitlines():
        line = line.strip()
        if "[!]" in line:
            findings.append({"type": "warning", "detail": line})
        elif "[+]" in line:
            findings.append({"type": "info", "detail": line})
    return findings

def parse_nmap_open_ports(content):
    ports = []
    for line in content.splitlines():
        m = re.match(r'(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)', line)
        if m:
            ports.append({
                "port": m.group(1),
                "service": m.group(2),
                "version": m.group(3).strip()
            })
    return ports

def parse_subdomains(content):
    subs = [line.strip() for line in content.splitlines() if line.strip() and "." in line and not line.startswith("#")]
    return list(dict.fromkeys(subs))

def parse_gobuster(content):
    found = []
    for line in content.splitlines():
        m = re.search(r'(https?://\S+|/\S*)\s+\(Status:\s*(\d+)\)', line)
        if m:
            found.append({"url": m.group(1), "status": m.group(2)})
    return found

def parse_ssl_headers(content):
    headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
               "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
    present = [h for h in headers if h.lower() in content.lower()]
    missing = [h for h in headers if h.lower() not in content.lower()]
    return {"present": present, "missing": missing}

def parse_emails(content):
    return list(dict.fromkeys(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', content)))

def severity_order(s):
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(s, 5)

# ─────────────────────────────────────────────────────────────
#  HTML HELPERS
# ─────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": "#ff2d2d", "HIGH": "#ff6b00", "MEDIUM": "#ffc107",
    "LOW": "#00e676", "INFO": "#29b6f6"
}

def sev_badge(sev):
    color = SEV_COLOR.get(sev, "#aaa")
    text_color = "#000" if sev in ("MEDIUM", "LOW") else "#fff"
    return f'<span class="badge" style="background:{color};color:{text_color}">{sev}</span>'

def status_badge(code):
    color = "#00e676" if code.startswith("2") else "#ffc107" if code.startswith("3") else "#aaa"
    return f'<span class="badge" style="background:{color};color:#000">{code}</span>'

def h(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def code_block(text, max_lines=60):
    if not text:
        return '<p class="empty">No data available.</p>'
    lines = text.splitlines()[:max_lines]
    content = h("\n".join(lines))
    return f'<pre class="code">{content}</pre>'

def stat_card(label, value, color="#00e5ff"):
    return f'''<div class="stat-card">
      <div class="stat-val" style="color:{color}">{value}</div>
      <div class="stat-label">{label}</div>
    </div>'''

# ─────────────────────────────────────────────────────────────
#  MAIN REPORT BUILDER
# ─────────────────────────────────────────────────────────────

def build_report(folder):
    folder = Path(folder).resolve()
    if not folder.exists():
        print(f"[-] Folder not found: {folder}")
        sys.exit(1)

    # Extract target from folder name
    m = re.search(r'reconledger_(.+?)_\d{8}_\d{6}', folder.name)
    target = m.group(1) if m else folder.name

    print(f"[*] Building reconledger report for: {target}")

    def f(rel): return folder / rel
    def r(rel): return read_file(f(rel))
    def rl(rel): return read_lines(f(rel))

    # Read key files
    target_ip       = r("network/target_ip.txt").strip()
    open_ports      = parse_nmap_open_ports(r("network/nmap_targeted.txt"))
    subdomains      = parse_subdomains(r("dns/subfinder_list.txt"))
    nuclei_raw      = r("vuln/nuclei_findings.txt") or r("vuln/nuclei_all.txt")
    nuclei_findings = parse_nuclei(nuclei_raw)
    nuclei_findings.sort(key=lambda x: severity_order(x["severity"]))

    wpscan_raw      = r("wordpress/wpscan.txt")
    wpscan_findings = parse_wpscan(wpscan_raw)
    is_wp           = bool("DETECTED" in r("wordpress/wp_detection.txt") or wpscan_findings)

    gobuster_dirs   = parse_gobuster(r("web/gobuster_dirs.txt"))
    whatweb         = r("web/whatweb.txt")
    wafw00f         = r("web/wafw00f.txt")
    nikto_out       = [line for line in read_lines(f("web/nikto.txt")) if line.strip().startswith("+")]
    emails_found    = parse_emails(r("metadata/emails_found.txt"))
    whois_raw       = r("osint/whois.txt")

    # Counts
    crit_count = sum(1 for f in nuclei_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in nuclei_findings if f["severity"] == "HIGH")
    med_count  = sum(1 for f in nuclei_findings if f["severity"] == "MEDIUM")
    low_count  = sum(1 for f in nuclei_findings if f["severity"] == "LOW")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>reconledger Report — {h(target)}</title>
<style>
  :root {{
    --bg: #0a0a0f; --bg2: #10101a; --bg3: #161625;
    --border: #1e1e35; --accent: #00e5ff; --text: #c9d1d9;
  }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; font-size: 13px; }}
  .header {{ background: linear-gradient(135deg, #0d0d1a, #12122a); padding: 30px 40px; border-bottom: 2px solid var(--accent); }}
  .header h1 {{ font-size: 24px; color: var(--accent); }}
  .nav {{ background: var(--bg2); padding: 12px 40px; display: flex; gap: 8px; flex-wrap: wrap; position: sticky; top: 0; z-index: 100; }}
  .nav a {{ color: #888; text-decoration: none; padding: 6px 12px; border: 1px solid #333; border-radius: 4px; font-size: 12px; }}
  .nav a:hover {{ color: var(--accent); border-color: var(--accent); }}
  .main {{ max-width: 1400px; margin: 0 auto; padding: 30px 40px; }}
  .section {{ margin-bottom: 50px; }}
  .section-title {{ font-size: 14px; color: var(--accent); border-left: 4px solid var(--accent); padding-left: 12px; margin-bottom: 16px; }}
  .stat-grid {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }}
  .stat-card {{ background: var(--bg2); border: 1px solid #333; border-radius: 6px; padding: 16px; text-align: center; min-width: 130px; }}
  .stat-val {{ font-size: 26px; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 8px 12px; border-bottom: 1px solid #333; text-align: left; }}
  th {{ background: var(--bg3); color: var(--accent); }}
  .badge {{ padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }}
  .code {{ background: var(--bg2); border: 1px solid #333; padding: 12px; overflow-x: auto; white-space: pre; font-size: 12px; max-height: 500px; }}
  .empty {{ color: #666; font-style: italic; }}
</style>
</head>
<body>

<div class="header">
  <h1>reconledger Report</h1>
  <p><strong>Target:</strong> {h(target)} &nbsp;|&nbsp; <strong>Generated:</strong> {now}</p>
</div>

<nav class="nav">
  <a href="#overview">Overview</a>
  <a href="#vulns">Vulnerabilities</a>
  <a href="#ports">Ports</a>
  <a href="#web">Web</a>
  <a href="#dns">DNS</a>
  <a href="#ssl">SSL</a>
  <a href="#wordpress">WordPress</a>
</nav>

<div class="main">

<div class="section" id="overview">
  <div class="section-title">Overview</div>
  <div class="stat-grid">
    {stat_card("Critical", crit_count, "#ff2d2d")}
    {stat_card("High", high_count, "#ff6b00")}
    {stat_card("Medium", med_count, "#ffc107")}
    {stat_card("Low", low_count, "#00e676")}
    {stat_card("Open Ports", len(open_ports))}
    {stat_card("Subdomains", len(subdomains))}
    {stat_card("Emails", len(emails_found))}
  </div>
</div>

<div class="section" id="vulns">
  <div class="section-title">Vulnerability Findings — Nuclei ({len(nuclei_findings)})</div>
"""
    if nuclei_findings:
        html += '<table><thead><tr><th>Severity</th><th>Template</th><th>URL</th></tr></thead><tbody>'
        for f in nuclei_findings:
            html += f'<tr><td>{sev_badge(f["severity"])}</td><td>{h(f["template"])}</td><td>{h(f["url"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No vulnerabilities found.</p>'

    html += f"""
  <div class="section-title" style="margin-top:20px">Raw Nuclei Output</div>
  {code_block(nuclei_raw, 100)}
</div>

<div class="section" id="ports">
  <div class="section-title">Open Ports & Services</div>
  <table>
    <thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead>
    <tbody>
"""
    for p in open_ports:
        html += f'<tr><td>{h(p["port"])}</td><td>{h(p["service"])}</td><td>{h(p["version"])}</td></tr>'
    html += '</tbody></table></div>'

    # Add more sections as needed (Web, DNS, SSL, WordPress, etc.)

    html += f"""
</div>
</body>
</html>"""

    # Save report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = folder / f"REPORT_reconledger_{ts}.html"

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Report generated successfully!")
    print(f"[+] Saved to: {outfile}")
    return outfile


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 reconledger_report.py <recon_folder>")
        sys.exit(1)

    build_report(sys.argv[1])
