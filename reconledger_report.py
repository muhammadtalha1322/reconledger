#!/usr/bin/env python3
"""
ReconLedger v2 — HTML Report Generator
Reads all output files from a reconledger scan folder and produces
a comprehensive, single-file HTML report.

Usage:
    python3 reconledger_report.py <scan_folder>
    python3 reconledger_report.py ~/Documents/reconledger_example.com_20260101_120000

Dependencies:
    Standard library only — no external packages required.
"""

import os
import re
import sys
import json
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────
#  FILE READERS
# ─────────────────────────────────────────────────────────────

def read_file(path, max_lines=None):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            if max_lines:
                lines = lines[:max_lines]
            return "".join(lines).strip()
    except Exception:
        return ""

def read_lines(path):
    content = read_file(path)
    return [l.strip() for l in content.splitlines() if l.strip()] if content else []

def file_exists(path):
    try:
        return Path(path).exists() and Path(path).stat().st_size > 0
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────
#  PARSERS
# ─────────────────────────────────────────────────────────────

def parse_nuclei(content):
    findings = []
    seen = set()
    sev_pattern = re.compile(r'\[(critical|high|medium|low|info)\]', re.IGNORECASE)
    tpl_pattern = re.compile(r'^\[([^\]]+)\]')
    url_pattern = re.compile(r'(https?://[^\s\]]+)')

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("[INF]") or line.startswith("[WRN]") or line.startswith("[ERR]"):
            continue
        sev_m = sev_pattern.search(line)
        if not sev_m:
            continue
        sev = sev_m.group(1).upper()
        tpl_m = tpl_pattern.match(line)
        tpl = tpl_m.group(1) if tpl_m else "unknown"
        url_m = url_pattern.search(line)
        url = url_m.group(1) if url_m else "N/A"

        dedup_key = f"{tpl}|{url}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        findings.append({"severity": sev, "template": tpl, "url": url, "raw": line})
    return findings

def parse_wpscan(content):
    findings = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if "[!]" in line:
            findings.append({"type": "warning", "detail": line})
        elif "[+]" in line:
            findings.append({"type": "info", "detail": line})
    return findings

def parse_nmap_open_ports(content):
    ports = []
    seen = set()
    for line in content.splitlines():
        m = re.match(r'(\d+/(?:tcp|udp))\s+open\s+(\S+)\s*(.*)', line)
        if m:
            port = m.group(1)
            if port not in seen:
                seen.add(port)
                ports.append({
                    "port":    port,
                    "service": m.group(2),
                    "version": m.group(3).strip()
                })
    return ports

def parse_subdomains(content):
    subs = []
    seen = set()
    for line in content.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#") and "." in line and line not in seen:
            seen.add(line)
            subs.append(line)
    return subs

def parse_gobuster(content):
    found = []
    seen = set()
    for line in content.splitlines():
        m = re.search(r'(https?://\S+|/\S*)\s+\(Status:\s*(\d+)\)', line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            found.append({"url": m.group(1), "status": m.group(2)})
            continue
        m2 = re.match(r'(/\S+)\s+\[Status: (\d+)', line)
        if m2 and m2.group(1) not in seen:
            seen.add(m2.group(1))
            found.append({"url": m2.group(1), "status": m2.group(2)})
    return found

def parse_ffuf(folder):
    """Parse ffuf JSON output if available."""
    results = []
    json_file = Path(folder) / "web" / "ffuf_results.json"
    if not json_file.exists():
        return results
    try:
        with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        for item in data.get("results", []):
            results.append({
                "url":    item.get("url", ""),
                "status": str(item.get("status", "")),
                "length": str(item.get("length", "")),
                "words":  str(item.get("words", "")),
            })
    except Exception:
        # Fallback: parse the text output
        txt = read_file(Path(folder) / "web" / "ffuf_dirs.txt")
        for line in txt.splitlines():
            m = re.search(r'(/.+?)\s+\[Status: (\d+)', line)
            if m:
                results.append({"url": m.group(1), "status": m.group(2), "length": "", "words": ""})
    return results

def parse_amass(folder):
    """Merge amass subdomain list with subfinder list, deduplicated."""
    subs = set()
    for fname in ["dns/amass_list.txt", "dns/subfinder_list.txt", "dns/subfinder.txt"]:
        content = read_file(Path(folder) / fname)
        for line in content.splitlines():
            line = line.strip().lower()
            if line and "." in line:
                subs.add(line)
    return sorted(subs)

def parse_sqlmap(folder):
    """Extract sqlmap findings from output directory or text file."""
    findings = []
    sqlmap_dir = Path(folder) / "vuln" / "sqlmap_output"
    sqlmap_txt = Path(folder) / "vuln" / "sqlmap.txt"

    if sqlmap_dir.exists():
        for log_file in sqlmap_dir.rglob("*.log"):
            content = read_file(log_file)
            for line in content.splitlines():
                if any(kw in line.lower() for kw in ["injectable", "parameter", "payload", "error-based", "boolean-based", "time-based"]):
                    findings.append(line.strip())
    elif sqlmap_txt.exists():
        content = read_file(sqlmap_txt)
        for line in content.splitlines():
            if any(kw in line.lower() for kw in ["injectable", "parameter", "payload", "identified"]):
                findings.append(line.strip())

    # Deduplicate
    return list(dict.fromkeys(findings))

def parse_hydra(content):
    """Extract hydra successful login attempts."""
    hits = []
    for line in content.splitlines():
        if "[22]" in line or "login:" in line.lower():
            if "host:" in line.lower() or "login:" in line.lower():
                hits.append(line.strip())
    return hits

def parse_searchsploit(folder):
    """Aggregate all searchsploit results from vuln/ directory."""
    results = []
    vuln_dir = Path(folder) / "vuln"
    if not vuln_dir.exists():
        return results
    seen = set()
    for f in sorted(vuln_dir.glob("searchsploit_*.txt")):
        content = read_file(f)
        service = f.stem.replace("searchsploit_", "").replace("_", " ")
        for line in content.splitlines():
            # Typical searchsploit output: Title | Path
            if "|" in line and not line.startswith("-") and not line.startswith("Exploits"):
                parts = line.split("|")
                if len(parts) >= 2:
                    title = parts[0].strip()
                    path  = parts[1].strip()
                    key   = f"{title}|{path}"
                    if key not in seen and title and len(title) > 3:
                        seen.add(key)
                        results.append({"service": service, "title": title, "path": path})
    return results

def parse_ssl_headers(content):
    security_headers = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "X-XSS-Protection", "Referrer-Policy",
        "Permissions-Policy", "Cache-Control",
        "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
    ]
    present = []
    missing = []
    low = content.lower()
    for h in security_headers:
        if h.lower() in low:
            present.append(h)
        else:
            missing.append(h)
    return {"present": present, "missing": missing}

def parse_emails(content):
    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', content)
    return list(dict.fromkeys(emails))

def parse_dns_record(content):
    records = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith(";") and len(line) > 5:
            records.append(line)
    return records[:20]

def parse_whois(content):
    keys = ["Registrar:", "Creation Date:", "Registry Expiry Date:",
            "Updated Date:", "Name Server:", "Registrant Organization:",
            "Registrant Country:"]
    result = {}
    for line in content.splitlines():
        for k in keys:
            if line.strip().startswith(k):
                val = line.split(":", 1)[1].strip() if ":" in line else ""
                if k not in result:
                    result[k.rstrip(":")] = val
    return result

def parse_nikto(content):
    findings = []
    for line in content.splitlines():
        if line.strip().startswith("+"):
            findings.append(line.strip())
    return findings

def parse_probe_files(folder):
    hits = []
    web_dir = Path(folder) / "web"
    if not web_dir.exists():
        return hits
    for f in sorted(web_dir.glob("probe__*.txt")):
        content = read_file(f)
        path = f.stem.replace("probe__", "/").replace("_", "/")
        if content and ("200" in content or "301" in content or "302" in content):
            m = re.search(r'HTTP/\S+\s+(\d{3})', content)
            status = m.group(1) if m else "2xx/3xx"
            hits.append({"path": path, "status": status, "file": f.name})
    return hits

def detect_cdn_waf(content):
    cdns = ["cloudflare", "akamai", "fastly", "incapsula", "sucuri",
            "imperva", "f5", "barracuda", "aws", "azure"]
    detected = []
    low = content.lower()
    for c in cdns:
        if c in low:
            detected.append(c.title())
    return detected

def parse_timeline(log_content):
    """Extract scan phase timestamps from reconledger.log."""
    events = []
    phase_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})')
    running_pattern = re.compile(r'Running \[(\d+)s\]: (.+)')

    for line in log_content.splitlines():
        ts_m = phase_pattern.search(line)
        run_m = running_pattern.search(line)
        if run_m:
            timeout_s = run_m.group(1)
            desc = run_m.group(2).strip()
            ts = ts_m.group(1) if ts_m else ""
            events.append({"time": ts, "desc": desc, "timeout": timeout_s})
    return events

def generate_executive_summary(target, target_ip, cdn_detected, open_ports,
                                subdomains, nuclei_findings, nikto_out,
                                ssl_headers, probe_hits, is_wp, emails_found,
                                wpscan_findings, hydra_hits, sqlmap_findings,
                                searchsploit_results):
    """Generate a plain-English executive summary paragraph from findings."""

    crit = sum(1 for f in nuclei_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in nuclei_findings if f["severity"] == "HIGH")
    med  = sum(1 for f in nuclei_findings if f["severity"] == "MEDIUM")

    lines = []

    # Target overview
    ip_info = f" (resolved to {target_ip})" if target_ip else ""
    lines.append(
        f"A reconnaissance assessment was conducted against <strong>{target}</strong>{ip_info}."
    )

    # CDN/WAF
    if cdn_detected:
        lines.append(
            f"The target is positioned behind <strong>{', '.join(cdn_detected)}</strong> infrastructure, "
            "which means active port scans reflect edge-node results rather than the origin server. "
            "Origin IP discovery is recommended before drawing conclusions from port scan data."
        )
    else:
        lines.append("No CDN or WAF layer was detected; scan results reflect the origin server directly.")

    # Ports
    if open_ports:
        port_list = ", ".join(p["port"] for p in open_ports[:10])
        lines.append(
            f"<strong>{len(open_ports)}</strong> open TCP port(s) were identified: {port_list}"
            f"{'and more' if len(open_ports) > 10 else ''}."
        )
    else:
        lines.append("No open ports were conclusively identified during this assessment.")

    # Subdomains
    if subdomains:
        lines.append(
            f"Subdomain enumeration yielded <strong>{len(subdomains)}</strong> unique subdomain(s), "
            "expanding the attack surface beyond the primary domain."
        )

    # Vulnerabilities
    if crit or high or med:
        sev_parts = []
        if crit: sev_parts.append(f"<strong style='color:#ff2d2d'>{crit} critical</strong>")
        if high: sev_parts.append(f"<strong style='color:#ff6b00'>{high} high</strong>")
        if med:  sev_parts.append(f"<strong style='color:#ffc107'>{med} medium</strong>")
        lines.append(
            f"Automated vulnerability scanning returned {', '.join(sev_parts)} severity finding(s) "
            "via Nuclei templates. These require prompt triage and remediation."
        )
    elif nuclei_findings:
        lines.append(
            f"Nuclei scanning returned {len(nuclei_findings)} informational finding(s) with no critical or high severity issues detected."
        )
    else:
        lines.append("No findings were returned by automated vulnerability scanning templates.")

    # Security headers
    if ssl_headers["missing"]:
        lines.append(
            f"{len(ssl_headers['missing'])} security header(s) are absent from HTTP responses "
            f"({', '.join(ssl_headers['missing'][:3])}{'...' if len(ssl_headers['missing']) > 3 else ''}), "
            "which may expose users to clickjacking, MIME-sniffing, and related browser-side attacks."
        )

    # Sensitive paths
    if probe_hits:
        lines.append(
            f"{len(probe_hits)} sensitive path(s) returned accessible HTTP responses "
            "(such as admin panels, debug endpoints, or configuration files), warranting immediate review."
        )

    # WordPress
    if is_wp:
        wp_extra = ""
        if wpscan_findings:
            wp_warnings = sum(1 for w in wpscan_findings if w["type"] == "warning")
            if wp_warnings:
                wp_extra = f" WPScan identified {wp_warnings} warning(s) including potentially vulnerable plugins or themes."
        lines.append(
            f"The target runs <strong>WordPress</strong>.{wp_extra} "
            "WordPress installations require active plugin and theme maintenance to avoid known CVE exposure."
        )

    # sqlmap
    if sqlmap_findings:
        lines.append(
            f"SQL injection testing flagged <strong>{len(sqlmap_findings)}</strong> potentially injectable parameter(s). "
            "Manual verification is required to confirm exploitability."
        )

    # hydra
    if hydra_hits:
        lines.append(
            f"Credential testing against SSH returned <strong>{len(hydra_hits)}</strong> successful login(s) "
            "using common passwords. Password hygiene and SSH hardening are strongly recommended."
        )

    # Searchsploit
    if searchsploit_results:
        lines.append(
            f"Cross-referencing detected service versions against the Exploit-DB produced "
            f"<strong>{len(searchsploit_results)}</strong> potential exploit match(es). "
            "These should be evaluated against confirmed service versions before assuming exploitability."
        )

    # Emails
    if emails_found:
        lines.append(
            f"{len(emails_found)} email address(es) were harvested from public-facing sources, "
            "which may be useful for phishing simulations or further OSINT work."
        )

    # Closing
    lines.append(
        "All findings in this report are based on automated tooling and require "
        "manual verification before remediation actions are taken. "
        "This assessment was performed exclusively against authorized targets."
    )

    return " ".join(lines)

def severity_order(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(s, 5)

# ─────────────────────────────────────────────────────────────
#  HTML HELPERS
# ─────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": "#ff2d2d",
    "HIGH":     "#ff6b00",
    "MEDIUM":   "#ffc107",
    "LOW":      "#00e676",
    "INFO":     "#29b6f6",
}

def sev_badge(sev):
    color = SEV_COLOR.get(sev, "#aaa")
    txt_color = "#000" if sev in ("MEDIUM", "LOW") else "#fff"
    return f'<span class="badge" style="background:{color};color:{txt_color}">{sev}</span>'

def status_badge(code):
    color = "#00e676" if code in ("200", "201") else "#ffc107" if code in ("301", "302") else "#aaa"
    return f'<span class="badge" style="background:{color};color:#000">{code}</span>'

def h(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def table(headers, rows, empty_msg="No data found."):
    if not rows:
        return f'<p class="empty">{empty_msg}</p>'
    cols = "".join(f"<th>{hh}</th>" for hh in headers)
    body = ""
    for row in rows:
        cells = "".join(f"<td>{c}</td>" for c in row)
        body += f"<tr>{cells}</tr>"
    return f'<table><thead><tr>{cols}</tr></thead><tbody>{body}</tbody></table>'

def code_block(text, max_lines=60):
    if not text:
        return '<p class="empty">No data.</p>'
    lines = text.splitlines()[:max_lines]
    truncated = len(text.splitlines()) > max_lines
    content = h("\n".join(lines))
    note = f'<p class="empty">... truncated to {max_lines} lines</p>' if truncated else ""
    return f'<pre class="code">{content}</pre>{note}'

def stat_card(label, value, color="#00e5ff"):
    return f'''<div class="stat-card">
      <div class="stat-val" style="color:{color}">{value}</div>
      <div class="stat-label">{label}</div>
    </div>'''

# ─────────────────────────────────────────────────────────────
#  JSON EXPORT DATA BUILDER
# ─────────────────────────────────────────────────────────────

def build_export_data(target, target_ip, cdn_detected, open_ports, nmap_udp,
                      subdomains, nuclei_findings, nikto_out, gobuster_dirs,
                      ffuf_results, probe_hits, ssl_headers, emails_found,
                      whois_parsed, dns_a, dns_mx, dns_ns, dns_txt,
                      searchsploit_results, sqlmap_findings, hydra_hits,
                      wpscan_findings, is_wp, now):
    return {
        "meta": {
            "target": target,
            "ip": target_ip,
            "generated": now,
            "tool": "ReconLedger v1",
        },
        "cdn_waf": cdn_detected,
        "wordpress": is_wp,
        "open_ports_tcp": open_ports,
        "open_ports_udp": nmap_udp,
        "subdomains": subdomains,
        "emails": emails_found,
        "dns": {"a": dns_a, "mx": dns_mx, "ns": dns_ns, "txt": dns_txt},
        "whois": whois_parsed,
        "nuclei_findings": nuclei_findings,
        "nikto_findings": nikto_out,
        "gobuster_dirs": gobuster_dirs,
        "ffuf_results": ffuf_results,
        "sensitive_paths": probe_hits,
        "ssl_headers": ssl_headers,
        "searchsploit": searchsploit_results,
        "sqlmap": sqlmap_findings,
        "hydra": hydra_hits,
        "wpscan": wpscan_findings,
    }

# ─────────────────────────────────────────────────────────────
#  MAIN REPORT BUILDER
# ─────────────────────────────────────────────────────────────

def build_report(folder):
    folder = Path(folder).resolve()
    if not folder.exists():
        print(f"[-] Folder not found: {folder}")
        sys.exit(1)

    folder_name = folder.name
    m = re.match(r'reconledger_(.+?)_\d{8}_\d{6}$', folder_name)
    if not m:
        # Fallback: accept old autorecon folder names too
        m = re.match(r'recon_(.+?)_\d{8}_\d{6}$', folder_name)
    target = m.group(1) if m else folder_name

    print(f"[*] Building report for: {target}")
    print(f"[*] Reading folder:      {folder}")

    def f(rel):  return folder / rel
    def r(rel):  return read_file(f(rel))
    def rl(rel): return read_lines(f(rel))

    # ── DNS ─────────────────────────────────────────────────
    dns_a       = parse_dns_record(r("dns/dig_a.txt"))
    dns_mx      = parse_dns_record(r("dns/dig_mx.txt"))
    dns_ns      = parse_dns_record(r("dns/dig_ns.txt"))
    dns_txt     = parse_dns_record(r("dns/dig_txt.txt"))
    dns_aaaa    = parse_dns_record(r("dns/dig_aaaa.txt"))
    zone_xfr    = r("dns/zone_transfer.txt")
    subdomains  = parse_amass(folder)  # merged subfinder + amass
    dnsrecon    = r("dns/dnsrecon_std.txt")
    dnsenum     = r("dns/dnsenum.txt")
    fierce_out  = r("dns/fierce.txt")
    gobuster_dns = rl("dns/gobuster_dns.txt")

    # ── Network ──────────────────────────────────────────────
    open_ports_raw  = r("network/open_ports.txt")
    open_ports      = parse_nmap_open_ports(r("network/nmap_targeted.txt"))
    nmap_vuln       = r("network/nmap_vuln.txt")
    nmap_udp        = parse_nmap_open_ports(r("network/nmap_udp.txt"))
    target_ip       = r("network/target_ip.txt").strip()
    traceroute      = r("network/traceroute.txt")
    masscan_open    = rl("network/masscan_open.lst")
    cdn_check       = r("network/cdn_check.txt")
    banners = {
        "port 22 (SSH)":  r("network/banner_p22.txt"),
        "port 80 (HTTP)": r("network/banner_p80.txt"),
        "port 443 (HTTPS)": r("network/banner_p443.txt"),
    }

    # ── Web ──────────────────────────────────────────────────
    whatweb         = r("web/whatweb.txt")
    wafw00f         = r("web/wafw00f.txt")
    nikto_out       = parse_nikto(r("web/nikto.txt"))
    gobuster_dirs   = parse_gobuster(r("web/gobuster_dirs.txt"))
    ffuf_results    = parse_ffuf(folder)
    curl_headers    = r("web/curl_headers.txt")
    robots_txt      = r("web/robots.txt")
    sitemap         = r("web/sitemap.xml")
    security_txt    = r("web/security.txt")
    probe_hits      = parse_probe_files(folder)

    # ── SSL ──────────────────────────────────────────────────
    sslscan_out     = r("ssl/sslscan.txt")
    openssl_cert    = r("ssl/openssl_cert.txt")
    header_analysis = r("ssl/header_analysis.txt")
    ssl_headers     = parse_ssl_headers(header_analysis or curl_headers)

    # ── OSINT ────────────────────────────────────────────────
    whois_raw       = r("osint/whois.txt")
    whois_parsed    = parse_whois(whois_raw)
    crtsh           = rl("osint/crtsh.txt")
    harvester_bing  = r("osint/harvester_bing.txt")
    harvester_crtsh = r("osint/harvester_crtsh.txt")
    harvester_baidu = r("osint/harvester_baidu.txt")

    # ── Metadata ─────────────────────────────────────────────
    emails_found    = parse_emails(r("metadata/emails_found.txt"))
    links_found     = rl("metadata/links_found.txt")
    urls_found      = rl("metadata/urls_found.txt")
    exiftool_out    = r("metadata/exiftool_index.txt")

    # ── Vuln ─────────────────────────────────────────────────
    nuclei_raw      = r("vuln/nuclei_findings.txt") or r("vuln/nuclei_all.txt")
    nuclei_findings = parse_nuclei(nuclei_raw)
    nuclei_findings.sort(key=lambda x: severity_order(x["severity"]))
    services_det    = rl("vuln/services_detected.txt")
    sqlmap_findings = parse_sqlmap(folder)
    hydra_hits      = parse_hydra(r("vuln/hydra_ssh.txt"))
    searchsploit_results = parse_searchsploit(folder)

    # ── WordPress ────────────────────────────────────────────
    wp_detect       = r("wordpress/wp_detection.txt")
    is_wp           = "DETECTED" in wp_detect and "NOT DETECTED" not in wp_detect
    wpscan_raw      = r("wordpress/wpscan_full.txt")
    wpscan_findings = parse_wpscan(wpscan_raw)
    wp_version      = r("wordpress/wp_version.txt")
    wp_users        = r("wordpress/wp_users.txt")
    wp_paths        = r("wordpress/wp_sensitive_paths.txt")
    wp_rest         = r("wordpress/wp_rest_api.txt")
    wp_xmlrpc       = r("wordpress/wp_xmlrpc.txt")
    nuclei_wp_raw   = r("wordpress/nuclei_wp_findings.txt")

    # ── Logs ─────────────────────────────────────────────────
    summary_txt     = r("SUMMARY.txt")
    log_content     = r("reconledger.log")
    timeline        = parse_timeline(log_content)

    # ── Derived ──────────────────────────────────────────────
    cdn_detected    = detect_cdn_waf(wafw00f + cdn_check)
    total_files     = sum(1 for _ in folder.rglob("*") if _.is_file())

    crit_count = sum(1 for x in nuclei_findings if x["severity"] == "CRITICAL")
    high_count = sum(1 for x in nuclei_findings if x["severity"] == "HIGH")
    med_count  = sum(1 for x in nuclei_findings if x["severity"] == "MEDIUM")
    low_count  = sum(1 for x in nuclei_findings if x["severity"] == "LOW")
    info_count = sum(1 for x in nuclei_findings if x["severity"] == "INFO")

    print(f"[*] Nuclei findings  : {len(nuclei_findings)}")
    print(f"[*] Open TCP ports   : {len(open_ports)}")
    print(f"[*] Subdomains       : {len(subdomains)}")
    print(f"[*] Emails           : {len(emails_found)}")
    print(f"[*] Searchsploit     : {len(searchsploit_results)}")
    print(f"[*] SQLmap findings  : {len(sqlmap_findings)}")
    print(f"[*] Hydra hits       : {len(hydra_hits)}")
    print(f"[*] WordPress        : {'yes' if is_wp else 'no'}")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    exec_summary = generate_executive_summary(
        target, target_ip, cdn_detected, open_ports,
        subdomains, nuclei_findings, nikto_out,
        ssl_headers, probe_hits, is_wp, emails_found,
        wpscan_findings, hydra_hits, sqlmap_findings,
        searchsploit_results
    )

    export_data = build_export_data(
        target, target_ip, cdn_detected, open_ports, nmap_udp,
        subdomains, nuclei_findings, nikto_out, gobuster_dirs,
        ffuf_results, probe_hits, ssl_headers, emails_found,
        whois_parsed, dns_a, dns_mx, dns_ns, dns_txt,
        searchsploit_results, sqlmap_findings, hydra_hits,
        wpscan_findings, is_wp, now
    )
    export_json = json.dumps(export_data, indent=2)

    # ─────────────────────────────────────────────────────────
    #  HTML OUTPUT
    # ─────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconLedger Report — {h(target)}</title>
<style>
  /* ── BASE ── */
  :root {{
    --bg:      #0a0a0f;
    --bg2:     #10101a;
    --bg3:     #161625;
    --border:  #1e1e35;
    --accent:  #00e5ff;
    --accent2: #7c4dff;
    --text:    #c9d1d9;
    --muted:   #555577;
    --crit:    #ff2d2d;
    --high:    #ff6b00;
    --med:     #ffc107;
    --low:     #00e676;
    --info:    #29b6f6;
    --font:    'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); font-size: 13px; line-height: 1.6; }}

  /* ── HEADER ── */
  .header {{
    background: linear-gradient(135deg, #0d0d1a 0%, #12122a 50%, #0d0d1a 100%);
    border-bottom: 2px solid var(--accent);
    padding: 30px 40px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(0,229,255,0.03) 40px),
                repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(0,229,255,0.03) 40px);
  }}
  .header-inner {{ position: relative; z-index: 1; }}
  .header h1 {{ font-size: 24px; color: var(--accent); letter-spacing: 3px; text-transform: uppercase; }}
  .header h1 span {{ color: #fff; }}
  .header-meta {{ margin-top: 10px; color: var(--muted); font-size: 12px; }}
  .header-meta strong {{ color: var(--text); }}
  .header-actions {{ margin-top: 14px; display: flex; gap: 10px; flex-wrap: wrap; }}
  .btn {{
    padding: 7px 16px; border: 1px solid var(--accent); background: transparent;
    color: var(--accent); cursor: pointer; font-family: var(--font); font-size: 11px;
    letter-spacing: 1px; border-radius: 3px; transition: all 0.2s;
  }}
  .btn:hover {{ background: var(--accent); color: #000; }}
  .btn-json {{ border-color: var(--accent2); color: var(--accent2); }}
  .btn-json:hover {{ background: var(--accent2); color: #fff; }}

  /* ── NAV ── */
  .nav {{
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 10px 40px;
    display: flex; gap: 6px; flex-wrap: wrap;
    position: sticky; top: 0; z-index: 100;
  }}
  .nav a {{
    color: var(--muted); text-decoration: none; padding: 4px 10px;
    border: 1px solid var(--border); border-radius: 3px; font-size: 11px;
    transition: all 0.2s;
  }}
  .nav a:hover {{ color: var(--accent); border-color: var(--accent); background: rgba(0,229,255,0.05); }}

  /* ── MAIN ── */
  .main {{ max-width: 1400px; margin: 0 auto; padding: 30px 40px; }}

  /* ── SECTIONS ── */
  .section {{ margin-bottom: 40px; }}
  .section-title {{
    font-size: 12px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--accent); border-left: 3px solid var(--accent);
    padding: 8px 14px; background: rgba(0,229,255,0.05);
    margin-bottom: 16px; display: flex; align-items: center; gap: 8px;
  }}

  /* ── EXECUTIVE SUMMARY ── */
  .exec-summary {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent);
    border-radius: 6px;
    padding: 20px 24px;
    line-height: 1.9;
    font-size: 13px;
    color: var(--text);
    margin-bottom: 16px;
  }}

  /* ── STAT CARDS ── */
  .stat-grid {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
  .stat-card {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 6px; padding: 16px 20px; min-width: 110px;
    text-align: center; flex: 1;
  }}
  .stat-val {{ font-size: 26px; font-weight: bold; }}
  .stat-label {{ color: var(--muted); font-size: 10px; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}

  /* ── TABLES ── */
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 12px; }}
  th {{ background: var(--bg3); color: var(--accent); padding: 8px 12px; text-align: left; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; border-bottom: 1px solid var(--border); }}
  td {{ padding: 7px 12px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
  tr:hover td {{ background: var(--bg3); }}

  /* ── BADGES ── */
  .badge {{ padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; display: inline-block; }}

  /* ── CODE ── */
  .code {{
    background: var(--bg2); border: 1px solid var(--border);
    border-radius: 4px; padding: 14px; overflow-x: auto;
    white-space: pre; font-size: 11px; color: #a0c0a0;
    max-height: 400px; overflow-y: auto;
  }}

  /* ── GRID ── */
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; }}
  @media (max-width: 900px) {{ .grid-2, .grid-3 {{ grid-template-columns: 1fr; }} }}

  /* ── CARDS ── */
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 12px; }}
  .card-title {{ color: var(--accent2); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }}

  /* ── TIMELINE ── */
  .timeline {{ position: relative; padding-left: 20px; }}
  .timeline::before {{ content: ''; position: absolute; left: 6px; top: 0; bottom: 0; width: 1px; background: var(--border); }}
  .tl-item {{ position: relative; margin-bottom: 10px; }}
  .tl-item::before {{
    content: '';
    position: absolute; left: -17px; top: 5px;
    width: 7px; height: 7px;
    border-radius: 50%; background: var(--accent);
  }}
  .tl-time {{ color: var(--muted); font-size: 10px; }}
  .tl-desc {{ color: var(--text); font-size: 12px; }}
  .tl-timeout {{ color: var(--muted); font-size: 10px; }}

  /* ── SEVERITY ROWS ── */
  .sev-CRITICAL td:first-child {{ border-left: 3px solid var(--crit); }}
  .sev-HIGH     td:first-child {{ border-left: 3px solid var(--high); }}
  .sev-MEDIUM   td:first-child {{ border-left: 3px solid var(--med); }}
  .sev-LOW      td:first-child {{ border-left: 3px solid var(--low); }}
  .sev-INFO     td:first-child {{ border-left: 3px solid var(--info); }}

  /* ── MISC ── */
  .empty {{ color: var(--muted); font-style: italic; padding: 10px; }}
  .chip {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 11px; margin: 2px; }}
  .hit {{ color: var(--low); }}
  .warn {{ color: var(--high); }}
  .missing {{ color: var(--crit); }}
  .present {{ color: var(--low); }}
  .info-text {{ color: var(--info); }}
  hr {{ border: none; border-top: 1px solid var(--border); margin: 24px 0; }}
  .footer {{ text-align: center; color: var(--muted); font-size: 11px; padding: 30px; border-top: 1px solid var(--border); margin-top: 40px; }}
  .scrolltop {{ position: fixed; bottom: 20px; right: 20px; background: var(--accent); color: #000; border: none; padding: 8px 12px; cursor: pointer; border-radius: 4px; font-family: var(--font); font-weight: bold; font-size: 12px; }}

  /* ── PRINT / PDF STYLES ── */
  @media print {{
    body {{ background: #fff; color: #000; font-size: 11px; }}
    .nav, .scrolltop, .header-actions, .btn {{ display: none !important; }}
    .header {{ background: #fff; border-bottom: 2px solid #000; padding: 20px; }}
    .header h1, .header-meta strong {{ color: #000; }}
    .header-meta {{ color: #333; }}
    .header::before {{ display: none; }}
    .section-title {{ color: #000; background: #f0f0f0; border-left-color: #000; }}
    .main {{ max-width: 100%; padding: 10px 20px; }}
    .stat-card {{ border: 1px solid #ccc; }}
    .stat-val {{ color: #000 !important; }}
    .code {{ background: #f8f8f8; color: #333; border: 1px solid #ccc; max-height: none; }}
    table {{ border: 1px solid #ccc; }}
    th {{ background: #eee; color: #000; }}
    td {{ border-bottom: 1px solid #ddd; }}
    .card {{ border: 1px solid #ccc; background: #fff; }}
    .exec-summary {{ background: #f9f9f9; border: 1px solid #ccc; }}
    .section {{ page-break-inside: avoid; }}
    a {{ color: #000; text-decoration: none; }}
    .badge {{ border: 1px solid #999; }}
    .present {{ color: #006600; }}
    .missing {{ color: #cc0000; }}
    .footer {{ color: #666; border-top: 1px solid #ccc; }}
  }}
</style>
</head>
<body>

<!-- HEADER -->
<div class="header">
  <div class="header-inner">
    <h1>ReconLedger <span>Report</span></h1>
    <div class="header-meta">
      <strong>Target:</strong> {h(target)} &nbsp;|&nbsp;
      <strong>IP:</strong> {h(target_ip) or "unknown"} &nbsp;|&nbsp;
      <strong>Generated:</strong> {now} &nbsp;|&nbsp;
      <strong>Files Read:</strong> {total_files} &nbsp;|&nbsp;
      <strong>CDN/WAF:</strong> {", ".join(cdn_detected) if cdn_detected else "None detected"}
      {"&nbsp;|&nbsp;<strong style='color:var(--low)'>WordPress: DETECTED</strong>" if is_wp else ""}
    </div>
    <div class="header-actions">
      <button class="btn" onclick="window.print()">Print / Save as PDF</button>
      <button class="btn btn-json" onclick="downloadJSON()">Export JSON</button>
    </div>
  </div>
</div>

<!-- NAV -->
<nav class="nav">
  <a href="#executive">Executive Summary</a>
  <a href="#overview">Overview</a>
  <a href="#vulns">Vulnerabilities</a>
  <a href="#ports">Ports</a>
  <a href="#web">Web</a>
  <a href="#dns">DNS</a>
  <a href="#ssl">SSL/TLS</a>
  <a href="#osint">OSINT</a>
  <a href="#metadata">Metadata</a>
  <a href="#exploit">Exploits</a>
  {"<a href='#wordpress'>WordPress</a>" if is_wp else ""}
  <a href="#nikto">Nikto</a>
  <a href="#timeline">Timeline</a>
  <a href="#logs">Logs</a>
</nav>

<div class="main">

<!-- EXECUTIVE SUMMARY -->
<div class="section" id="executive">
  <div class="section-title">Executive Summary</div>
  <div class="exec-summary">{exec_summary}</div>
</div>

<!-- OVERVIEW -->
<div class="section" id="overview">
  <div class="section-title">Overview</div>
  <div class="stat-grid">
    {stat_card("Critical", crit_count, "#ff2d2d")}
    {stat_card("High", high_count, "#ff6b00")}
    {stat_card("Medium", med_count, "#ffc107")}
    {stat_card("Low", low_count, "#00e676")}
    {stat_card("Info", info_count, "#29b6f6")}
    {stat_card("Total Findings", len(nuclei_findings), "#00e5ff")}
    {stat_card("Open TCP Ports", len(open_ports), "#7c4dff")}
    {stat_card("Subdomains", len(subdomains), "#e040fb")}
    {stat_card("Emails", len(emails_found), "#ff80ab")}
    {stat_card("Nikto Hits", len(nikto_out), "#69f0ae")}
    {stat_card("Dirs Found", len(gobuster_dirs) + len(ffuf_results), "#40c4ff")}
    {stat_card("Sensitive Paths", len(probe_hits), "#ff6d00")}
    {stat_card("Exploit Matches", len(searchsploit_results), "#ff5252")}
    {stat_card("SQLmap Flags", len(sqlmap_findings), "#ff7043")}
  </div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">Target Information</div>
      <table>
        <tr><td>Domain</td><td><strong>{h(target)}</strong></td></tr>
        <tr><td>IP Address</td><td>{h(target_ip) or "N/A"}</td></tr>
        <tr><td>CDN / WAF</td><td>{", ".join(cdn_detected) if cdn_detected else "None detected"}</td></tr>
        <tr><td>WordPress</td><td>{"<span class='hit'>DETECTED</span>" if is_wp else "Not detected"}</td></tr>
        <tr><td>Scan Folder</td><td style="word-break:break-all">{h(str(folder))}</td></tr>
        <tr><td>Report Generated</td><td>{now}</td></tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">WHOIS Summary</div>
      {"".join(f"<div><span style='color:var(--muted)'>{h(k)}:</span> {h(v)}</div>" for k,v in whois_parsed.items()) or '<p class="empty">No WHOIS data.</p>'}
    </div>
  </div>
</div>

<!-- VULNERABILITY FINDINGS -->
<div class="section" id="vulns">
  <div class="section-title">Vulnerability Findings — Nuclei ({len(nuclei_findings)} total)</div>
"""

    if nuclei_findings:
        html += '<table><thead><tr><th>#</th><th>Severity</th><th>Template</th><th>URL / Detail</th></tr></thead><tbody>'
        for i, finding in enumerate(nuclei_findings, 1):
            sev = finding["severity"]
            html += f'<tr class="sev-{sev}"><td>{i}</td><td>{sev_badge(sev)}</td><td>{h(finding["template"])}</td><td>{h(finding["url"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No nuclei findings detected.</p>'

    html += f"""
  <div style="margin-top:14px">
    <div class="card-title">Raw Nuclei Output</div>
    {code_block(nuclei_raw, 80)}
  </div>
</div>

<!-- OPEN PORTS & SERVICES -->
<div class="section" id="ports">
  <div class="section-title">Open Ports & Services</div>
  <div class="grid-2">
    <div>
      <div class="card-title">TCP Ports (nmap targeted)</div>
"""

    if open_ports:
        html += '<table><thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>'
        for p in open_ports:
            html += f'<tr><td><span class="hit">{h(p["port"])}</span></td><td>{h(p["service"])}</td><td>{h(p["version"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += code_block(open_ports_raw, 40)

    html += f"""
    </div>
    <div>
      <div class="card-title">UDP Ports (nmap udp)</div>
"""

    if nmap_udp:
        html += '<table><thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>'
        for p in nmap_udp:
            html += f'<tr><td><span class="info-text">{h(p["port"])}</span></td><td>{h(p["service"])}</td><td>{h(p["version"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No UDP ports detected.</p>'

    html += f"""
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">Masscan Raw Output</div>
  {"".join(f'<span class="chip" style="background:var(--bg3);border:1px solid var(--border)">{h(p)}</span>' for p in masscan_open) or '<p class="empty">No masscan data.</p>'}

  <div class="card-title" style="margin-top:14px">Nmap Vuln Scripts</div>
  {code_block(nmap_vuln, 60)}

  <div class="card-title" style="margin-top:14px">Service Banners</div>
  <div class="grid-3">
"""

    for port_label, banner_content in banners.items():
        html += f'<div><div class="card-title">{h(port_label)}</div>{code_block(banner_content, 15)}</div>'

    html += f"""
  </div>

  <div class="card-title" style="margin-top:14px">Traceroute</div>
  {code_block(traceroute, 30)}
</div>

<!-- WEB RECON -->
<div class="section" id="web">
  <div class="section-title">Web Recon</div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">WhatWeb Fingerprint</div>
      {code_block(whatweb, 20)}
    </div>
    <div class="card">
      <div class="card-title">WAF / CDN Detection (wafw00f)</div>
      {code_block(wafw00f, 20)}
    </div>
  </div>

  <div class="card-title">Directory Brute Force — gobuster ({len(gobuster_dirs)} results)</div>
"""

    if gobuster_dirs:
        html += '<table><thead><tr><th>#</th><th>Path / URL</th><th>Status</th></tr></thead><tbody>'
        for i, d in enumerate(gobuster_dirs, 1):
            html += f'<tr><td>{i}</td><td>{h(d["url"])}</td><td>{status_badge(d["status"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No directories found or gobuster output empty.</p>'

    html += f"""
  <div class="card-title" style="margin-top:14px">Directory Fuzzing — ffuf ({len(ffuf_results)} results)</div>
"""

    if ffuf_results:
        html += '<table><thead><tr><th>#</th><th>URL</th><th>Status</th><th>Length</th></tr></thead><tbody>'
        for i, d in enumerate(ffuf_results, 1):
            html += f'<tr><td>{i}</td><td>{h(d["url"])}</td><td>{status_badge(d["status"])}</td><td>{h(d["length"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No ffuf results found or ffuf not run.</p>'

    html += f"""
  <div class="card-title" style="margin-top:14px">Sensitive Path Probes (HTTP 2xx/3xx hits)</div>
"""

    if probe_hits:
        html += '<table><thead><tr><th>Path</th><th>Status</th></tr></thead><tbody>'
        for p in probe_hits:
            html += f'<tr><td class="warn">{h(p["path"])}</td><td>{status_badge(p["status"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No sensitive paths returned 2xx/3xx responses.</p>'

    html += f"""
  <div class="grid-2" style="margin-top:14px">
    <div>
      <div class="card-title">robots.txt</div>
      {code_block(robots_txt, 30)}
    </div>
    <div>
      <div class="card-title">security.txt</div>
      {code_block(security_txt, 20)}
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">HTTP Response Headers</div>
  {code_block(curl_headers, 40)}
</div>

<!-- DNS ENUMERATION -->
<div class="section" id="dns">
  <div class="section-title">DNS Enumeration</div>

  <div class="grid-3">
    <div class="card">
      <div class="card-title">A Records</div>
      {"".join(f'<div class="hit">{h(r)}</div>' for r in dns_a) or '<p class="empty">None</p>'}
    </div>
    <div class="card">
      <div class="card-title">MX Records</div>
      {"".join(f'<div>{h(r)}</div>' for r in dns_mx) or '<p class="empty">None</p>'}
    </div>
    <div class="card">
      <div class="card-title">NS Records</div>
      {"".join(f'<div>{h(r)}</div>' for r in dns_ns) or '<p class="empty">None</p>'}
    </div>
    <div class="card">
      <div class="card-title">TXT Records</div>
      {"".join(f'<div style="word-break:break-all">{h(r)}</div>' for r in dns_txt) or '<p class="empty">None</p>'}
    </div>
    <div class="card">
      <div class="card-title">AAAA Records</div>
      {"".join(f'<div>{h(r)}</div>' for r in dns_aaaa) or '<p class="empty">None</p>'}
    </div>
    <div class="card">
      <div class="card-title">Zone Transfer (AXFR)</div>
      {code_block(zone_xfr, 15)}
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">Subdomains — Combined (subfinder + amass + gobuster): {len(subdomains)}</div>
  <div style="max-height:200px;overflow-y:auto;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:12px">
    {"".join(f'<span class="chip" style="background:var(--bg3);border:1px solid var(--border);color:var(--low)">{h(s)}</span>' for s in subdomains) or '<p class="empty">No subdomains found.</p>'}
  </div>

  <div class="grid-2" style="margin-top:14px">
    <div>
      <div class="card-title">DNSRecon</div>
      {code_block(dnsrecon, 40)}
    </div>
    <div>
      <div class="card-title">Fierce</div>
      {code_block(fierce_out, 40)}
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">DNSEnum</div>
  {code_block(dnsenum, 50)}
</div>

<!-- SSL / TLS -->
<div class="section" id="ssl">
  <div class="section-title">SSL / TLS Analysis</div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">Security Headers — Present</div>
      {"".join(f'<div class="present">+ {h(hh)}</div>' for hh in ssl_headers["present"]) or '<p class="empty">None found</p>'}
      <div class="card-title" style="margin-top:12px">Security Headers — Missing</div>
      {"".join(f'<div class="missing">- {h(hh)}</div>' for hh in ssl_headers["missing"]) or '<p class="empty">All present.</p>'}
    </div>
    <div class="card">
      <div class="card-title">Certificate Info (openssl)</div>
      {code_block(openssl_cert, 30)}
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">SSLScan Output</div>
  {code_block(sslscan_out, 80)}
</div>

<!-- OSINT -->
<div class="section" id="osint">
  <div class="section-title">OSINT</div>

  <div class="grid-2">
    <div class="card">
      <div class="card-title">WHOIS (Full)</div>
      {code_block(whois_raw, 50)}
    </div>
    <div class="card">
      <div class="card-title">crt.sh Certificate Transparency ({len(crtsh)} entries)</div>
      <div style="max-height:200px;overflow-y:auto">
        {"".join(f'<div style="color:var(--info)">{h(c)}</div>' for c in crtsh[:50]) or '<p class="empty">No crt.sh data.</p>'}
      </div>
    </div>
  </div>

  <div class="grid-2" style="margin-top:14px">
    <div>
      <div class="card-title">theHarvester — Bing</div>
      {code_block(harvester_bing, 30)}
    </div>
    <div>
      <div class="card-title">theHarvester — crt.sh / Certspotter</div>
      {code_block(harvester_crtsh, 30)}
    </div>
  </div>
</div>

<!-- METADATA -->
<div class="section" id="metadata">
  <div class="section-title">Metadata & Extraction</div>

  <div class="card-title">Emails Found ({len(emails_found)})</div>
  <div style="margin-bottom:14px">
    {"".join(f'<span class="chip" style="background:var(--bg3);border:1px solid #ff80ab;color:#ff80ab">{h(e)}</span>' for e in emails_found) or '<p class="empty">No emails found.</p>'}
  </div>

  <div class="grid-2">
    <div>
      <div class="card-title">Links Found ({len(links_found)})</div>
      <div style="max-height:200px;overflow-y:auto;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:10px">
        {"".join(f'<div style="word-break:break-all;color:var(--accent)">{h(l)}</div>' for l in links_found[:60]) or '<p class="empty">None</p>'}
      </div>
    </div>
    <div>
      <div class="card-title">URLs Found ({len(urls_found)})</div>
      <div style="max-height:200px;overflow-y:auto;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:10px">
        {"".join(f'<div style="word-break:break-all">{h(u)}</div>' for u in urls_found[:60]) or '<p class="empty">None</p>'}
      </div>
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">Exiftool Metadata</div>
  {code_block(exiftool_out, 50)}
</div>

<!-- EXPLOIT MATCHING -->
<div class="section" id="exploit">
  <div class="section-title">Exploit Matching & Credential Testing</div>

  <div class="card-title">Searchsploit Matches ({len(searchsploit_results)} unique findings across detected services)</div>
"""

    if searchsploit_results:
        html += '<table><thead><tr><th>#</th><th>Service</th><th>Exploit Title</th><th>Path</th></tr></thead><tbody>'
        for i, r in enumerate(searchsploit_results, 1):
            html += f'<tr><td>{i}</td><td><span class="info-text">{h(r["service"])}</span></td><td class="warn">{h(r["title"])}</td><td style="color:var(--muted)">{h(r["path"])}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No searchsploit matches found, or no nmap XML to parse service versions from.</p>'

    html += f"""
  <div class="card-title" style="margin-top:20px">SQLmap — Injection Testing ({len(sqlmap_findings)} flag(s))</div>
"""

    if sqlmap_findings:
        html += '<table><thead><tr><th>#</th><th>Finding</th></tr></thead><tbody>'
        for i, line in enumerate(sqlmap_findings, 1):
            html += f'<tr><td>{i}</td><td class="warn">{h(line)}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No SQL injection parameters flagged by sqlmap.</p>'

    html += f"""
  <div class="card-title" style="margin-top:20px">Hydra — Credential Testing ({len(hydra_hits)} successful login(s))</div>
"""

    if hydra_hits:
        html += '<table><thead><tr><th>#</th><th>Result</th></tr></thead><tbody>'
        for i, line in enumerate(hydra_hits, 1):
            html += f'<tr><td>{i}</td><td style="color:var(--crit);font-weight:bold">{h(line)}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No successful credential attempts recorded.</p>'

    html += "</div>"

    # ── WORDPRESS ──────────────────────────────────────────────
    if is_wp or wpscan_findings:
        html += f"""
<div class="section" id="wordpress">
  <div class="section-title">WordPress Recon</div>

  <div class="grid-2">
    <div class="card" style="border-color:var(--accent2)">
      <div class="card-title">WP Detection</div>
      {code_block(wp_detect, 10)}
    </div>
    <div class="card">
      <div class="card-title">WP Version Detection</div>
      {code_block(wp_version, 20)}
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">WPScan Findings ({len(wpscan_findings)})</div>
"""

        if wpscan_findings:
            html += '<table><thead><tr><th>#</th><th>Type</th><th>Detail</th></tr></thead><tbody>'
            for i, wf in enumerate(wpscan_findings, 1):
                badge_color = "#ff6b00" if wf["type"] == "warning" else "#29b6f6"
                html += f'<tr><td>{i}</td><td><span class="badge" style="background:{badge_color};color:#fff">{h(wf["type"].upper())}</span></td><td>{h(wf["detail"])}</td></tr>'
            html += '</tbody></table>'
        else:
            html += '<p class="empty">No WPScan findings parsed.</p>'

        html += f"""
  <div class="grid-2" style="margin-top:14px">
    <div>
      <div class="card-title">WP Users</div>
      {code_block(wp_users, 30)}
    </div>
    <div>
      <div class="card-title">WP Sensitive Paths</div>
      {code_block(wp_paths, 30)}
    </div>
  </div>

  <div class="card-title" style="margin-top:14px">REST API Enumeration</div>
  {code_block(wp_rest, 40)}

  <div class="card-title" style="margin-top:14px">XML-RPC Analysis</div>
  {code_block(wp_xmlrpc, 20)}

  <div class="card-title" style="margin-top:14px">Nuclei WordPress Templates</div>
  {code_block(nuclei_wp_raw, 40)}
</div>
"""

    # ── NIKTO ──────────────────────────────────────────────────
    html += f"""
<div class="section" id="nikto">
  <div class="section-title">Nikto Web Scanner ({len(nikto_out)} findings)</div>
"""

    if nikto_out:
        html += '<table><thead><tr><th>#</th><th>Finding</th></tr></thead><tbody>'
        for i, n in enumerate(nikto_out, 1):
            html += f'<tr><td>{i}</td><td style="color:var(--med)">{h(n)}</td></tr>'
        html += '</tbody></table>'
    else:
        html += '<p class="empty">No Nikto findings or nikto.txt is empty.</p>'

    html += "</div>"

    # ── TIMELINE ───────────────────────────────────────────────
    html += f"""
<div class="section" id="timeline">
  <div class="section-title">Scan Timeline</div>
  <div class="card">
"""

    if timeline:
        html += '<div class="timeline">'
        for event in timeline[:150]:
            html += f"""<div class="tl-item">
  <div class="tl-time">{h(event["time"])}</div>
  <div class="tl-desc">{h(event["desc"])}</div>
  <div class="tl-timeout">timeout: {h(event["timeout"])}s</div>
</div>"""
        html += '</div>'
    else:
        html += '<p class="empty">No timeline data found in reconledger.log.</p>'

    html += f"""
  </div>
</div>

<!-- LOGS -->
<div class="section" id="logs">
  <div class="section-title">Raw Logs & Summary</div>

  <div class="card-title">SUMMARY.txt</div>
  {code_block(summary_txt, 100)}

  <div class="card-title" style="margin-top:14px">reconledger.log (last 100 lines)</div>
  {code_block(chr(10).join(log_content.splitlines()[-100:]) if log_content else "", 100)}
</div>

</div><!-- /main -->

<div class="footer">
  ReconLedger v1 Report &nbsp;|&nbsp; Target: {h(target)} &nbsp;|&nbsp; {now}<br>
  <span style="color:#333">For authorized use only. Unauthorized scanning is illegal.</span>
</div>

<button class="scrolltop" onclick="window.scrollTo({{top:0,behavior:'smooth'}})">TOP</button>

<script>
const _exportData = {export_json};

function downloadJSON() {{
  const blob = new Blob([JSON.stringify(_exportData, null, 2)], {{type: 'application/json'}});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'reconledger_{h(target)}_' + new Date().toISOString().slice(0,10) + '.json';
  a.click();
  URL.revokeObjectURL(a.href);
}}
</script>
</body>
</html>"""

    return html

# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:   python3 reconledger_report.py <scan_folder>")
        print("Example: python3 reconledger_report.py ~/Documents/reconledger_example.com_20260101_120000")
        sys.exit(1)

    folder = sys.argv[1]
    html   = build_report(folder)

    folder_path = Path(folder).resolve()
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = folder_path / f"REPORT_{ts}.html"

    with open(outfile, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"\n[+] Report saved : {outfile}")
    print(f"[*] Open with    : firefox '{outfile}'")
