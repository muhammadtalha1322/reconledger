#!/usr/bin/env bash
# =============================================================================
#   reconledger - Automated Reconnaissance Script
#   Author  : muhammadtalha1322 (GitHub)
#   Version : 1.0
#   Usage   : sudo bash reconledger.sh [options] <target>
#   Options : --quick   (fast scan)
#             --full    (default - comprehensive)
#             --stealth (slow & low noise)
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────
#  COLORS
# ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BLUE='\033[0;34m'; NC='\033[0m'
BOLD='\033[1m'

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════════╗"
  echo "  ║               reconledger  v1.0                              ║"
  echo "  ║     Professional Automated Reconnaissance Framework          ║"
  echo "  ╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

# ─────────────────────────────────────────────────────────────
#  ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────
MODE="full"
RAW_TARGET=""

usage() {
  echo -e "${BOLD}Usage:${NC} sudo bash $0 [--quick|--full|--stealth] <target>"
  echo "  --quick    : Fast scan (top 1000 ports, limited vuln checks)"
  echo "  --full     : Full comprehensive scan (recommended)"
  echo "  --stealth  : Low noise, slow timing"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)   MODE="quick"; shift ;;
    --full)    MODE="full"; shift ;;
    --stealth) MODE="stealth"; shift ;;
    --help|-h) usage ;;
    -*) echo -e "${RED}Unknown option: $1${NC}"; usage ;;
    *)  RAW_TARGET="$1"; shift ;;
  esac
done

[[ -z "${RAW_TARGET}" ]] && usage

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[!] Please run as root (sudo).${NC}"; exit 1
fi

# Normalize target
TARGET="${RAW_TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%%/*}"
TARGET="${TARGET%.}"

if ! [[ "${TARGET}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo -e "${RED}[!] Invalid target.${NC}"; exit 1
fi

# Timing settings
case "${MODE}" in
  quick)   NMAP_TIMING="-T4"; MASSCAN_RATE=2000; NMAP_TIMEOUT=180 ;;
  stealth) NMAP_TIMING="-T2"; MASSCAN_RATE=200;  NMAP_TIMEOUT=600 ;;
  *)       NMAP_TIMING="-T4"; MASSCAN_RATE=1000; NMAP_TIMEOUT=300 ;;
esac

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="$HOME/Documents/reconledger_${TARGET}_${TIMESTAMP}"
LOGFILE="${OUTDIR}/reconledger.log"
SUMMARY="${OUTDIR}/SUMMARY.txt"
OPEN_PORTS_FILE="${OUTDIR}/network/open_ports.txt"

mkdir -p "${OUTDIR}"/{dns,network,web,ssl,osint,metadata,vuln,raw,wordpress}

# ─────────────────────────────────────────────────────────────
#  LOGGING FUNCTIONS
# ─────────────────────────────────────────────────────────────
log()     { echo -e "${GREEN}[+]${NC} $*" | tee -a "${LOGFILE}"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "${LOGFILE}"; }
err()     { echo -e "${RED}[-]${NC} $*" | tee -a "${LOGFILE}"; }
section() { echo -e "\n${BLUE}${BOLD}━━━ $* ━━━${NC}" | tee -a "${LOGFILE}"; }

run_cmd() {
  local desc="$1"
  local outfile="$2"
  local timeout_sec="${3:-180}"
  shift 3
  log "Running [${timeout_sec}s]: ${desc}"
  if timeout "${timeout_sec}" "$@" > "${outfile}" 2>>"${LOGFILE}"; then
    log "Completed: ${desc}"
  else
    local code=$?
    [[ $code -eq 124 ]] && err "TIMEOUT: ${desc}" || err "Failed: ${desc}"
  fi
}

# ─────────────────────────────────────────────────────────────
#  MAIN PHASES (Ordered by Standard Recon Methodology)
# ─────────────────────────────────────────────────────────────

main() {
  banner
  log "Target     : ${TARGET}"
  log "Mode       : ${MODE}"
  log "Output     : ${OUTDIR}"
  log "Started    : $(date)"

  # Phase 1: Tool Check
  section "Phase 1 — Tool Check & Setup"
  # (Tool installation logic can be added here if needed)

  # Phase 2: Target Resolution & CDN Check
  section "Phase 2 — Target Resolution & CDN/WAF Detection"
  TARGET_IP=$(dig +short A "${TARGET}" | head -n1)
  echo "${TARGET_IP:-unknown}" > "${OUTDIR}/network/target_ip.txt"
  run_cmd "CDN Check" "${OUTDIR}/network/cdn_check.txt" 15 \
    curl -sI --max-time 10 "https://${TARGET}"

  # Phase 3: Passive OSINT
  section "Phase 3 — Passive OSINT"
  run_cmd "WHOIS" "${OUTDIR}/osint/whois.txt" 60 whois "${TARGET}"
  run_cmd "crt.sh" "${OUTDIR}/osint/crtsh.txt" 30 curl -s "https://crt.sh/?q=%25.${TARGET}&output=json"

  # Phase 4: DNS Enumeration
  section "Phase 4 — DNS Enumeration"
  run_cmd "Subfinder" "${OUTDIR}/dns/subfinder.txt" 120 subfinder -d "${TARGET}" -o "${OUTDIR}/dns/subfinder_list.txt"
  run_cmd "DNSRecon" "${OUTDIR}/dns/dnsrecon_std.txt" 300 dnsrecon -d "${TARGET}" -t std

  # Phase 5: Port Scanning
  section "Phase 5 — Port Scanning"
  run_cmd "Masscan" "${OUTDIR}/network/masscan_all.txt" 300 \
    masscan -p1-65535 "${TARGET_IP}" --rate="${MASSCAN_RATE}" -oG "${OUTDIR}/network/masscan_all.txt"

  # Phase 6: Service Enumeration (nmap)
  section "Phase 6 — Service Enumeration"
  run_cmd "Nmap Targeted" "${OUTDIR}/network/nmap_targeted.txt" "${NMAP_TIMEOUT}" \
    nmap -sV -sC -O --open ${NMAP_TIMING} "${TARGET}" -oA "${OUTDIR}/network/nmap_targeted"

  # Phase 7: Web Recon
  section "Phase 7 — Web Application Recon"
  run_cmd "WhatWeb" "${OUTDIR}/web/whatweb.txt" 60 whatweb -a 3 "https://${TARGET}"
  run_cmd "Wafw00f" "${OUTDIR}/web/wafw00f.txt" 60 wafw00f "https://${TARGET}"
  run_cmd "Gobuster" "${OUTDIR}/web/gobuster_dirs.txt" 600 \
    gobuster dir -u "https://${TARGET}" -w /usr/share/wordlists/dirb/common.txt -t 30 --timeout 10s

  # Phase 8: SSL/TLS Analysis
  section "Phase 8 — SSL/TLS Analysis"
  run_cmd "SSLScan" "${OUTDIR}/ssl/sslscan.txt" 120 sslscan --no-colour "${TARGET}:443"

  # Phase 9: WordPress Recon
  section "Phase 9 — WordPress Detection & Scanning"
  if command -v wpscan &>/dev/null; then
    log "Updating WPScan database..."
    wpscan --update --no-banner > /dev/null 2>&1 || true
    run_cmd "WPScan" "${OUTDIR}/wordpress/wpscan.txt" 900 \
      wpscan --url "https://${TARGET}" --enumerate u,vp,vt,tt,cb,dbe \
        --plugins-detection mixed --themes-detection passive \
        --random-user-agent --no-banner --output "${OUTDIR}/wordpress/wpscan.txt"
  fi

  # Phase 10: Vulnerability Scanning
  section "Phase 10 — Vulnerability Scanning"
  run_cmd "Nuclei" "${OUTDIR}/vuln/nuclei_findings.txt" 900 \
    nuclei -u "https://${TARGET}" -severity low,medium,high,critical -silent

  # Generate Summary
  section "Final Summary"
  {
    echo "reconledger Scan Summary"
    echo "Target     : ${TARGET}"
    echo "Date       : $(date)"
    echo "Mode       : ${MODE}"
    echo "Output     : ${OUTDIR}"
  } > "${SUMMARY}"

  log "Scan completed successfully."

  # Ask for Report Generation
  echo ""
  read -p "Generate HTML Report now? [y/N]: " -r generate
  if [[ "$generate" =~ ^[Yy]$ ]]; then
    REPORT_SCRIPT="$(dirname "$0")/reconledger_report.py"
    if [[ -f "${REPORT_SCRIPT}" ]]; then
      python3 "${REPORT_SCRIPT}" "${OUTDIR}"
    else
      echo "Report generator not found. Please run it manually."
    fi
  fi

  echo -e "\n${GREEN}${BOLD}reconledger completed.${NC}"
  echo -e "Results saved in: ${OUTDIR}"
}

main "$@"
