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
CYAN='\033[0;36m'; BLUE='\033[0;34m'; MAGENTA='\033[0;35m'
BOLD='\033[1m'; NC='\033[0m'
 
banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════════╗"
  echo "  ║         R E C O N L E D G E R  v2                            ║"
  echo "  ║   Ordered Recon Pipeline  |  WordPress  |  Parallel          ║"
  echo "  ╚══════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}
 
# ─────────────────────────────────────────────────────────────
#  ARGUMENT PARSING & INPUT VALIDATION
# ─────────────────────────────────────────────────────────────
MODE="full"
RAW_TARGET=""
 
usage() {
  echo -e "${BOLD}Usage:${NC} sudo bash $0 [--quick|--full|--stealth] <target-domain-or-IP>"
  echo "  --quick    Fast scan: top 1000 ports, no vuln scripts"
  echo "  --full     Default: comprehensive scan with vuln scripts (30-90min)"
  echo "  --stealth  Slow timing (T2), reduced rate, minimal noise"
  exit 1
}
 
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)   MODE="quick";   shift ;;
    --full)    MODE="full";    shift ;;
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
 
# Normalize: strip protocol, trailing path, trailing dot
TARGET="${RAW_TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%%/*}"
TARGET="${TARGET%.}"
 
if ! [[ "${TARGET}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  echo -e "${RED}[!] Invalid target '${TARGET}' — must be a domain or IP.${NC}"
  exit 1
fi
 
case "${MODE}" in
  quick)   NMAP_TIMING="-T4"; MASSCAN_RATE=2000; NMAP_TIMEOUT=180 ;;
  stealth) NMAP_TIMING="-T2"; MASSCAN_RATE=200;  NMAP_TIMEOUT=600 ;;
  *)       NMAP_TIMING="-T4"; MASSCAN_RATE=1000; NMAP_TIMEOUT=300 ;;
esac
 
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTDIR="${HOME}/Documents/reconledger_${TARGET}_${TIMESTAMP}"
LOGFILE="${OUTDIR}/reconledger.log"
SUMMARY="${OUTDIR}/SUMMARY.txt"
OPEN_PORTS_FILE="${OUTDIR}/network/open_ports.txt"
IS_WORDPRESS="false"
BEHIND_CDN="false"
CDN_NAME=""
 
mkdir -p "${OUTDIR}"/{dns,network,web,ssl,osint,metadata,vuln,raw,wordpress}
 
# ─────────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────────
log()     { echo -e "${GREEN}[+]${NC} $*" | tee -a "${LOGFILE}"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "${LOGFILE}"; }
err()     { echo -e "${RED}[-]${NC} $*" | tee -a "${LOGFILE}"; }
info()    { echo -e "${MAGENTA}[i]${NC} $*" | tee -a "${LOGFILE}"; }
section() { echo -e "\n${BLUE}${BOLD}━━━ $* ━━━${NC}" | tee -a "${LOGFILE}"; }
skip()    { warn "Skipping: $* (unavailable or not applicable)"; }
 
# ─────────────────────────────────────────────────────────────
#  SAFE RUNNER — never halts pipeline on individual tool failure
# ─────────────────────────────────────────────────────────────
run_cmd() {
  local desc="$1"
  local outfile="$2"
  local tsec="${3:-120}"
  shift 3
  log "Running [${tsec}s]: ${desc}"
  if timeout "${tsec}" "$@" > "${outfile}" 2>>"${LOGFILE}"; then
    log "Done: ${desc}"
  else
    local code=$?
    [[ $code -eq 124 ]] \
      && err "TIMEOUT (${tsec}s): ${desc} — moving on." \
      || err "FAILED (exit ${code}): ${desc} — moving on."
    echo "[FAILED/TIMEOUT] ${desc}" >> "${outfile}"
  fi
}
 
# ─────────────────────────────────────────────────────────────
#  TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────
declare -A TOOLS=(
  [dnsrecon]="dnsrecon"
  [dnsenum]="dnsenum"
  [fierce]="fierce"
  [subfinder]="subfinder"
  [amass]="amass"
  [nmap]="nmap"
  [masscan]="masscan"
  [whatweb]="whatweb"
  [wafw00f]="wafw00f"
  [gobuster]="gobuster"
  [ffuf]="ffuf"
  [nikto]="nikto"
  [sslscan]="sslscan"
  [theHarvester]="theharvester"
  [exiftool]="libimage-exiftool-perl"
  [nuclei]="nuclei"
  [searchsploit]="exploitdb"
  [hydra]="hydra"
  [sqlmap]="sqlmap"
  [wpscan]="wpscan"
  [xmllint]="libxml2-utils"
  [curl]="curl"
  [dig]="dnsutils"
  [whois]="whois"
  [wget]="wget"
  [host]="bind9-host"
  [traceroute]="traceroute"
  [nc]="netcat-openbsd"
  [jq]="jq"
)
 
# ─────────────────────────────────────────────────────────────
#  PHASE 1 — TOOL CHECK & AUTO-INSTALL
# ─────────────────────────────────────────────────────────────
check_and_install_tools() {
  section "PHASE 1 — Tool Check & Auto-Install"
 
  if ! command -v nala &>/dev/null; then
    warn "nala not found — installing via apt-get..."
    apt-get install -y nala >> "${LOGFILE}" 2>&1 \
      || warn "nala install failed — falling back to apt-get."
  fi
  PKG_MANAGER="nala"; command -v nala &>/dev/null || PKG_MANAGER="apt-get"
 
  log "Updating package lists..."
  ${PKG_MANAGER} update -y >> "${LOGFILE}" 2>&1 || warn "Package update had warnings."
 
  MISSING_PKGS=()
  for binary in "${!TOOLS[@]}"; do
    if ! command -v "${binary}" &>/dev/null; then
      warn "Missing: ${binary}  (pkg: ${TOOLS[$binary]})"
      MISSING_PKGS+=("${TOOLS[$binary]}")
    else
      log "Found:   ${binary}"
    fi
  done
 
  if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    UNIQUE_PKGS=($(printf '%s\n' "${MISSING_PKGS[@]}" | sort -u))
    log "Installing: ${UNIQUE_PKGS[*]}"
    ${PKG_MANAGER} install -y "${UNIQUE_PKGS[@]}" >> "${LOGFILE}" 2>&1 \
      && log "Packages installed." \
      || warn "Some packages failed — continuing."
  else
    log "All tools present."
  fi
 
  # wpscan gem fallback
  if ! command -v wpscan &>/dev/null; then
    warn "wpscan missing from apt — trying gem..."
    gem install wpscan >> "${LOGFILE}" 2>&1 \
      && log "wpscan installed via gem." \
      || warn "wpscan gem install failed — WP scans will use curl fallbacks."
  fi
 
  # wpscan database — update if installed
  if command -v wpscan &>/dev/null; then
    log "Updating wpscan vulnerability database..."
    if ! wpscan --update >> "${LOGFILE}" 2>&1; then
      warn "wpscan database update failed (may be outdated). Attempting gem reinstall..."
      gem uninstall wpscan --all --ignore-dependencies >> "${LOGFILE}" 2>&1 || true
      gem install wpscan >> "${LOGFILE}" 2>&1 \
        && wpscan --update >> "${LOGFILE}" 2>&1 \
        && log "wpscan reinstalled and updated successfully." \
        || warn "wpscan could not be updated — scans may use an outdated database."
    else
      log "wpscan database up to date."
    fi
  fi
 
  # SecLists
  SUBDOMAIN_WL="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  if [[ ! -f "${SUBDOMAIN_WL}" ]]; then
    log "Installing SecLists..."
    ${PKG_MANAGER} install -y seclists >> "${LOGFILE}" 2>&1 \
      || warn "SecLists install failed — subdomain brute-force will skip."
  fi
 
  # nuclei templates
  if command -v nuclei &>/dev/null; then
    log "Updating nuclei templates..."
    nuclei -update-templates >> "${LOGFILE}" 2>&1 || warn "nuclei template update failed."
  fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 2 — TARGET VALIDATION & IP RESOLUTION
# ─────────────────────────────────────────────────────────────
resolve_target() {
  section "PHASE 2 — Target Validation & IP Resolution"
 
  TARGET_IP=$(dig +short A "${TARGET}" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true)
  if [[ -z "${TARGET_IP}" ]]; then
    if [[ "${TARGET}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      TARGET_IP="${TARGET}"
      log "Target is a raw IP: ${TARGET_IP}"
    else
      err "Could not resolve ${TARGET} to an IP. DNS may be unreachable. Exiting."
      exit 1
    fi
  else
    log "Resolved: ${TARGET} → ${TARGET_IP}"
  fi
  echo "${TARGET_IP}" > "${OUTDIR}/network/target_ip.txt"
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 3 — CDN / WAF DETECTION
# ─────────────────────────────────────────────────────────────
cdn_waf_detection() {
  section "PHASE 3 — CDN / WAF Detection"
 
  info "Checking for CDN/WAF before active scanning..."
  CDN_HEADERS=$(curl -sI --max-time 10 "https://${TARGET}" 2>/dev/null || \
                curl -sI --max-time 10 "http://${TARGET}"  2>/dev/null || true)
 
  CDN_NAME=""
  echo "${CDN_HEADERS}" | grep -qi "cf-ray\|cloudflare"     && CDN_NAME="Cloudflare"
  echo "${CDN_HEADERS}" | grep -qi "x-akamai\|akamaighost"  && CDN_NAME="Akamai"
  echo "${CDN_HEADERS}" | grep -qi "x-fastly\|fastly"       && CDN_NAME="Fastly"
  echo "${CDN_HEADERS}" | grep -qi "x-sucuri\|sucuri"       && CDN_NAME="Sucuri"
  echo "${CDN_HEADERS}" | grep -qi "x-imperva\|imperva"     && CDN_NAME="Imperva"
 
  {
    echo "Target : ${TARGET}"
    echo "IP     : ${TARGET_IP}"
    echo "CDN    : ${CDN_NAME:-None detected}"
    echo ""
    echo "${CDN_HEADERS}"
  } > "${OUTDIR}/network/cdn_check.txt"
 
  if [[ -n "${CDN_NAME}" ]]; then
    BEHIND_CDN="true"
    warn "Target appears to be behind ${CDN_NAME}."
    warn "Port scans will hit ${CDN_NAME} infrastructure, not the origin server."
    warn "Consider origin IP discovery (subfinder, Shodan, old DNS records) before full-port scans."
  else
    log "No CDN/WAF detected — proceeding with direct scan against ${TARGET_IP}."
  fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 4 — PASSIVE OSINT (no active traffic to target)
# ─────────────────────────────────────────────────────────────
passive_osint() {
  section "PHASE 4 — Passive OSINT (WHOIS, theHarvester, crt.sh)"
 
  {
    run_cmd "WHOIS" "${OUTDIR}/osint/whois.txt" 60 whois "${TARGET}"
  } &
  {
    run_cmd "crt.sh" "${OUTDIR}/osint/crtsh.txt" 30 \
      curl -s "https://crt.sh/?q=%25.${TARGET}&output=json"
  } &
  {
    run_cmd "curl HTTP headers"  "${OUTDIR}/web/curl_headers.txt"  20 \
      curl -sI --max-time 15 "https://${TARGET}"
    run_cmd "robots.txt"         "${OUTDIR}/web/robots.txt"        20 \
      curl -sL --max-time 15 "https://${TARGET}/robots.txt"
    run_cmd "sitemap.xml"        "${OUTDIR}/web/sitemap.xml"       20 \
      curl -sL --max-time 15 "https://${TARGET}/sitemap.xml"
    run_cmd "security.txt"       "${OUTDIR}/web/security.txt"      20 \
      curl -sL --max-time 15 "https://${TARGET}/.well-known/security.txt"
  } &
 
  wait
  log "Passive OSINT parallel jobs complete."
 
  if command -v theHarvester &>/dev/null; then
    for src in bing baidu certspotter crtsh dnsdumpster; do
      run_cmd "theHarvester (${src})" "${OUTDIR}/osint/harvester_${src}.txt" 120 \
        theHarvester -d "${TARGET}" -b "${src}" -l 200
    done
  else skip "theHarvester"; fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 5 — DNS ENUMERATION & SUBDOMAIN DISCOVERY
# ─────────────────────────────────────────────────────────────
dns_enum() {
  section "PHASE 5 — DNS Enumeration & Subdomain Discovery"
 
  # dig records (parallel)
  {
    run_cmd "dig A"    "${OUTDIR}/dns/dig_a.txt"    20  dig A    "${TARGET}" +short
    run_cmd "dig MX"   "${OUTDIR}/dns/dig_mx.txt"   20  dig MX   "${TARGET}" +noall +answer
    run_cmd "dig NS"   "${OUTDIR}/dns/dig_ns.txt"   20  dig NS   "${TARGET}" +noall +answer
    run_cmd "dig TXT"  "${OUTDIR}/dns/dig_txt.txt"  20  dig TXT  "${TARGET}" +noall +answer
    run_cmd "dig SOA"  "${OUTDIR}/dns/dig_soa.txt"  20  dig SOA  "${TARGET}" +noall +answer
    run_cmd "dig AAAA" "${OUTDIR}/dns/dig_aaaa.txt" 20  dig AAAA "${TARGET}" +short
    run_cmd "host -a"  "${OUTDIR}/dns/host.txt"     20  host -a "${TARGET}"
  } &
 
  # AXFR — loop all authoritative NS servers
  {
    NS_LIST_FILE="${OUTDIR}/dns/ns_servers.txt"
    dig NS "${TARGET}" +short 2>/dev/null | sed 's/\.$//' > "${NS_LIST_FILE}" || true
    echo "=== DNS Zone Transfer Attempts (AXFR) ===" > "${OUTDIR}/dns/zone_transfer.txt"
    echo "Authoritative NS servers:" >> "${OUTDIR}/dns/zone_transfer.txt"
    cat "${NS_LIST_FILE}" >> "${OUTDIR}/dns/zone_transfer.txt"
    echo "" >> "${OUTDIR}/dns/zone_transfer.txt"
 
    if [[ ! -s "${NS_LIST_FILE}" ]]; then
      echo "No NS records found — cannot attempt AXFR." >> "${OUTDIR}/dns/zone_transfer.txt"
    else
      while IFS= read -r ns; do
        [[ -z "${ns}" ]] && continue
        echo "--- Attempting AXFR: ${TARGET} @${ns} ---" >> "${OUTDIR}/dns/zone_transfer.txt"
        timeout 20 dig AXFR "${TARGET}" "@${ns}" >> "${OUTDIR}/dns/zone_transfer.txt" 2>&1 \
          && log "AXFR attempt completed: @${ns}" \
          || warn "AXFR failed or refused: @${ns}"
      done < "${NS_LIST_FILE}"
    fi
  } &
 
  # dnsrecon
  {
    if command -v dnsrecon &>/dev/null; then
      run_cmd "dnsrecon standard"  "${OUTDIR}/dns/dnsrecon_std.txt" 300 \
        dnsrecon -d "${TARGET}" -t std
      run_cmd "dnsrecon brute"     "${OUTDIR}/dns/dnsrecon_brt.txt" 1200 \
        dnsrecon -d "${TARGET}" -t brt -D /usr/share/dnsrecon/namelist.txt
    else skip "dnsrecon"; fi
  } &
 
  # dnsenum
  {
    if command -v dnsenum &>/dev/null; then
      run_cmd "dnsenum" "${OUTDIR}/dns/dnsenum.txt" 1800 \
        dnsenum --noreverse --threads 5 "${TARGET}"
    else skip "dnsenum"; fi
  } &
 
  # fierce
  {
    if command -v fierce &>/dev/null; then
      run_cmd "fierce" "${OUTDIR}/dns/fierce.txt" 600 \
        fierce --domain "${TARGET}"
    else skip "fierce"; fi
  } &
 
  # subfinder
  {
    if command -v subfinder &>/dev/null; then
      run_cmd "subfinder" "${OUTDIR}/dns/subfinder.txt" 120 \
        subfinder -d "${TARGET}" -silent -o "${OUTDIR}/dns/subfinder_list.txt"
    else skip "subfinder"; fi
  } &
 
  # amass — passive subdomain OSINT (different sources than subfinder)
  {
    if command -v amass &>/dev/null; then
      run_cmd "amass passive" "${OUTDIR}/dns/amass.txt" 300 \
        amass enum -passive -d "${TARGET}" -o "${OUTDIR}/dns/amass_list.txt"
    else skip "amass"; fi
  } &
 
  wait
  log "DNS enumeration parallel jobs complete."
 
  # gobuster DNS — subdomain wordlist (sequential, needs network)
  if command -v gobuster &>/dev/null; then
    SUBDOMAIN_WL="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    ALT_WL="/usr/share/seclists/Discovery/DNS/namelist.txt"
    DNS_WL=""
    [[ -f "${SUBDOMAIN_WL}" ]] && DNS_WL="${SUBDOMAIN_WL}"
    [[ -z "${DNS_WL}" && -f "${ALT_WL}" ]] && DNS_WL="${ALT_WL}"
 
    if [[ -n "${DNS_WL}" ]]; then
      run_cmd "gobuster DNS" "${OUTDIR}/dns/gobuster_dns.txt" 600 \
        gobuster dns -d "${TARGET}" -w "${DNS_WL}" -t 20 --timeout 10s --no-error -q
    else
      warn "No subdomain wordlist found — gobuster DNS skipped."
    fi
  else skip "gobuster (DNS)"; fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 6 — PORT SCANNING (masscan sweep → targeted nmap)
# ─────────────────────────────────────────────────────────────
network_scan() {
  section "PHASE 6 — Port Scanning (masscan → nmap pipeline)"
 
  if [[ "${BEHIND_CDN}" == "true" ]]; then
    warn "CDN detected — port scan targets CDN edge, not origin. Results may be misleading."
  fi
 
  OPEN_PORTS_RAW="${OUTDIR}/network/masscan_open.lst"
  if command -v masscan &>/dev/null; then
    run_cmd "masscan full port sweep (${TARGET_IP})" \
      "${OUTDIR}/network/masscan_all.txt" 300 \
      masscan -p1-65535 "${TARGET_IP}" --rate="${MASSCAN_RATE}" \
        -oL "${OPEN_PORTS_RAW}"
  else
    warn "masscan not found — falling back to nmap -p- for discovery (slower)."
    run_cmd "nmap initial port discovery" "${OUTDIR}/network/nmap_discovery.txt" 600 \
      nmap -p- "${NMAP_TIMING}" --open --min-rate 1000 -n \
        "${TARGET_IP}" -oG "${OUTDIR}/network/nmap_discovery_grep.txt"
    OPEN_PORTS_RAW="${OUTDIR}/network/nmap_discovery_grep.txt"
  fi
 
  # Extract confirmed open ports
  if [[ -f "${OPEN_PORTS_RAW}" ]]; then
    if grep -q "^open" "${OPEN_PORTS_RAW}" 2>/dev/null; then
      grep "^open" "${OPEN_PORTS_RAW}" \
        | awk '{print $3}' | sort -un \
        | tr '\n' ',' | sed 's/,$//' \
        > "${OPEN_PORTS_FILE}" 2>/dev/null || true
    fi
    if [[ ! -s "${OPEN_PORTS_FILE}" ]]; then
      grep "Ports:" "${OPEN_PORTS_RAW}" 2>/dev/null \
        | grep -Eo '[0-9]+/open' | cut -d/ -f1 \
        | sort -un | tr '\n' ',' | sed 's/,$//' \
        > "${OPEN_PORTS_FILE}" || true
    fi
  fi
 
  if [[ -s "${OPEN_PORTS_FILE}" ]]; then
    OPEN_PORTS=$(cat "${OPEN_PORTS_FILE}")
    log "Open ports confirmed: ${OPEN_PORTS}"
  else
    warn "No open ports found — falling back to nmap top-1000."
    OPEN_PORTS="top1000"
  fi
 
  if command -v nmap &>/dev/null; then
    [[ "${OPEN_PORTS}" == "top1000" ]] && NMAP_PORT_ARG="--top-ports 1000" || NMAP_PORT_ARG="-p ${OPEN_PORTS}"
 
    run_cmd "nmap service+version+OS (open ports)" \
      "${OUTDIR}/network/nmap_targeted.txt" "${NMAP_TIMEOUT}" \
      nmap ${NMAP_PORT_ARG} -sV -sC -O --open ${NMAP_TIMING} \
        "${TARGET}" -oA "${OUTDIR}/network/nmap_targeted"
 
    if [[ "${MODE}" != "quick" ]]; then
      run_cmd "nmap vuln scripts (open ports only)" \
        "${OUTDIR}/network/nmap_vuln.txt" 600 \
        nmap ${NMAP_PORT_ARG} --script=vuln ${NMAP_TIMING} \
          "${TARGET}" -oA "${OUTDIR}/network/nmap_vuln"
    fi
 
    # UDP — full mode only
    if [[ "${MODE}" == "full" ]]; then
      run_cmd "nmap UDP top 100" "${OUTDIR}/network/nmap_udp.txt" 300 \
        nmap -sU --top-ports 100 ${NMAP_TIMING} "${TARGET}" \
          -oA "${OUTDIR}/network/nmap_udp"
    fi
 
    run_cmd "traceroute" "${OUTDIR}/network/traceroute.txt" 30 traceroute -n "${TARGET}"
 
    # Banner grabs — only on confirmed open ports
    for port in 21 22 25 80 443 3306 3389 8080; do
      if echo "${OPEN_PORTS}" | tr ',' '\n' | grep -q "^${port}$" \
         || [[ "${OPEN_PORTS}" == "top1000" ]]; then
        run_cmd "nc banner port ${port}" \
          "${OUTDIR}/network/banner_p${port}.txt" 10 \
          bash -c "echo '' | nc -w 3 ${TARGET} ${port} 2>/dev/null || true"
      fi
    done
  else skip "nmap"; fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 7 — SERVICE-SPECIFIC SCRIPTS (port-gated)
# ─────────────────────────────────────────────────────────────
service_scripts() {
  section "PHASE 7 — Service-Specific Nmap Scripts (port-gated)"
 
  if ! command -v nmap &>/dev/null; then skip "nmap service scripts"; return; fi
 
  HTTP_PORTS=$(echo "${OPEN_PORTS}" | tr ',' '\n' \
    | grep -E '^(80|443|8080|8443)$' | tr '\n' ',' | sed 's/,$//' || true)
  if [[ -n "${HTTP_PORTS}" || "${OPEN_PORTS}" == "top1000" ]]; then
    HPORT_ARG="${HTTP_PORTS:-80,443,8080,8443}"
    run_cmd "nmap HTTP scripts (ports: ${HPORT_ARG})" \
      "${OUTDIR}/web/nmap_http.txt" 120 \
      nmap -p "${HPORT_ARG}" \
        --script=http-title,http-headers,http-methods,http-auth-finder \
        ${NMAP_TIMING} "${TARGET}" -oA "${OUTDIR}/web/nmap_http"
  else
    info "No HTTP ports open — skipping nmap HTTP scripts."
  fi
 
  SMB_PORTS=$(echo "${OPEN_PORTS}" | tr ',' '\n' \
    | grep -E '^(445|139)$' | tr '\n' ',' | sed 's/,$//' || true)
  if [[ -n "${SMB_PORTS}" ]]; then
    run_cmd "nmap SMB scripts (ports: ${SMB_PORTS})" \
      "${OUTDIR}/network/nmap_smb.txt" 120 \
      nmap -p "${SMB_PORTS}" \
        --script=smb-enum-shares,smb-enum-users,smb-os-discovery \
        ${NMAP_TIMING} "${TARGET}" -oA "${OUTDIR}/network/nmap_smb"
  else
    info "Ports 445/139 not open — skipping SMB scripts."
  fi
 
  if echo "${OPEN_PORTS}" | tr ',' '\n' | grep -q '^21$'; then
    run_cmd "nmap FTP scripts" "${OUTDIR}/network/nmap_ftp.txt" 60 \
      nmap -p 21 --script=ftp-anon,ftp-bounce,ftp-syst \
        ${NMAP_TIMING} "${TARGET}" -oA "${OUTDIR}/network/nmap_ftp"
  else
    info "Port 21 not open — skipping FTP scripts."
  fi
 
  if echo "${OPEN_PORTS}" | tr ',' '\n' | grep -q '^22$'; then
    run_cmd "nmap SSH scripts" "${OUTDIR}/network/nmap_ssh.txt" 60 \
      nmap -p 22 --script=ssh-auth-methods,ssh-hostkey \
        ${NMAP_TIMING} "${TARGET}" -oA "${OUTDIR}/network/nmap_ssh"
  else
    info "Port 22 not open — skipping SSH scripts."
  fi
 
  if echo "${OPEN_PORTS}" | tr ',' '\n' | grep -q '^3306$'; then
    run_cmd "nmap MySQL scripts" "${OUTDIR}/network/nmap_mysql.txt" 60 \
      nmap -p 3306 --script=mysql-info,mysql-empty-password \
        ${NMAP_TIMING} "${TARGET}" -oA "${OUTDIR}/network/nmap_mysql"
  else
    info "Port 3306 not open — skipping MySQL scripts."
  fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 8 — WEB FINGERPRINTING
# ─────────────────────────────────────────────────────────────
web_fingerprint() {
  section "PHASE 8 — Web Fingerprinting"
 
  if command -v whatweb &>/dev/null; then
    run_cmd "whatweb fingerprint" "${OUTDIR}/web/whatweb.txt" 60 \
      whatweb -a 3 --colour=never "https://${TARGET}"
  else skip "whatweb"; fi
 
  if command -v wafw00f &>/dev/null; then
    run_cmd "wafw00f WAF detection" "${OUTDIR}/web/wafw00f.txt" 60 \
      wafw00f "https://${TARGET}"
  else skip "wafw00f"; fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 9 — WEB CONTENT DISCOVERY (gobuster, ffuf, nikto, probes)
# ─────────────────────────────────────────────────────────────
web_content_discovery() {
  section "PHASE 9 — Web Content Discovery"
 
  # Directory brute — SecLists with fallback to dirb
  if command -v gobuster &>/dev/null; then
    DIR_WL=""
    for wl in \
        "/usr/share/seclists/Discovery/Web-Content/common.txt" \
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" \
        "/usr/share/wordlists/dirb/common.txt" \
        "/usr/share/dirb/wordlists/common.txt"; do
      [[ -f "${wl}" ]] && DIR_WL="${wl}" && break
    done
    if [[ -n "${DIR_WL}" ]]; then
      run_cmd "gobuster dir brute" "${OUTDIR}/web/gobuster_dirs.txt" 600 \
        gobuster dir -u "https://${TARGET}" -w "${DIR_WL}" -t 30 --timeout 10s --no-error -q
    else
      warn "No directory wordlist found — gobuster dir skipped."
    fi
  else skip "gobuster"; fi
 
  # ffuf — parameter and additional content fuzzing
  if command -v ffuf &>/dev/null; then
    FFUF_WL=""
    for wl in \
        "/usr/share/seclists/Discovery/Web-Content/common.txt" \
        "/usr/share/wordlists/dirb/common.txt"; do
      [[ -f "${wl}" ]] && FFUF_WL="${wl}" && break
    done
    if [[ -n "${FFUF_WL}" ]]; then
      run_cmd "ffuf dir fuzz" "${OUTDIR}/web/ffuf_dirs.txt" 600 \
        ffuf -u "https://${TARGET}/FUZZ" -w "${FFUF_WL}" \
          -mc 200,201,301,302,403 -ac -s \
          -o "${OUTDIR}/web/ffuf_results.json" -of json
    else
      warn "No wordlist for ffuf — skipping."
    fi
  else skip "ffuf"; fi
 
  # nikto
  if command -v nikto &>/dev/null; then
    run_cmd "nikto web scan" "${OUTDIR}/web/nikto.txt" 1200 \
      nikto -h "https://${TARGET}" -nointeractive -maxtime 1200s
  else skip "nikto"; fi
 
  # Sensitive path probes
  for endpoint in /admin /login /phpmyadmin /.env /config.php /backup \
                  /.git/HEAD /.htaccess /server-status /api /swagger.json \
                  /wp-login.php /.DS_Store /crossdomain.xml /xmlrpc.php \
                  /console /actuator /actuator/health /graphql; do
    safe="${endpoint//\//_}"
    run_cmd "probe ${endpoint}" "${OUTDIR}/web/probe_${safe}.txt" 12 \
      curl -sIL --max-time 10 --write-out "\nHTTP_STATUS:%{http_code}\n" \
        "https://${TARGET}${endpoint}"
  done
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 10 — SSL/TLS ANALYSIS
# ─────────────────────────────────────────────────────────────
ssl_analysis() {
  section "PHASE 10 — SSL/TLS Analysis"
 
  if command -v sslscan &>/dev/null; then
    run_cmd "sslscan" "${OUTDIR}/ssl/sslscan.txt" 120 \
      sslscan --no-colour "${TARGET}:443"
  else skip "sslscan"; fi
 
  run_cmd "openssl certificate info" "${OUTDIR}/ssl/openssl_cert.txt" 30 \
    bash -c "echo | openssl s_client -connect ${TARGET}:443 -servername ${TARGET} 2>/dev/null \
      | openssl x509 -noout -text 2>/dev/null || echo '[No SSL or connection failed]'"
 
  {
    echo "=== Security Header Analysis: ${TARGET} ==="
    HEADERS=$(curl -sI --max-time 15 "https://${TARGET}" 2>/dev/null || true)
    for hdr in "Strict-Transport-Security" "Content-Security-Policy" \
               "X-Frame-Options" "X-Content-Type-Options" \
               "Referrer-Policy" "Permissions-Policy" \
               "Cross-Origin-Opener-Policy" "Cross-Origin-Resource-Policy"; do
      if echo "${HEADERS}" | grep -qi "${hdr}"; then
        echo "[PRESENT]  ${hdr}"
      else
        echo "[MISSING]  ${hdr}"
      fi
    done
  } > "${OUTDIR}/ssl/header_analysis.txt" 2>>"${LOGFILE}"
  log "Security header analysis → ${OUTDIR}/ssl/header_analysis.txt"
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 11 — METADATA EXTRACTION
# ─────────────────────────────────────────────────────────────
metadata_extraction() {
  section "PHASE 11 — Metadata Extraction"
 
  TMPHTML="${OUTDIR}/raw/index.html"
  run_cmd "wget index page" "${OUTDIR}/raw/wget.log" 30 \
    wget -q --timeout=20 -O "${TMPHTML}" "https://${TARGET}" || true
 
  if command -v exiftool &>/dev/null && [[ -f "${TMPHTML}" ]]; then
    run_cmd "exiftool" "${OUTDIR}/metadata/exiftool_index.txt" 30 exiftool "${TMPHTML}"
  else skip "exiftool"; fi
 
  if [[ -f "${TMPHTML}" ]]; then
    grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
      "${TMPHTML}" | sort -u > "${OUTDIR}/metadata/emails_found.txt" 2>/dev/null || true
    grep -Eo 'href="[^"]+"' "${TMPHTML}" | sort -u \
      > "${OUTDIR}/metadata/links_found.txt" 2>/dev/null || true
    grep -Eo '(https?://[^ "]+)' "${TMPHTML}" | sort -u \
      > "${OUTDIR}/metadata/urls_found.txt" 2>/dev/null || true
    log "Metadata extracted → ${OUTDIR}/metadata/"
  fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 12 — WORDPRESS DETECTION & FULL WP RECON
# ─────────────────────────────────────────────────────────────
wordpress_recon() {
  section "PHASE 12 — WordPress Detection & Recon"
 
  WPDIR="${OUTDIR}/wordpress"
  WP_BASE="https://${TARGET}"
  WP_SIGNALS=0
 
  info "Running WordPress detection signals..."
 
  WP_LOGIN_STATUS=$(curl -sIL --max-time 10 "${WP_BASE}/wp-login.php" \
    -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
  [[ "${WP_LOGIN_STATUS}" =~ ^(200|302|301)$ ]] \
    && WP_SIGNALS=$((WP_SIGNALS+1)) \
    && log "WP signal 1: wp-login.php → ${WP_LOGIN_STATUS}"
 
  WP_CONTENT=$(curl -sL --max-time 10 "${WP_BASE}" 2>/dev/null \
    | grep -c "wp-content" 2>/dev/null || true)
  [[ "${WP_CONTENT}" -gt 0 ]] \
    && WP_SIGNALS=$((WP_SIGNALS+1)) \
    && log "WP signal 2: wp-content in source (${WP_CONTENT} hits)"
 
  WP_JSON_STATUS=$(curl -sIL --max-time 10 "${WP_BASE}/wp-json/" \
    -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
  [[ "${WP_JSON_STATUS}" == "200" ]] \
    && WP_SIGNALS=$((WP_SIGNALS+1)) \
    && log "WP signal 3: wp-json REST API → 200"
 
  WP_GENERATOR=$(curl -sL --max-time 10 "${WP_BASE}" 2>/dev/null \
    | grep -i 'generator.*WordPress' || true)
  [[ -n "${WP_GENERATOR}" ]] \
    && WP_SIGNALS=$((WP_SIGNALS+1)) \
    && log "WP signal 4: generator meta tag found"
 
  {
    echo "WordPress Detection"
    echo "Target  : ${TARGET}"
    echo "Signals : ${WP_SIGNALS}/4"
  } > "${WPDIR}/wp_detection.txt"
 
  if [[ "${WP_SIGNALS}" -ge 2 ]]; then
    IS_WORDPRESS="true"
    info "WordPress DETECTED (${WP_SIGNALS}/4) — running full WP recon."
    echo "Status  : DETECTED" >> "${WPDIR}/wp_detection.txt"
  else
    info "WordPress NOT detected (${WP_SIGNALS}/4) — skipping WP scans."
    echo "Status  : NOT DETECTED" >> "${WPDIR}/wp_detection.txt"
    return 0
  fi
 
  # wpscan — parallel scans with increased timeouts and --update flag
  if command -v wpscan &>/dev/null; then
    {
      run_cmd "wpscan full enum" "${WPDIR}/wpscan_full.txt" 900 \
        wpscan --url "${WP_BASE}" --enumerate ap,at,cb,dbe,u,m \
          --plugins-detection aggressive --themes-detection aggressive \
          --request-timeout 120 --connect-timeout 60 \
          --no-banner --format cli-no-colour
    } &
    {
      run_cmd "wpscan vuln plugins" "${WPDIR}/wpscan_vuln_plugins.txt" 900 \
        wpscan --url "${WP_BASE}" --enumerate vp \
          --plugins-detection aggressive \
          --request-timeout 120 --connect-timeout 60 \
          --no-banner --format cli-no-colour
    } &
    {
      run_cmd "wpscan vuln themes" "${WPDIR}/wpscan_vuln_themes.txt" 900 \
        wpscan --url "${WP_BASE}" --enumerate vt \
          --themes-detection aggressive \
          --request-timeout 120 --connect-timeout 60 \
          --no-banner --format cli-no-colour
    } &
    wait
    log "wpscan parallel jobs complete."
  else
    warn "wpscan not available — using curl-based WP fingerprinting."
  fi
 
  # WP version detection (5 sources)
  {
    echo "=== WordPress Version Detection ==="
    echo "[1] Generator meta tag:"
    curl -sL --max-time 15 "${WP_BASE}" 2>/dev/null | grep -i 'generator' | head -5 \
      || echo "  Not found"
    echo ""
    echo "[2] readme.html:"
    curl -sL --max-time 15 "${WP_BASE}/readme.html" 2>/dev/null \
      | grep -i 'version\|wordpress' | head -10 || echo "  Not accessible"
    echo ""
    echo "[3] RSS feed generator:"
    curl -sL --max-time 15 "${WP_BASE}/feed/" 2>/dev/null \
      | grep -i 'generator' | head -5 || echo "  Not found"
    echo ""
    echo "[4] wp-includes/version.php HTTP status:"
    curl -sIL --max-time 10 "${WP_BASE}/wp-includes/version.php" \
      -o /dev/null -w "  HTTP Status: %{http_code}\n" 2>/dev/null || echo "  ERR"
    echo ""
    echo "[5] Admin CSS ver param:"
    curl -sL --max-time 15 "${WP_BASE}/wp-admin/css/common.css" 2>/dev/null \
      | grep -i 'ver=' | head -3 || echo "  Not accessible"
  } > "${WPDIR}/wp_version.txt" 2>>"${LOGFILE}"
 
  # REST API enumeration
  {
    echo "=== WordPress REST API ==="
    echo "[1] /wp-json/ root:"
    curl -sL --max-time 15 "${WP_BASE}/wp-json/" 2>/dev/null \
      | (command -v jq &>/dev/null && jq '.' || cat) | head -60
    echo ""
    echo "[2] Users:"
    curl -sL --max-time 15 "${WP_BASE}/wp-json/wp/v2/users" 2>/dev/null \
      | (command -v jq &>/dev/null && jq '.[].name,.slug' || cat) | head -30
    echo ""
    echo "[3] Posts (5):"
    curl -sL --max-time 15 "${WP_BASE}/wp-json/wp/v2/posts?per_page=5" 2>/dev/null \
      | (command -v jq &>/dev/null && jq '.[].link' || cat) | head -20
  } > "${WPDIR}/wp_rest_api.txt" 2>>"${LOGFILE}"
 
  # User enumeration
  {
    echo "=== WordPress User Enumeration ==="
    echo "[1] ?author= parameter scan (1-10):"
    for i in $(seq 1 10); do
      RESP=$(curl -sIL --max-time 10 "${WP_BASE}/?author=${i}" \
        -w "\nHTTP_CODE:%{http_code}\nFINAL_URL:%{url_effective}" 2>/dev/null || true)
      CODE=$(echo "${RESP}" | grep "HTTP_CODE" | cut -d: -f2)
      URL=$(echo "${RESP}"  | grep "FINAL_URL" | cut -d: -f2-)
      [[ "${CODE}" =~ ^(200|301|302)$ ]] && echo "  author=${i} → ${URL} [${CODE}]"
    done
    echo ""
    echo "[2] REST API users:"
    curl -sL --max-time 15 "${WP_BASE}/wp-json/wp/v2/users" 2>/dev/null \
      | grep -Eo '"slug":"[^"]*"|"name":"[^"]*"' | head -20 || echo "  Not accessible"
  } > "${WPDIR}/wp_users.txt" 2>>"${LOGFILE}"
 
  # Plugin & theme detection from source
  {
    echo "=== Plugin & Theme Detection ==="
    echo "[1] Plugins in source:"
    curl -sL --max-time 20 "${WP_BASE}" 2>/dev/null \
      | grep -Eo 'wp-content/plugins/[a-zA-Z0-9_-]+' | sort -u || echo "  None visible"
    echo ""
    echo "[2] Themes in source:"
    curl -sL --max-time 20 "${WP_BASE}" 2>/dev/null \
      | grep -Eo 'wp-content/themes/[a-zA-Z0-9_-]+' | sort -u || echo "  None visible"
  } > "${WPDIR}/wp_plugins_themes.txt" 2>>"${LOGFILE}"
 
  # Sensitive path probe
  {
    echo "=== WP Sensitive Endpoint Probes ==="
    WP_PATHS=(
      "/wp-login.php" "/wp-admin/" "/wp-admin/admin-ajax.php"
      "/wp-config.php" "/wp-config.php.bak" "/wp-config.old"
      "/.wp-config.php.swp" "/wp-content/debug.log"
      "/wp-content/uploads/" "/wp-includes/version.php"
      "/readme.html" "/license.txt" "/wp-cron.php" "/xmlrpc.php"
      "/wp-json/wp/v2/users" "/wp-json/wp/v2/settings"
      "/?rest_route=/wp/v2/users" "/wp-admin/install.php"
      "/wp-admin/setup-config.php" "/.env"
    )
    for path in "${WP_PATHS[@]}"; do
      STATUS=$(curl -sIL --max-time 10 "${WP_BASE}${path}" \
        -o /dev/null -w "%{http_code}" 2>/dev/null || echo "ERR")
      printf "  %-55s [%s]\n" "${path}" "${STATUS}"
    done
  } > "${WPDIR}/wp_sensitive_paths.txt" 2>>"${LOGFILE}"
 
  # XML-RPC analysis
  {
    echo "=== XML-RPC Analysis ==="
    echo "[1] HTTP status:"
    curl -sIL --max-time 10 "${WP_BASE}/xmlrpc.php" 2>/dev/null | head -10
    echo ""
    echo "[2] Method list:"
    curl -sL --max-time 15 "${WP_BASE}/xmlrpc.php" \
      --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
      2>/dev/null | head -60 || echo "  Not responding"
  } > "${WPDIR}/wp_xmlrpc.txt" 2>>"${LOGFILE}"
 
  # Nuclei WP templates
  if command -v nuclei &>/dev/null; then
    run_cmd "nuclei WP templates" "${WPDIR}/nuclei_wp.txt" 900 \
      nuclei -u "${WP_BASE}" -tags wordpress -silent \
        -o "${WPDIR}/nuclei_wp_findings.txt"
  fi
 
  # nmap WP scripts — only if 80/443 open
  if command -v nmap &>/dev/null; then
    WP_HTTP=$(echo "${OPEN_PORTS}" | tr ',' '\n' \
      | grep -E '^(80|443)$' | tr '\n' ',' | sed 's/,$//' || true)
    if [[ -n "${WP_HTTP}" || "${OPEN_PORTS}" == "top1000" ]]; then
      run_cmd "nmap WP scripts" "${WPDIR}/nmap_wp.txt" 120 \
        nmap --script=http-wordpress-users,http-wordpress-enum \
          -p "${WP_HTTP:-80,443}" "${TARGET}" -oA "${WPDIR}/nmap_wp"
    fi
  fi
 
  log "WordPress recon complete → ${WPDIR}/"
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 13 — VULNERABILITY SCANNING (nuclei, searchsploit)
# ─────────────────────────────────────────────────────────────
vuln_identification() {
  section "PHASE 13 — Vulnerability Scanning"
 
  if command -v nuclei &>/dev/null; then
    run_cmd "nuclei full scan" "${OUTDIR}/vuln/nuclei_all.txt" 900 \
      nuclei -u "https://${TARGET}" -silent \
        -severity low,medium,high,critical \
        -o "${OUTDIR}/vuln/nuclei_findings.txt"
  else skip "nuclei"; fi
 
  # sqlmap — only if HTTP ports are open
  HTTP_UP=$(echo "${OPEN_PORTS}" | tr ',' '\n' | grep -E '^(80|443|8080|8443)$' | head -1 || true)
  if command -v sqlmap &>/dev/null && [[ -n "${HTTP_UP}" || "${OPEN_PORTS}" == "top1000" ]]; then
    run_cmd "sqlmap crawl" "${OUTDIR}/vuln/sqlmap.txt" 300 \
      sqlmap -u "https://${TARGET}" --crawl=2 --batch --level=1 --risk=1 \
        --output-dir="${OUTDIR}/vuln/sqlmap_output" --quiet
  else skip "sqlmap (no HTTP ports or tool unavailable)"; fi
 
  # hydra — SSH brute only if port 22 open (minimal, informational)
  if command -v hydra &>/dev/null && echo "${OPEN_PORTS}" | tr ',' '\n' | grep -q '^22$'; then
    HYDRA_WL="/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"
    if [[ -f "${HYDRA_WL}" ]]; then
      run_cmd "hydra SSH common passwords (user: admin)" "${OUTDIR}/vuln/hydra_ssh.txt" 120 \
        hydra -l admin -P "${HYDRA_WL}" -t 4 -f ssh://"${TARGET}"
    else
      warn "Hydra wordlist not found — skipping SSH brute."
    fi
  else
    info "Port 22 not open or hydra unavailable — skipping SSH brute."
  fi
 
  # searchsploit — parse nmap XML for product+version, run per service
  if command -v searchsploit &>/dev/null && command -v xmllint &>/dev/null; then
    NMAP_XML="${OUTDIR}/network/nmap_targeted.xml"
    if [[ -f "${NMAP_XML}" ]]; then
      log "Parsing nmap XML for service versions..."
      xmllint --xpath \
        "//port[state/@state='open']/service[string-length(@product)>0]" \
        "${NMAP_XML}" 2>/dev/null \
        | grep -Eo 'product="[^"]*"[^/]*version="[^"]*"' \
        | sed 's/product="//;s/" version="/ /;s/"//' \
        | sort -u > "${OUTDIR}/vuln/services_detected.txt" || true
 
      if [[ ! -s "${OUTDIR}/vuln/services_detected.txt" ]]; then
        grep -E "open.*tcp|open.*udp" "${OUTDIR}/network/nmap_targeted.txt" \
          2>/dev/null | awk '{
            for(i=1;i<=NF;i++){
              if($i ~ /^[0-9]+\.[0-9]+/){
                print $(i-1) " " $i; break
              }
            }
          }' | sort -u >> "${OUTDIR}/vuln/services_detected.txt" || true
      fi
 
      log "Services for searchsploit:"
      cat "${OUTDIR}/vuln/services_detected.txt" | head -20 | tee -a "${LOGFILE}"
 
      while IFS= read -r svc; do
        [[ -z "${svc}" ]] && continue
        safe="${svc//[^a-zA-Z0-9._-]/_}"
        run_cmd "searchsploit: ${svc}" \
          "${OUTDIR}/vuln/searchsploit_${safe}.txt" 30 \
          searchsploit --colour "${svc}"
      done < "${OUTDIR}/vuln/services_detected.txt"
    else
      warn "No nmap XML found — running generic searchsploit."
      run_cmd "searchsploit generic" "${OUTDIR}/vuln/searchsploit_generic.txt" 30 \
        searchsploit "${TARGET}"
    fi
  elif command -v searchsploit &>/dev/null; then
    warn "xmllint not found — running generic searchsploit."
    run_cmd "searchsploit generic" "${OUTDIR}/vuln/searchsploit_generic.txt" 30 \
      searchsploit "${TARGET}"
  else
    skip "searchsploit"
  fi
}
 
# ─────────────────────────────────────────────────────────────
#  PHASE 14 — SUMMARY REPORT
# ─────────────────────────────────────────────────────────────
generate_summary() {
  section "PHASE 14 — Summary Report"
 
  {
    echo "================================================================"
    echo "  ReconLedger v1 — Summary Report"
    echo "  Target      : ${TARGET}"
    echo "  IP          : ${TARGET_IP:-unknown}"
    echo "  CDN/WAF     : ${CDN_NAME:-None detected}"
    echo "  WordPress   : $([[ "${IS_WORDPRESS}" == "true" ]] && echo 'DETECTED' || echo 'Not detected')"
    echo "  Scan Mode   : ${MODE}"
    echo "  Date        : $(date)"
    echo "  Output dir  : ${OUTDIR}/"
    echo "================================================================"
    echo ""
 
    echo "── OPEN PORTS ──────────────────────────────────────────────────"
    [[ -s "${OPEN_PORTS_FILE}" ]] && cat "${OPEN_PORTS_FILE}" || echo "N/A"
    echo ""
 
    echo "── nmap SERVICE VERSIONS ───────────────────────────────────────"
    grep -E "^[0-9]+/tcp.*open" "${OUTDIR}/network/nmap_targeted.txt" \
      2>/dev/null || echo "N/A"
    echo ""
 
    echo "── WHOIS SUMMARY ───────────────────────────────────────────────"
    grep -E "Registrar:|Creation Date|Expiry|Name Server" \
      "${OUTDIR}/osint/whois.txt" 2>/dev/null | head -12 || echo "N/A"
    echo ""
 
    echo "── DNS RECORDS ─────────────────────────────────────────────────"
    for f in "${OUTDIR}/dns/dig_a.txt" "${OUTDIR}/dns/dig_mx.txt" \
              "${OUTDIR}/dns/dig_ns.txt" "${OUTDIR}/dns/dig_txt.txt"; do
      [[ -s "${f}" ]] && echo "  [$(basename ${f})]:" && cat "${f}" | head -5
    done
    echo ""
 
    echo "── SUBDOMAINS ──────────────────────────────────────────────────"
    {
      cat "${OUTDIR}/dns/subfinder_list.txt" 2>/dev/null
      cat "${OUTDIR}/dns/amass_list.txt" 2>/dev/null
    } | sort -u | head -30 || echo "N/A"
    echo ""
 
    echo "── WEB TECHNOLOGIES ────────────────────────────────────────────"
    cat "${OUTDIR}/web/whatweb.txt" 2>/dev/null | head -15 || echo "N/A"
    echo ""
 
    echo "── SECURITY HEADERS ────────────────────────────────────────────"
    cat "${OUTDIR}/ssl/header_analysis.txt" 2>/dev/null || echo "N/A"
    echo ""
 
    echo "── EMAILS FOUND ────────────────────────────────────────────────"
    cat "${OUTDIR}/metadata/emails_found.txt" 2>/dev/null | head -20 || echo "N/A"
    echo ""
 
    echo "── NUCLEI FINDINGS ─────────────────────────────────────────────"
    cat "${OUTDIR}/vuln/nuclei_findings.txt" 2>/dev/null | head -40 || echo "None"
    echo ""
 
    echo "── DIRECTORIES FOUND ───────────────────────────────────────────"
    grep -E "Status: (200|301|302)" \
      "${OUTDIR}/web/gobuster_dirs.txt" 2>/dev/null | head -30 || echo "N/A"
    echo ""
 
    if [[ "${IS_WORDPRESS}" == "true" ]]; then
      echo "── WORDPRESS ───────────────────────────────────────────────────"
      echo "  [Version]"
      cat "${OUTDIR}/wordpress/wp_version.txt" 2>/dev/null | head -20
      echo ""
      echo "  [Users]"
      grep -E "author=|slug|name" \
        "${OUTDIR}/wordpress/wp_users.txt" 2>/dev/null | head -15 || echo "  N/A"
      echo ""
      echo "  [Accessible Sensitive Paths]"
      grep "\[200\]\|\[301\]\|\[302\]" \
        "${OUTDIR}/wordpress/wp_sensitive_paths.txt" 2>/dev/null | head -20 \
        || echo "  None found"
      echo ""
      echo "  [WPScan Highlights]"
      grep -E "\[!\]|\[\+\]|Vulnerability|Plugin|Theme|User|Version" \
        "${OUTDIR}/wordpress/wpscan_full.txt" 2>/dev/null | head -30 || echo "  N/A"
      echo ""
    fi
 
    echo "── OUTPUT STRUCTURE ────────────────────────────────────────────"
    echo "  ${OUTDIR}/"
    echo "  ├── dns/           DNS records, AXFR, subdomain discovery"
    echo "  ├── network/       masscan→nmap pipeline, service scripts"
    echo "  ├── web/           Fingerprint, WAF, nikto, gobuster, ffuf"
    echo "  ├── ssl/           Ciphers, cert, security headers"
    echo "  ├── osint/         WHOIS, theHarvester, crt.sh"
    echo "  ├── metadata/      Emails, links, exiftool"
    echo "  ├── vuln/          nuclei, searchsploit, sqlmap, hydra"
    echo "  ├── wordpress/     Full WP recon (if detected)"
    echo "  ├── raw/           Page sources"
    echo "  ├── SUMMARY.txt    This file"
    echo "  └── reconledger.log Full execution log"
    echo ""
    echo "  Full log → ${LOGFILE}"
    echo "================================================================"
 
  } | tee "${SUMMARY}"
 
  log "Summary → ${SUMMARY}"
}
 
# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
main() {
  banner
 
  log "Target        : ${TARGET}"
  log "Mode          : ${MODE}"
  log "Output dir    : ${OUTDIR}"
  log "Log file      : ${LOGFILE}"
  log "Started at    : $(date)"
  echo "---" | tee -a "${LOGFILE}"
 
  check_and_install_tools   # Phase 1  — tool check & install
  resolve_target            # Phase 2  — IP resolution
  cdn_waf_detection         # Phase 3  — CDN/WAF check (before active traffic)
  passive_osint             # Phase 4  — WHOIS, theHarvester, crt.sh (passive)
  dns_enum                  # Phase 5  — DNS records, AXFR, subdomain discovery
  network_scan              # Phase 6  — masscan → targeted nmap
  service_scripts           # Phase 7  — port-gated service scripts
  web_fingerprint           # Phase 8  — whatweb, wafw00f
  web_content_discovery     # Phase 9  — gobuster, ffuf, nikto, probes
  ssl_analysis              # Phase 10 — sslscan, cert, header audit
  metadata_extraction       # Phase 11 — emails, links, exiftool
  wordpress_recon           # Phase 12 — WordPress detection + full WP suite
  vuln_identification       # Phase 13 — nuclei, searchsploit, sqlmap, hydra
  generate_summary          # Phase 14 — consolidated summary
 
  echo -e "\n${GREEN}${BOLD}[+] ReconLedger v1 — Scan Complete${NC}"
  echo -e "${CYAN}  Results  → ${OUTDIR}/${NC}"
  echo -e "${CYAN}  Summary  → ${SUMMARY}${NC}"
  [[ "${IS_WORDPRESS}" == "true" ]] && echo -e "${MAGENTA}  WordPress → ${OUTDIR}/wordpress/${NC}"
  [[ "${BEHIND_CDN}"   == "true" ]] && echo -e "${YELLOW}  CDN/WAF detected — review cdn_check.txt before acting on port scan results.${NC}"
  log "Finished at   : $(date)"
 
  echo ""
  echo -e "${CYAN}${BOLD}Generate HTML report now? [y/N]:${NC} \c"
  read -r REPORT_ANSWER
  if [[ "${REPORT_ANSWER,,}" == "y" || "${REPORT_ANSWER,,}" == "yes" ]]; then
    if command -v python3 &>/dev/null && [[ -f "$(dirname "$0")/reconledger_report.py" ]]; then
      log "Launching reconledger_report.py..."
      python3 "$(dirname "$0")/reconledger_report.py" "${OUTDIR}"
    else
      warn "reconledger_report.py not found in the same directory as this script."
      warn "Run manually: python3 reconledger_report.py ${OUTDIR}"
    fi
  else
    info "Skipped. To generate report later:"
    info "  python3 reconledger_report.py ${OUTDIR}"
  fi
}
 
main "$@"
