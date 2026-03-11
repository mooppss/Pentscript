#!/usr/bin/env bash
# =============================================================================
# DEFENSIVE WEB SECURITY ASSESSMENT - KALI LINUX AUTOMATION (REVISED)
# =============================================================================
# LEGAL: Use ONLY on assets you OWN or have EXPLICIT WRITTEN AUTHORIZATION
#        to assess. Unauthorized access is illegal.
# SCOPE: Recon, DNS, fingerprinting, headers, TLS, safe misconfig, no exploitation.
# =============================================================================
set -euo pipefail
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# -----------------------------------------------------------------------------
# Configuration (noisiness + rate/safety)
# -----------------------------------------------------------------------------
DOMAIN=""
BASE_DIR=""
RUN_DIR=""
DRY_RUN=false
RESUME=false
MODE="balanced"                    # passive | balanced | thorough-safe
RATE_LIMIT_DELAY=2
HTTP_TIMEOUT=15
THREADS=5
EXCLUDE_FILE=""
ALLOWLIST_FILE=""
LOG_FILE=""
COMMAND_LOG=""
export PATH="${PATH}:${HOME}/go/bin:/usr/local/go/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()    { echo -e "${BLUE}[*]${NC} $*" | tee -a "$LOG_FILE"; }
ok()     { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG_FILE"; }
err()    { echo -e "${RED}[-]${NC} $*" | tee -a "$LOG_FILE"; }
phase()  { echo -e "\n${GREEN}=== $* ===${NC}" | tee -a "$LOG_FILE"; }

usage() {
  cat << EOF
Usage: $SCRIPT_NAME -d <domain> [options]
Defensive web assessment: recon, DNS, fingerprinting, headers, TLS, safe checks only.

  -d, --domain DOMAIN   Target domain (required)
  -o, --output DIR      Base output directory (default: current dir)
  -m, --mode MODE       passive | balanced | thorough-safe (default: balanced)
  -t, --threads N       Concurrency for httpx/probes (default: 5)
  -T, --timeout N       HTTP timeout seconds (default: 15)
  -s, --rate-delay N    Sleep between batch requests (default: 2)
  -e, --exclude-file F  File with subdomains to exclude (one per line)
  -a, --allowlist-file F File with allowed subdomains only (one per line)
  -n, --dry-run         Check deps and create dirs only
  -r, --resume          Skip phases that already have output
  -h, --help            This help

Requires: written authorization for the target domain.
EOF
}

check_deps() {
  phase "Dependency check"
  local required=(assetfinder subfinder httpx gowitness waybackurls unfurl naabu nuclei curl jq sort awk sed)
  local missing=()
  for cmd in "${required[@]}"; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    err "Missing required: ${missing[*]}"
    return 1
  fi
  for cmd in dnsx katana gau; do command -v "$cmd" &>/dev/null && log "Optional present: $cmd" || warn "Optional missing: $cmd (phase will degrade)"; done
  ok "Required tools OK"
  return 0
}

validate_domain() {
  local d="$1"
  if [[ -z "$d" ]]; then
    err "Domain is required"
    return 1
  fi
  if [[ "$d" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
    return 0
  fi
  err "Invalid domain: $d"
  return 1
}

setup_dirs() {
  local base="$1" domain="$2"
  local ts
  ts=$(date +%Y%m%d_%H%M%S)
  RUN_DIR="${base}/${domain}/${ts}"
  for sub in 00_scope 01_passive_osint 02_dns 03_subdomains 04_live_hosts 05_http_metadata 06_screenshots 07_archives 08_crawling 09_content_discovery 10_js_analysis 11_api_surface 12_ports 13_tls 14_headers 15_nuclei_safe 16_service_fingerprints 17_findings 18_reports logs tmp; do
    mkdir -p "${RUN_DIR}/${sub}"
  done
  LOG_FILE="${RUN_DIR}/logs/run.log"
  COMMAND_LOG="${RUN_DIR}/logs/commands.log"
  echo "# Scope: $domain - $(date -Iseconds)" > "${RUN_DIR}/00_scope/scope.txt"
  echo "$domain" >> "${RUN_DIR}/00_scope/scope.txt"
  echo "MODE=$MODE" >> "${RUN_DIR}/00_scope/scope.txt"
  ok "Run directory: $RUN_DIR"
}

run_cmd() { echo "$(date -Iseconds) $*" >> "$COMMAND_LOG"; "$@"; }

# Phase: Passive subdomain collection
phase_subdomains() {
  local domain="$1"
  local out_osint="${RUN_DIR}/01_passive_osint"
  local out_sub="${RUN_DIR}/03_subdomains"
  local raw="${RUN_DIR}/tmp/subdomains_raw.txt"
  local master="${out_sub}/subdomains_all.txt"
  [[ -f "$master" && "$RESUME" == true ]] && { ok "Resume: subdomains exist"; return 0; }
  : > "$raw"
  log "crt.sh"
  run_cmd curl -sS "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -v '^$' >> "$raw" || true
  sleep "$RATE_LIMIT_DELAY"
  if command -v assetfinder &>/dev/null; then log "assetfinder"; run_cmd assetfinder --subs-only "$domain" >> "$raw" 2>/dev/null || true; fi
  if command -v subfinder &>/dev/null; then log "subfinder"; run_cmd subfinder -d "$domain" -all -silent >> "$raw" 2>/dev/null || true; fi
  if command -v amass &>/dev/null; then log "amass (passive)"; run_cmd amass enum -passive -d "$domain" -o "${out_osint}/amass.txt" 2>/dev/null || true; [[ -f "${out_osint}/amass.txt" ]] && cat "${out_osint}/amass.txt" >> "$raw"; fi
  sort -u "$raw" | sed "/^\\*\\./d;/^$/d" | sort -u > "${RUN_DIR}/tmp/subdomains_merged.txt"
  if [[ -n "$EXCLUDE_FILE" && -f "$EXCLUDE_FILE" ]]; then grep -vFf "$EXCLUDE_FILE" "${RUN_DIR}/tmp/subdomains_merged.txt" > "$master" || cp "${RUN_DIR}/tmp/subdomains_merged.txt" "$master"; else cp "${RUN_DIR}/tmp/subdomains_merged.txt" "$master"; fi
  if [[ -n "$ALLOWLIST_FILE" && -f "$ALLOWLIST_FILE" ]]; then grep -Ff "$ALLOWLIST_FILE" "$master" > "${RUN_DIR}/tmp/allowlisted.txt" && mv "${RUN_DIR}/tmp/allowlisted.txt" "$master"; fi
  local count; count=$(wc -l < "$master")
  ok "Subdomains: $count"
}

# Phase: DNS and infrastructure (optional: dnsx)
phase_dns() {
  local list="${RUN_DIR}/03_subdomains/subdomains_all.txt"
  local out="${RUN_DIR}/02_dns"
  [[ ! -f "$list" ]] && return 0
  [[ -f "${out}/dnsx.txt" && "$RESUME" == true ]] && { ok "Resume: DNS exist"; return 0; }
  if command -v dnsx &>/dev/null; then
    log "dnsx (A, AAAA, CNAME, MX, NS, TXT)"
    run_cmd dnsx -l "$list" -a -aaaa -cname -mx -ns -txt -silent -o "${out}/dnsx.txt" 2>/dev/null || true
  else
    log "dig (fallback for root domain)"
    run_cmd dig +short A "$DOMAIN" 2>/dev/null > "${out}/dig_A.txt" || true
  fi
  ok "DNS in 02_dns/"
}

# Phase: Live host validation and metadata
phase_live_hosts() {
  local list="${RUN_DIR}/03_subdomains/subdomains_all.txt"
  local out="${RUN_DIR}/04_live_hosts"
  local meta="${RUN_DIR}/05_http_metadata"
  local urls="${out}/live_urls.txt"
  [[ -f "$urls" && "$RESUME" == true ]] && { ok "Resume: live hosts exist"; return 0; }
  [[ ! -f "$list" ]] && { warn "No subdomains list"; return 0; }
  log "Probing with httpx (threads=$THREADS)"
  run_cmd httpx -l "$list" -sc -title -tech-detect -status-code -ip -cname -follow-redirects -silent -timeout "$HTTP_TIMEOUT" -threads "$THREADS" -o "${out}/httpx_full.txt" 2>/dev/null || true
  grep -E '^https?://' "${out}/httpx_full.txt" 2>/dev/null | awk '{print $1}' | sort -u > "$urls" || true
  cp "${out}/httpx_full.txt" "${meta}/httpx_tech.txt" 2>/dev/null || true
  ok "Live hosts in ${out}/httpx_full.txt"
}

# Phase: Screenshots
phase_screenshots() {
  local urls="${RUN_DIR}/04_live_hosts/live_urls.txt"
  local out="${RUN_DIR}/06_screenshots"
  [[ ! -f "$urls" ]] && { warn "No live URLs"; return 0; }
  log "Screenshotting with gowitness"
  run_cmd gowitness file -f "$urls" -P "${out}/screenshots" --disable-db 2>/dev/null || true
  ok "Screenshots in ${out}/screenshots"
}

# Phase: Historical and passive URL expansion (07_archives, 08_crawling)
phase_archives() {
  local urls="${RUN_DIR}/04_live_hosts/live_urls.txt"
  local out_arch="${RUN_DIR}/07_archives"
  local out_crawl="${RUN_DIR}/08_crawling"
  [[ ! -f "$urls" ]] && return 0
  : > "${out_arch}/wayback_raw.txt"
  while IFS= read -r u; do
    domain=$(echo "$u" | unfurl domains 2>/dev/null | head -1)
    [[ -z "$domain" ]] && continue
    echo "$domain" | waybackurls 2>/dev/null >> "${out_arch}/wayback_raw.txt" || true
    if command -v gau &>/dev/null; then echo "$domain" | gau --threads 1 2>/dev/null >> "${out_arch}/gau_raw.txt" || true; fi
    sleep "$RATE_LIMIT_DELAY"
  done < "$urls"
  sort -u "${out_arch}/wayback_raw.txt" 2>/dev/null > "${out_arch}/wayback_unique.txt" || true
  if [[ "$MODE" != "passive" ]] && command -v katana &>/dev/null; then
    log "Crawling with katana"
    run_cmd katana -u "$urls" -d 2 -jc -kf all -silent -o "${out_crawl}/katana_crawl.txt" 2>/dev/null || true
  else
    : > "${out_crawl}/katana_crawl.txt"
  fi
  cat "${out_crawl}/katana_crawl.txt" "${out_arch}/wayback_unique.txt" 2>/dev/null | sort -u | unfurl paths 2>/dev/null | sort -u > "${out_arch}/paths_all.txt" || true
  INTERESTING_PATHS="/robots.txt /sitemap.xml /.well-known/ /security.txt /crossdomain.xml /clientaccesspolicy.xml /swagger /swagger-ui /openapi.json /api-docs /graphql /graphiql /login /signin /admin /dashboard /debug /actuator /health /metrics /version"
  for path in $INTERESTING_PATHS; do grep -F "$path" "${out_arch}/paths_all.txt" 2>/dev/null >> "${out_arch}/interesting_paths.txt" || true; done
  for ext in .bak .old .zip .tar .gz .sql .env .log .conf; do grep -F "$ext" "${out_arch}/paths_all.txt" 2>/dev/null >> "${out_arch}/interesting_paths.txt" || true; done
  sort -u "${out_arch}/interesting_paths.txt" 2>/dev/null > "${RUN_DIR}/tmp/interesting_dedup.txt" && mv "${RUN_DIR}/tmp/interesting_dedup.txt" "${out_arch}/interesting_paths.txt" 2>/dev/null || true
  ok "Archives and paths in 07_archives/ and 08_crawling/"
}

# Phase: Safe path checks (light-touch: robots, sitemap, .well-known, etc.)
phase_safe_path_checks() {
  local urls="${RUN_DIR}/04_live_hosts/live_urls.txt"
  local out="${RUN_DIR}/11_api_surface"
  [[ ! -f "$urls" ]] && return 0
  local base_paths="/robots.txt /sitemap.xml /.well-known/security.txt /crossdomain.xml /clientaccesspolicy.xml /swagger /openapi.json /api-docs /graphql /graphiql /login /admin /actuator /health /metrics /version"
  : > "${out}/safe_path_checks.txt"
  while IFS= read -r base_url; do
    for path in $base_paths; do
      url="${base_url%/}$path"
      code=$(curl -sS -o /dev/null -w "%{http_code}" -m "$HTTP_TIMEOUT" "$url" 2>/dev/null || echo "000")
      echo "$url $code" >> "${out}/safe_path_checks.txt"
      sleep "$RATE_LIMIT_DELAY"
    done
  done < "$urls"
  ok "Safe path checks in 11_api_surface/safe_path_checks.txt"
}

# Phase: HTTP metadata (whatweb/wafw00f optional, may be noisy)
phase_http_metadata() {
  local out="${RUN_DIR}/05_http_metadata"
  cp "${RUN_DIR}/04_live_hosts/httpx_full.txt" "${out}/httpx_tech.txt" 2>/dev/null || true
  ok "HTTP metadata in 05_http_metadata/"
}

# Phase: Port and service discovery (safe ports only)
phase_ports() {
  local list="${RUN_DIR}/04_live_hosts/live_urls.txt"
  local out="${RUN_DIR}/12_ports"
  local sf="${RUN_DIR}/16_service_fingerprints"
  [[ ! -f "$list" ]] && return 0
  sed 's|^https\?://||;s|/.*||' "$list" | sort -u > "${RUN_DIR}/tmp/hosts_for_ports.txt"
  log "Naabu on common web ports"
  run_cmd naabu -l "${RUN_DIR}/tmp/hosts_for_ports.txt" -p 80,443,8080,8443,8000,3000,9443 -silent -o "${out}/naabu_ports.txt" 2>/dev/null || true
  cp "${out}/naabu_ports.txt" "${sf}/open_ports.txt" 2>/dev/null || true
  ok "Ports in 12_ports/"
}

# Phase: TLS / certificate review
phase_tls() {
  local urls="${RUN_DIR}/04_live_hosts/live_urls.txt"
  local out="${RUN_DIR}/13_tls"
  [[ ! -f "$urls" ]] && return 0
  while IFS= read -r u; do
    host=$(echo "$u" | sed 's|^https\?://||;s|/.*||')
    [[ -z "$host" ]] && continue
    safe=$(echo "$host" | sed 's/[^a-zA-Z0-9.-]/_/g')
    echo | timeout 5 openssl s_client -connect "${host}:443" -servername "$host" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null > "${out}/${safe}.txt" || true
    sleep "$RATE_LIMIT_DELAY"
  done < "$urls"
  ok "TLS in 13_tls/"
}

# Phase: Security header and cookie review
phase_headers() {
  local urls="${RUN_DIR}/04_live_hosts/live_urls.txt"
  local out="${RUN_DIR}/14_headers"
  local sum="${out}/headers_summary.txt"
  [[ ! -f "$urls" ]] && return 0
  echo "# Security header summary - $(date -Iseconds)" > "$sum"
  while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    safe=$(echo "$u" | sed 's/[^a-zA-Z0-9.-]/_/g')
    curl -sI -L -m "$HTTP_TIMEOUT" "$u" 2>/dev/null > "${out}/${safe}.txt" || true
    { echo "--- $u ---"; grep -iE '^(strict-transport-security|x-frame-options|x-content-type-options|content-security-policy|referrer-policy|permissions-policy|set-cookie|access-control):' "${out}/${safe}.txt" 2>/dev/null || echo "No security headers"; } >> "$sum"
    sleep "$RATE_LIMIT_DELAY"
  done < "$urls"
  ok "Headers in 14_headers/"
}

# Phase: Safe nuclei (exposures, misconfig, default-logins id only, takeovers passive; no exploits)
phase_nuclei() {
  local urls="${RUN_DIR}/04_live_hosts/live_urls.txt"
  local out="${RUN_DIR}/15_nuclei_safe"
  [[ ! -f "$urls" ]] && return 0
  log "Nuclei (safe templates only: exposures, misconfigurations, default-logins, takeovers; severity info,low,medium)"
  run_cmd nuclei -l "$urls" -t exposures/ -t misconfigurations/ -t default-logins/ -t takeovers/ -severity info,low,medium -no-color -silent -o "${out}/nuclei_raw.txt" -rate-limit 30 2>/dev/null || true
  ok "Nuclei in 15_nuclei_safe/"
}

# Phase: JS and API surface (collect JS URLs from crawl/archives)
phase_js_analysis() {
  local out_js="${RUN_DIR}/10_js_analysis"
  local out_api="${RUN_DIR}/11_api_surface"
  cat "${RUN_DIR}/08_crawling/katana_crawl.txt" "${RUN_DIR}/07_archives/wayback_unique.txt" 2>/dev/null | grep -E '\.js(\?|$)' | sort -u > "${out_js}/js_urls.txt" || true
  cat "${RUN_DIR}/07_archives/interesting_paths.txt" 2>/dev/null > "${out_api}/identified_endpoints.txt" || true
  ok "JS URLs and API surface in 10_js_analysis/ and 11_api_surface/"
}

# Phase: Findings correlation and normalization (title, category, host, source, severity, evidence, remediation, confidence)
phase_findings_correlation() {
  local out="${RUN_DIR}/17_findings"
  echo "title,category,affected_host,source_tool,severity,evidence_path,explanation,remediation,confidence" > "${out}/findings.csv"
  if [[ -f "${RUN_DIR}/15_nuclei_safe/nuclei_raw.txt" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      echo "Nuclei finding,Template,$DOMAIN,nuclei,low,15_nuclei_safe/nuclei_raw.txt,$line,Review and remediate per template,medium" >> "${out}/findings.csv"
    done < "${RUN_DIR}/15_nuclei_safe/nuclei_raw.txt"
  fi
  if [[ -f "${RUN_DIR}/14_headers/headers_summary.txt" ]]; then
    echo "Missing or weak security headers,Headers,$DOMAIN,curl,info,14_headers/headers_summary.txt,Review headers_summary.txt,Configure HSTS/CSP/X-Frame-Options etc.,high" >> "${out}/findings.csv"
  fi
  ok "Findings in 17_findings/findings.csv"
}

# Phase: Final reports
phase_report() {
  local out="${RUN_DIR}/18_reports"
  local inv="${out}/host_inventory.csv"
  echo "url,status_code,title,tech" > "$inv"
  awk '{print $1","$2","$3","$4}' "${RUN_DIR}/04_live_hosts/httpx_full.txt" 2>/dev/null >> "$inv" || true
  cat > "${out}/TECHNICAL_FINDINGS.md" << EOF
# Technical Findings
- Host inventory: $inv
- Headers: 14_headers/headers_summary.txt
- TLS: 13_tls/
- Nuclei: 15_nuclei_safe/nuclei_raw.txt
- Interesting paths: 07_archives/interesting_paths.txt
- Safe path checks: 11_api_surface/safe_path_checks.txt
- Findings: 17_findings/findings.csv
EOF
  cat > "${out}/EXECUTIVE_SUMMARY.md" << EOF
# Executive Summary
Assessment of $DOMAIN completed at $(date -Iseconds). Mode: $MODE.
Output directory: $RUN_DIR
No scan guarantees complete detection; this is triage support, not a substitute for expert review.
Review TECHNICAL_FINDINGS.md and REMEDIATION_CHECKLIST.md.
EOF
  cat > "${out}/REMEDIATION_CHECKLIST.md" << EOF
# Remediation Checklist
- [ ] Review missing security headers (14_headers)
- [ ] Renew or fix expiring/weak TLS (13_tls)
- [ ] Restrict exposed admin/default paths (07_archives/interesting_paths.txt, 11_api_surface/safe_path_checks.txt)
- [ ] Validate open ports (12_ports) and firewall if not needed
- [ ] Address nuclei findings (15_nuclei_safe)
- [ ] Review 17_findings/findings.csv for correlated findings
EOF
  ok "Reports in 18_reports/"
}

main() {
  local base_dir="."
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) DOMAIN="$2"; shift 2 ;;
      -o|--output) base_dir="$2"; shift 2 ;;
      -m|--mode) MODE="$2"; shift 2 ;;
      -t|--threads) THREADS="$2"; shift 2 ;;
      -T|--timeout) HTTP_TIMEOUT="$2"; shift 2 ;;
      -s|--rate-delay) RATE_LIMIT_DELAY="$2"; shift 2 ;;
      -e|--exclude-file) EXCLUDE_FILE="$2"; shift 2 ;;
      -a|--allowlist-file) ALLOWLIST_FILE="$2"; shift 2 ;;
      -n|--dry-run) DRY_RUN=true; shift ;;
      -r|--resume) RESUME=true; shift ;;
      -h|--help) usage; exit 0 ;;
      *) err "Unknown option: $1"; usage; exit 1 ;;
    esac
  done
  if ! validate_domain "$DOMAIN"; then usage; exit 1; fi
  [[ "$MODE" != "passive" && "$MODE" != "balanced" && "$MODE" != "thorough-safe" ]] && { err "Mode must be passive, balanced, or thorough-safe"; exit 1; }
  BASE_DIR="$(cd "$base_dir" && pwd)"
  check_deps || exit 1
  setup_dirs "$BASE_DIR" "$DOMAIN"
  if [[ "$DRY_RUN" == true ]]; then ok "Dry run complete"; exit 0; fi
  phase_subdomains "$DOMAIN"
  phase_dns
  phase_live_hosts
  phase_http_metadata
  phase_screenshots
  phase_archives
  phase_safe_path_checks
  phase_js_analysis
  phase_ports
  phase_tls
  phase_headers
  phase_nuclei
  phase_findings_correlation
  phase_report
  ok "Assessment complete. Run dir: $RUN_DIR"
}

main "$@"
