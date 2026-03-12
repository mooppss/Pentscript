# Defensive Web Security Assessment — Workflow Document

---

## Legal Notice and Scope

**WRITTEN AUTHORIZATION REQUIRED.** Use this workflow and the associated automation **only** on assets that you **own** or for which you have **explicit written authorization** to assess. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

**Scope:** Reconnaissance, asset inventory, DNS review, exposed-service discovery, HTTP/TLS/security-header analysis, passive and light-touch URL collection, historical URL intelligence, JS/API surface analysis, screenshotting, technology fingerprinting, and safe template-based misconfiguration checks. **No exploitation, payload delivery to targets, persistence, phishing, malware, privilege escalation, or denial-of-service.** No credential attacks, brute force, or destructive testing.

---

## Honesty Disclaimer

**No scan can guarantee complete detection.** Results depend on scope, permissions, available tooling, and target behavior. This automation provides **triage and coverage support** and is **not a substitute for manual expert review**. Always validate findings and apply professional judgment.

---

## Project Overview

### Purpose

- Automate the **authorized, defensive** portion of a web security assessment with broad, correlated coverage.
- Prefer **overlap for validation and correlation**, not redundancy for noise.
- Produce structured outputs (raw + cleaned), logs, normalized findings, and final reports with defender next-steps guidance.

### What the automation DOES

- Scope initialization, dependency checks, dry-run, **noisiness mode** (passive | balanced | thorough-safe), **rate/safety controls** (concurrency, timeout, jitter, optional exclusion/allowlist).
- Passive OSINT and subdomain collection; DNS and infrastructure review (dnsx, dig); live host validation and metadata (httpx, whatweb, wafw00f).
- Historical and passive URL expansion (waybackurls, gau, waymore); conservative content discovery (optional); JS and API surface analysis.
- Specific safe checks: robots.txt, sitemap.xml, .well-known/, security.txt, crossdomain.xml, clientaccesspolicy.xml, swagger/openapi/api-docs, graphql/graphiql, login/signin, admin/dashboard, debug/actuator/health/metrics/version, backup extensions in passive data only (.bak, .old, .zip, .tar, .gz, .sql, .env, .log, .conf).
- TLS/certificate review; security header and cookie review; **safe nuclei only** (exposures, misconfig, default-logins identification, takeovers passive); service exposure review; findings correlation and normalization.
- Reporting: executive summary, technical findings, host inventory CSV/TSV, prioritized remediation checklist.
- (Optional) **Exploitation preparation artifacts only**: create notes/checklists and run exploit *research* helpers (e.g. `searchsploit --nmap`) against collected scan outputs. This does **not** exploit targets.

### What the automation does NOT do

- No exploitation, payload delivery to targets, persistence, phishing, malware, privilege escalation, DoS, credential attacks, brute force, or destructive testing.
- No aggressive path spraying, parameter fuzzing, recursive aggressive crawling, or high-risk nuclei/authenticated templates.
- Note: Some scripts can optionally **generate payload files locally** for authorized testing workflows. They are **not executed** or delivered automatically; treat them as training/ops artifacts and keep them out of shared repos.

---

## Notes for `webapp_pentest.sh` (this repo)

`webapp_pentest.sh` is a practical recon + scanning script with a single timestamped output folder (e.g. `pentest-output-YYYYMMDD_HHMMSS/`).

- **Output hardening**
  - Subdomain/host list is sanitized to avoid ANSI/graph-output corruption.
  - Unresolvable hostnames are skipped to reduce empty result files.
  - Tool calls use timeouts where possible to prevent hangs.
- **Optional exploitation prep**
  - `--exploitation-prep` writes `exploitation/` artifacts (notes + searchsploit outputs).
  - `--generate-payloads` additionally generates example payload files locally (requires `msfvenom`).

---

## Folder Structure

Output is organized under a timestamped run directory: `[base]/[domain]/[YYYYMMDD_HHMMSS]/`.

| Folder | Contents |
|--------|----------|
| `00_scope/` | Scope file, allowlist/exclusion list, run metadata (e.g. MODE). |
| `01_passive_osint/` | Raw OSINT: crt.sh, passive subdomain sources (per-tool files). |
| `02_dns/` | Per-host DNS: A, AAAA, CNAME, MX, NS, TXT; dangling CDN/WAF clues (dnsx, dig). |
| `03_subdomains/` | Merged and deduplicated subdomain lists (raw + cleaned). |
| `04_live_hosts/` | httpx results: live URLs, status code, title, tech, IP, cname, redirect chain. |
| `05_http_metadata/` | Titles, WAF, whatweb, server banners, redirects (raw + summary). |
| `06_screenshots/` | gowitness screenshots; optional per-host markdown summary. |
| `07_archives/` | waybackurls, gau, waymore raw; deduped URLs by extension/path; interesting_paths. |
| `08_crawling/` | katana/hakrawler safe crawl output. |
| `09_content_discovery/` | Optional feroxbuster/ffuf/dirsearch conservative output (raw + cleaned). |
| `10_js_analysis/` | Collected JS URLs, extracted endpoints, API/GraphQL/auth indicators. |
| `11_api_surface/` | Identified API routes, docs, GraphQL, Swagger, auth endpoints; safe_path_checks. |
| `12_ports/` | naabu/nmap results; web vs non-web; per-host. |
| `13_tls/` | testssl/openssl/sslyze; cert expiry, SANs, weak cipher flags. |
| `14_headers/` | Security header and cookie review; CORS/CSP summary. |
| `15_nuclei_safe/` | Nuclei raw + normalized (exposures, misconfig, default-logins, takeovers only). |
| `16_service_fingerprints/` | Service/version mapping per host. |
| `17_findings/` | Normalized findings (CSV/JSON); deduplicated, with evidence path. |
| `18_reports/` | Executive summary, technical report, host inventory, remediation checklist. |
| `logs/` | Phase logs, command log, main run log. |
| `tmp/` | Temporary merged lists, resume markers. |

---

## Tooling (Overlap for Validation, Not Noise)

- **DNS:** dnsx, dig, nslookup; dnsrecon (safe enum only).
- **Subdomain:** assetfinder, subfinder, amass passive, crt.sh.
- **Web probe:** httpx, whatweb, wafw00f; aquatone optional.
- **Archive/URL:** waybackurls, gau, waymore; hakrawler; sitemap via curl.
- **Content discovery:** feroxbuster/ffuf/dirsearch conservative only (low rate, small wordlist).
- **Secrets:** trufflehog passive only; gf/grep on collected content.
- **TLS:** testssl.sh, openssl, sslyze.
- **Ports:** naabu, nmap; nikto low-risk only with documented limits.
- **Cloud/storage:** Pattern match in HTML/JS (S3, GCS, etc.); no exploitation.
- **JS:** linkfinder or equivalent; extract API/GraphQL/auth.
- **Visual:** gowitness; optional per-host markdown.
- **Processing:** curl, jq, anew, sort, awk, sed.

---

## Noisiness and Rate/Safety Controls

### Modes

- **passive** — No active path discovery; mostly passive collection and probing (no katana crawl).
- **balanced** — Light crawling and conservative checks (default).
- **thorough-safe** — More complete but still non-destructive and rate-limited.

Select with `--mode passive|balanced|thorough-safe`.

### Rate and safety

- Configurable **concurrency** (e.g. httpx threads).
- Configurable **request timeout** (HTTP timeout in seconds).
- **Sleep/jitter** between heavier operations (e.g. between batch requests to archives).
- Optional **exclusion list** (file of subdomains to exclude).
- Optional **allowlist** (file of in-scope subdomains only).

---

## Scanning Phase — Sub-Phases A–J

### A. DNS and Infrastructure Review

**Objective:** Resolve and record DNS for discovered hosts; identify dangling CNAME and CDN/WAF clues.

**Tools:** dnsx, dig (fallback).

**Commands (representative):**
- `dnsx -l subdomains.txt -a -aaaa -cname -mx -ns -txt -silent -o 02_dns/dnsx.txt`
- `dig +short A <host>`

**Output:** `02_dns/dnsx.txt` (or per-host files). **Interpretation:** Missing A/AAAA with CNAME may indicate dangling DNS. **Defender:** Verify CNAME targets; deprovision or reclaim services.

---

### B. Web Host Validation and Metadata

**Objective:** Probe all hosts; record status code, title, technologies, redirect chain, IP, cname, server header.

**Tools:** httpx (primary).

**Commands:** `httpx -l subdomains.txt -sc -title -tech-detect -status-code -ip -cname -follow-redirects -silent -timeout N -threads M -o 04_live_hosts/httpx_full.txt`

**Output:** `04_live_hosts/`, `05_http_metadata/`. **Interpretation:** Separate live, redirected, forbidden, error. **Defender:** Retire or fix redirect chains; restrict or remove unnecessary hosts.

---

### C. Historical and Passive URL Expansion

**Objective:** Collect historical and passive URLs; deduplicate; identify interesting paths and backup extensions (passive only).

**Tools:** waybackurls, gau, waymore; katana in balanced/thorough-safe.

**Commands:** `echo domain | waybackurls`, `gau --threads 1 domain`, waymore if available; merge and `unfurl paths`; grep for interesting paths and backup extensions (.bak, .old, .zip, .tar, .gz, .sql, .env, .log, .conf) in passive data only.

**Output:** `07_archives/`, `08_crawling/`. **Interpretation:** High-value paths (admin, api, graphql, login, actuator, etc.) and sensitive extensions. **Defender:** Check if resources are still reachable; remove or protect; purge caches if needed.

---

### D. Conservative Content Discovery (Optional)

**Objective:** Low-rate path discovery only; no parameter fuzzing or recursive aggressive crawl.

**Tools:** feroxbuster, ffuf, or dirsearch in strict limits.

**Commands (example):** `feroxbuster -u <base> -w wordlist_small.txt -t 2 -d 1 --rate-limit 5`. Only in thorough-safe; mark optional in production.

**Output:** `09_content_discovery/`. **Defender:** Restrict or remove exposed paths; align with business need.

---

### E. JavaScript and API Surface Analysis

**Objective:** Collect JS URLs; extract endpoints; identify API routes, GraphQL, Swagger/OpenAPI, auth endpoints.

**Tools:** linkfinder or equivalent; grep/parse on collected JS and crawl output.

**Output:** `10_js_analysis/`, `11_api_surface/`. **Defender:** Restrict API/docs; remove secrets from client bundles; rotate any exposed tokens.

---

### F. TLS / Certificate / HTTPS Review

**Objective:** Protocol support, weak cipher/config flags where detectable, cert expiry, SANs; mixed-content/redirect-to-http if observed.

**Tools:** testssl.sh, openssl s_client, optional sslyze.

**Commands:** `testssl.sh --jsonfile=out.json https://host` or `openssl s_client -connect host:443 -servername host` then `openssl x509 -noout -dates -subject -issuer`.

**Output:** `13_tls/`. **Defender:** Renew expiring certs; enforce TLS 1.2+; disable weak ciphers; fix HSTS.

---

### G. Security Header and Cookie Review

**Objective:** Missing headers; insecure cookie flags; CORS/CSP indicators from response headers only.

**Tools:** curl.

**Commands:** `curl -sI -L -m N "URL"`; grep for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Set-Cookie, Access-Control.

**Output:** `14_headers/headers_summary.txt` and per-host files. **Defender:** Configure HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; secure cookie flags.

---

### H. Safe Template-Based Misconfiguration Checks (Nuclei)

**Objective:** Identify exposures, misconfigurations, default-login panels (identification only), default pages, exposed dashboards/docs, passive takeover indicators. **No intrusive or exploit templates.**

**Allowed:** `exposures/`, `misconfigurations/`, `default-logins/` (identification only), default pages, exposed dashboards/docs, `takeovers/` (passive/low-risk). **Disallowed:** `exploits/`, fuzzing, intrusive, authenticated workflows, destructive templates.

**Commands:** `nuclei -l urls -t exposures/ -t misconfigurations/ -t default-logins/ -t takeovers/ -severity info,low,medium -no-color -rate-limit 30`. Update templates with `nuclei -update-templates`.

**Output:** `15_nuclei_safe/nuclei_raw.txt`. **Defender:** Remediate per template; restrict panels; fix misconfigs; verify takeover indicators.

---

### I. Service Exposure Review

**Objective:** Classify open ports; identify unexpected admin services; version leakage; map service to host.

**Tools:** naabu, nmap (safe flags only).

**Output:** `12_ports/`, `16_service_fingerprints/`. **Defender:** Validate business need; firewall or restrict unnecessary services; reduce version leakage.

---

### J. Findings Correlation

**Objective:** Correlate DNS + HTTP + TLS + ports + historical URLs + screenshots + nuclei; deduplicate; one normalized finding per issue.

**Output:** `17_findings/` (CSV/JSON) with: title, category, affected host, source tool, severity (info/low/medium), evidence path, short explanation, remediation, confidence. **Defender:** Use as prioritized remediation list; validate and fix each finding.

---

## Specific Safe Checks (Light-Touch)

The script explicitly checks (e.g. via curl or collected URLs) for:

- `/robots.txt`, `/sitemap.xml`, `/.well-known/`, `/security.txt`
- `/crossdomain.xml`, `/clientaccesspolicy.xml`
- `/swagger`, `/swagger-ui`, `/openapi.json`, `/api-docs`
- `/graphql`, `/graphiql`
- `/login`, `/signin`, `/admin`, `/dashboard`, `/debug`, `/actuator`, `/health`, `/metrics`, `/version`

Backup/sensitive extensions (`.bak`, `.old`, `.zip`, `.tar`, `.gz`, `.sql`, `.env`, `.log`, `.conf`) are identified **only from passive/archived URL data**, not aggressive probing.

---

## Findings Normalization

Each finding includes:

- **title** — Short description.
- **category** — e.g. Headers, Template, TLS.
- **affected_host** — Domain/host.
- **source_tool** — e.g. nuclei, curl.
- **severity** — info | low | medium (unless strong evidence for higher).
- **evidence_path** — Path to file or output.
- **explanation** — Short technical note.
- **remediation** — Defensive action.
- **confidence** — high | medium | low.

---

## Reporting

Generated in `18_reports/`:

- **EXECUTIVE_SUMMARY.md** — Scope, mode, run dir, triage disclaimer, pointer to technical findings and remediation.
- **TECHNICAL_FINDINGS.md** — Pointers to host inventory, headers, TLS, nuclei, interesting paths, safe path checks, findings CSV.
- **host_inventory.csv** — url, status_code, title, tech.
- **REMEDIATION_CHECKLIST.md** — Prioritized checklist (headers, TLS, exposed paths, ports, nuclei, findings).

---

## Defender Follow-Up (Per Finding Type)

| Finding type | Defender action |
|--------------|-----------------|
| Exposed documentation | Restrict access (IP/VPN/auth); remove or move to internal. |
| Public admin panel | Restrict by IP, SSO, VPN; change defaults; add MFA. |
| Version leakage | Disable or generic server banners; patch and hide version. |
| Risky HTTP methods | Disable unnecessary methods at proxy/app. |
| Missing TLS hardening | Enforce TLS 1.2+; disable weak ciphers; HSTS. |
| Missing security headers | Configure HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. |
| Dangling DNS / takeover indicator | Verify CNAME target; deprovision or reclaim service. |
| Public storage reference | Confirm bucket/resource is intended public; restrict if not. |
| Sensitive archived endpoint | Check if still reachable; remove or protect; purge caches. |
| Exposed debug/health endpoint | Restrict to internal/monitoring; remove or auth in prod. |
| Possible secret in public JS | Rotate exposed secrets; remove from client bundles. |
| Unusual open service | Validate business need; firewall or restrict. |
| Default page / default panel | Change defaults; restrict access; disable if unused. |
| Takeover indicator | Same as dangling DNS; reclaim or deprovision. |

---

## Package Install (Kali-Friendly)

```bash
# Go tools (core)
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/sensepost/gowitness@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# apt
sudo apt update && sudo apt install -y nmap whatweb jq curl openssl bind9-dnsutils
# Optional: amass, wafw00f, waymore, testssl.sh (clone/install separately)
# nuclei: nuclei -update-templates
```

---

*End of workflow document.*
