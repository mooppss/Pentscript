## `webapp_pentest.sh` tool order (simple)

This is the **execution order** of tools/phases in `webapp_pentest.sh`.

### 1) Dependency check

- `subfinder`, `assetfinder`, `amass`, `sublist3r`, `theHarvester`
- `nmap`, `whatweb`, `gobuster`, `ffuf`
- `nikto`, `nuclei`, `wapiti`
- `wpscan` (only used if WP is detected and token is set)

### 2) Passive recon (OSINT) → `osint/`

- `subfinder` → `osint/subfinder.txt`
- `assetfinder` → `osint/assetfinder.txt`
- `amass enum -passive -silent` → `osint/amass.txt`
- `sublist3r` → `osint/sublist3r.txt`
- `theHarvester` → `osint/theharvester.html`
- Merge/sanitize/deduplicate → `osint/all_subdomains.txt`

### 3) Active scan (per resolvable hostname)

For each entry in `osint/all_subdomains.txt`:

- `nmap` → `nmap/<host>.xml`
- `whatweb` → `whatweb/<host>.json`
- `gobuster` → `directories/<host>-gobuster.txt`
- `ffuf` → `directories/<host>-ffuf.txt`

### 4) Vulnerability scanning (per host × detected web ports)

For each host and each chosen web port:

- `nikto` → `nikto/<host>-<port>.html`
- `nuclei` → `nuclei/<host>-<port>.txt`
- `wapiti` → `wapiti/<host>-<port>.json`
- `wpscan` (only if WordPress is detected + token set) → `wpscan/<host>-<port>.txt`

### 5) Optional exploitation prep → `exploitation/`

Only if `--exploitation-prep` (or `--generate-payloads`) is set:

- `searchsploit --nmap` (for each `nmap/*.xml`) → `exploitation/searchsploit_from_nmap.txt`
- Targeted `searchsploit` keyword searches → `exploitation/searchsploit_targeted.txt`
- Notes/checklist → `exploitation/exploitation_notes.txt`
- Payload helper script written (not executed by default) → `exploitation/generate_payloads.sh`
- If `--generate-payloads`: runs that script to generate payload files under `exploitation/payloads/`

### 6) Summary/report

- Writes `summary.md` in the output directory.

