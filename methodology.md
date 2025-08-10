# Methodology

## Phase 1 — Passive Reconnaissance
1. Use `crt.sh` and `amass` to discover subdomains
2. Use `subfinder` to aggregate passive results
3. Enrich with `whois`, `shodan`, and GitHub search

## Phase 2 — Service Discovery (Low-Impact Active)
1. Probe hosts with `httpx`
2. Use `nmap` with `-sV -sC` on limited ports
3. Capture outputs in machine-readable formats

## Phase 3 — Analysis & Reporting
1. Parse `nmap` XML and summarize service versions
2. Generate visual maps
3. Produce technical report and executive summary