#!/bin/bash
# Complete red team recon simulation setup

# Create directory structure
mkdir -p red-team-recon-simulation/{data,visual_maps}
cd red-team-recon-simulation

# Create core scripts
cat > generate_reports.py <<'EOF'
#!/usr/bin/env python3
"""generate_reports.py - Aggregate sample data into summary CSV/JSON"""
import json, csv, os

DATA_DIR = 'data'
OUT_JSON = os.path.join(DATA_DIR, 'summary.json')
OUT_CSV = os.path.join(DATA_DIR, 'service_summary.csv')

sv_path = os.path.join(DATA_DIR, 'service_versions.json')
with open(sv_path) as f:
    sv = json.load(f)

summary = []
for ip, info in sv.items():
    host = info.get('host')
    for svc in info.get('services', []):
        summary.append({
            'ip': ip,
            'host': host,
            'port': svc.get('port'),
            'service': svc.get('service'),
            'version': sv极.get('version')
        })

with open(OUT_JSON, 'w') as f:
    json.dump(summary, f, indent=2)

with open(OUT_CSV, 'w', newline='') as csvf:
    writer = csv.DictWriter(csvf, fieldnames=['ip','host','port','service','version'])
    writer.writeheader()
    for row in summary:
        writer.writerow(row)

print('[*] Generated', OUT_JSON, 'and', OUT_CSV)
EOF

cat > parse_nmap.py <<'EOF'
#!/usr/bin/env python3
"""parse_nmap.py - Enhanced Nmap XML parser with service/version extraction"""
import xml.etree.ElementTree as ET
import json, csv, sys, os

def parse_nmap(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    results = {}
    
    for host in root.findall('host'):
        addr = host.find('address').get('addr') if host.find('address') is not None else None
        if not addr:
            continue
            
        hostnames = host.find('hostnames')
        primary_host = None
        if hostnames:
            for hostname in hostnames.findall('hostname'):
                if hostname.get('type') == 'user':
                    primary_host = hostname.get('name')
                    break
        
        services = []
        ports = host.find('ports')
        if ports is None:
            continue
            
        for port in ports.findall('port'):
            portid = port.get('portid')
            proto = port.get('protocol')
            state = port.find('state').get('state') if port.find('state') is not None else None
            
            service_info = port.find('service')
            service_name = service_info.get('name') if service_info is not None else None
            version = service_info.get('product') if service_info is not None else None
            if version and service_info.get('version'):
                version += ' ' + service_info.get('version')
            
            if version and service_info.get('extrainfo'):
                version += ' (' + service_info.get('extrainfo') + ')'
            
            services.append({
                'port': portid,
                'service': service_name,
                'version': version,
                'protocol': proto,
                'state': state
            })
        
        results[addr] = {
            'host': primary_host,
            'services': services
        }
    
    return results

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: parse_nmap.py <nmap_xml> [output.json]')
        sys.exit(1)
    
    xml = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'service_versions.json'
    
    data = parse_nmap(xml)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f'[*] Parsed {len(data)} hosts to {output_file}')
EOF

cat > recon_pipeline.sh <<'EOF'
#!/bin/bash
# Complete recon simulation pipeline
set -e
echo "[*] Starting recon simulation..."

OUTPUT_DIR="data"
mkdir -p "$OUTPUT_DIR"

echo "[*] Creating sample data files..."
cat > data/subdomains.txt <<SUB
api.example.com
dev.example.com
www.example.com
shop.example.com
mail.example.com
SUB

cat > data/live_ips.txt <<IP
198.51.100.11
198.51.100.12
198.51.100.13
198.51.100.20
198.51.100.14
IP

echo "[*] Generating simulated nmap scan..."
cat > data/nmap_scan.xml <<XML
<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -iL data/live_ips.txt" start="1686145129" version="7.92" xmloutputversion="1.05">
  <host starttime="1686145129" endtime="1686145182">
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.11" addrtype="ipv4"/>
    <hostnames>
      <hostname name="api.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="58"/>
        <service name="http" product="nginx" version="1.14.0" extrainfo="(Ubuntu)" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
  <host starttime="1686145129" endtime="1686145182">
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.12" addrtype="ipv4"/>
    <hostnames>
      <hostname name="dev.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="58"/>
        <service name="ssh" product="OpenSSH" version="7.2p2 Ubuntu 4ubuntu2.10" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
  <host starttime="1686145129" endtime="1686145182">
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.13" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="58"/>
        <service name="ssl" product="Apache httpd" version="2.4.18" extrainfo="(Ubuntu)" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
  <host starttime="1686145129" endtime="1686145182">
    <status state="up" reason="syn-ack"/>
    <address addr="198.51.100.20" addrtype="ipv4"/>
    <hostnames>
      <hostname name="shop.example.com" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="58"/>
        <service name="https" product="Apache httpd" version="2.4.38" extrainfo="(Debian)" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack" reason_ttl="58"/>
        <service name="http" product="Node.js Express framework" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
XML

echo "[*] Parsing scan results..."
python3 parse_nmap.py data/nmap_scan.xml data/service_versions.json

echo "[*] Generating reports..."
python3 generate_reports.py

echo "[*] Creating network visualization..."
mkdir -p visual_maps
cat > visual_maps/network_map.txt <<'VIZ'
Red Team Reconnaissance - Network Visualization

External Attack Surface

[ Internet ]
|
├── [198.51.100.11] api.example.com
│   ├── Port 80/tcp: HTTP (nginx 1.14.0)
│   └── Risk: Medium (Outdated web server)
│
├── [198.51.100.12] dev.example.com
│   ├── Port 22/tcp: SSH (OpenSSH 7.2p2)
│   └── Risk: High (Vulnerable SSH version)
│
├── [198.51.100.13] (Unnamed Host)
│   ├── Port 443/tcp: HTTPS (Apache 2.4.18)
│   └── Risk: Critical (EOL software)
│
├── [198.51.100.20] shop.example.com
│   ├── Port 443/tcp: HTTPS (Apache 2.4.38)
│   ├── Port 8080/tcp: HTTP (Node.js Express)
│   └── Risk: Medium (Secondary service exposure)
│
└── [198.51.100.14] (No open ports)

Key Findings:
- 4/5 hosts have outdated services
- Web servers (80,443,8080) are primary entry points
- SSH service on dev host is high priority

Recommendations:
1. Patch web servers immediately
2. Upgrade SSH on dev.example.com
3. Investigate unlabeled host (198.51.100.13)
VIZ

echo "[+] Recon simulation complete!"
echo "    Generated reports: data/summary.json, data/service_summary.csv"
echo "    Network map: visual_maps/network_map.txt"
EOF

# Create documentation
cat > methodology.md <<'EOF'
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
EOF

cat > executive_summary.md <<'EOF'
# Executive Summary

This repository contains a simulated red-team reconnaissance engagement.

Key findings (simulation):
- Discovered 12 subdomains and prioritized 5 externally-exposed services
- Identified potential high-risk services
- Produced visual maps and CSV data for open ports
EOF

cat > README.md <<'EOF'
# Red Team Recon Simulation

This project simulates a red team reconnaissance engagement using sample data, Nmap parsing scripts, and visual network maps.

## Quick Start
1. Run setup script: `./red-team-recon-simulation-setup.sh`
2. Execute pipeline: `./recon_pipeline.sh`

## Generated Outputs
- `data/`: JSON/CSV reports of discovered services
- `visual_maps/`: Text-based network diagrams
- Documentation: Methodology, executive summary, technical report

## Requirements
- Python 3
- Bash shell
EOF

cat > technical_report.md <<'EOF'
# Technical Report

## Tools Used
- `subfinder` / `amass` for passive enumeration
- `httpx` for probing HTTP endpoints
- `nmap` for port scanning
- Custom scripts for processing

## Sample Commands
```bash
subfinder -d example.com -o data/subdomains.txt
nmap -sV -iL data/live_ips.txt -oA data/nmap_scan