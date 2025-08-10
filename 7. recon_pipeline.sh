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
 极
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