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