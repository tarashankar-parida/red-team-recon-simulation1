#!/usr/bin/env python3
"""generate_reports.py - Red Team Reconnaissance Report Generator"""
import json
import csv
import os
import sys
import logging
from datetime import datetime

# Operational configuration
DATA_DIR = 'recon_data'
SERVICE_VERSIONS_FILE = os.path.join(DATA_DIR, 'service_versions.json')
OUT_JSON = os.path.join(DATA_DIR, f'recon_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
OUT_CSV = os.path.join(DATA_DIR, f'service_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
REPORT_FIELDS = ['ip', 'host', 'port', 'service', 'version', 'vulnerability_indicator']

# Setup reconnaissance logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(DATA_DIR, 'recon_report.log')),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('red_team_reporter')

def secure_file_operation(file_path, mode='r', data=None):
    """Handle file operations with security considerations"""
    try:
        if 'w' in mode or 'a' in mode:
            with open(file_path, mode) as f:
                if data is not None:
                    json.dump(data, f, indent=2)
            # Set restrictive permissions on output files
            os.chmod(file_path, 0o600)
            return True
        else:
            with open(file_path, mode) as f:
                return json.load(f)
    except (FileNotFoundError, PermissionError) as e:
        logger.error(f"File operation failed: {str(e)}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in {file_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        sys.exit(1)

def analyze_service(service):
    """Add red team analysis indicators to service data"""
    analysis = {
        'vulnerability_indicator': 'unknown'
    }
    
    # Simple heuristic for vulnerability assessment
    service_name = (service.get('service') or '').lower()
    version = (service.get('version') or '').lower()
    
    if 'ssh' in service_name:
        if '7.' in version or '6.' in version:
            analysis['vulnerability_indicator'] = 'potentially_vulnerable'
        else:
            analysis['vulnerability_indicator'] = 'check_config'
    
    elif 'http' in service_name:
        if 'apache' in version and '2.4' not in version:
            analysis['vulnerability_indicator'] = 'outdated'
        elif 'nginx' in version and '1.18' not in version:
            analysis['vulnerability_indicator'] = 'outdated'
        elif 'iis' in version and '10.' not in version:
            analysis['vulnerability_indicator'] = 'potentially_vulnerable'
    
    return {**service, **analysis}

def generate_reports():
    """Main recon report generation workflow"""
    try:
        # Ensure operational directory exists securely
        os.makedirs(DATA_DIR, exist_ok=True, mode=0o700)
        logger.info(f"Operational directory secured: {DATA_DIR}")
        
        # Load recon data
        logger.info(f"Loading recon data from {SERVICE_VERSIONS_FILE}")
        service_data = secure_file_operation(SERVICE_VERSIONS_FILE)
        
        # Process and analyze data
        report_data = []
        for ip, info in service_data.items():
            host = info.get('host', '')
            for svc in info.get('services', []):
                analyzed_svc = analyze_service(svc)
                report_data.append({
                    'ip': ip,
                    'host': host,
                    'port': analyzed_svc.get('port'),
                    'service': analyzed_svc.get('service'),
                    'version': analyzed_svc.get('version'),
                    'vulnerability_indicator': analyzed_svc.get('vulnerability_indicator')
                })
        logger.info(f"Processed {len(report_data)} service records")
        
        # Generate JSON report
        secure_file_operation(OUT_JSON, 'w', report_data)
        logger.info(f"Generated JSON recon report: {OUT_JSON}")
        
        # Generate CSV report
        try:
            with open(OUT_CSV, 'w', newline='') as csvf:
                writer = csv.DictWriter(csvf, fieldnames=REPORT_FIELDS)
                writer.writeheader()
                writer.writerows(report_data)
            os.chmod(OUT_CSV, 0o600)
            logger.info(f"Generated CSV recon report: {OUT_CSV}")
        except IOError as e:
            logger.error(f"Failed to write CSV report: {str(e)}")
        
        logger.info("Recon report generation completed successfully")
        return True
        
    except Exception as e:
        logger.critical(f"Critical failure in recon operation: {str(e)}")
        return False

if __name__ == "__main__":
    if not generate_reports():
        sys.exit(1)