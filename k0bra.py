#!/usr/bin/env python3
import os
import sqlite3
import logging
import asyncio
import json
import csv
import re
import ipaddress
import socket
import concurrent.futures
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import scapy.all as scapy
import requests
import nmap
from jsonschema import validate, ValidationError, RefResolver, Draft7Validator
from jsonschema.exceptions import RefResolutionError
from typing import List, Dict, Optional, Tuple, Any

# Advanced Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('k0bra.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Enhanced Color Codes
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    RESET = "\033[0m"

    @classmethod
    def colorize(cls, text, color):
        """Colorize text with given color."""
        return f"{color}{text}{cls.RESET}"

# Advanced Vulnerability Database with Enhanced Features
class VulnerabilityDatabase:
    def __init__(self):
        """Initialize advanced vulnerability database."""
        self.sources = {
            'CIRCL': 'https://cve.circl.lu/api/last',
            'NVD': 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        }
        self.cve_cache = {}
        self.metasploit_modules = {
            "SMB": {
                "CVE-2017-0143": "exploit/windows/smb/ms17_010_eternalblue",
                "CVE-2021-34527": "exploit/windows/smb/printnightmare",
            },
            "HTTP": {
                "CVE-2017-5638": "exploit/multi/http/struts2_content_type_ognl",
                "CVE-2021-26084": "exploit/multi/http/confluence_widget_connector_rce",
            },
            "SSL": {
                "CVE-2014-0160": "auxiliary/scanner/ssl/openssl_heartbleed",
            },
            "Android": {
                "CVE-2017-13156": "exploit/android/local/janus",
                "CVE-2021-0938": "exploit/android/local/put_user_vroot",
            }
        }
        self.service_port_mapping = {
            80: 'HTTP',
            443: 'HTTPS',
            22: 'SSH',
            21: 'FTP',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP'
        }

    def fetch_multiple_cve_sources(self) -> List[Dict]:
        """
        Fetch CVE data from multiple sources with advanced aggregation.
        
        Returns:
            Aggregated and deduplicated list of vulnerability entries
        """
        all_vulnerabilities = []
        
        for source, url in self.sources.items():
            try:
                response = requests.get(url, timeout=15, verify=False)
                response.raise_for_status()
                vulnerabilities = self._parse_cve_source(response.json(), source)
                all_vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                logger.warning(f"Failed to fetch vulnerabilities from {source}: {e}")
        
        # Remove duplicates based on CVE ID
        unique_vulnerabilities = {vuln['id']: vuln for vuln in all_vulnerabilities}.values()
        return list(unique_vulnerabilities)

    def _parse_cve_source(self, raw_data: Dict, source: str) -> List[Dict]:
        """
        Parse vulnerability data from different sources.
        
        Args:
            raw_data (Dict): Raw vulnerability data
            source (str): Source of the data
        
        Returns:
            List of parsed vulnerability entries
        """
        vulnerabilities = []
        try:
            if source == 'CIRCL':
                for item in raw_data:
                    vulnerability = self._normalize_cve_data(item)
                    vulnerabilities.append(vulnerability)
            elif source == 'NVD':
                for item in raw_data.get('result', {}).get('CVE_Items', []):
                    vulnerability = self._normalize_cve_data(item)
                    vulnerabilities.append(vulnerability)
        except Exception as e:
            logger.error(f"Error parsing {source} vulnerabilities: {e}")
        
        return vulnerabilities

    def _normalize_cve_data(self, cve_entry: Dict) -> Dict:
        """
        Normalize CVE data to a consistent format.
        
        Args:
            cve_entry (Dict): Raw CVE entry
        
        Returns:
            Normalized vulnerability dictionary
        """
        try:
            return {
                'id': cve_entry.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'Unknown'),
                'description': self._extract_description(cve_entry),
                'severity': self._calculate_severity(cve_entry),
                'published_date': cve_entry.get('publishedDate', datetime.now().isoformat()),
                'affected_services': self._determine_affected_services(cve_entry)
            }
        except Exception as e:
            logger.warning(f"CVE normalization error: {e}")
            return {}

    def _extract_description(self, cve_entry: Dict) -> str:
        """Extract description from CVE entry."""
        descriptions = cve_entry.get('cve', {}).get('description', {}).get('description_data', [])
        return descriptions[0].get('value', 'No description') if descriptions else 'No description'

    def _calculate_severity(self, cve_entry: Dict) -> float:
        """Calculate vulnerability severity."""
        try:
            return float(cve_entry.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 0.0))
        except (TypeError, ValueError):
            return 0.0

    def _determine_affected_services(self, cve_entry: Dict) -> List[int]:
        """
        Determine affected network services based on CVE description and configuration.
        
        Args:
            cve_entry (Dict): CVE entry data
        
        Returns:
            List of affected port numbers
        """
        description = self._extract_description(cve_entry).lower()
        affected_ports = []

        for port, service in self.service_port_mapping.items():
            if service.lower() in description:
                affected_ports.append(port)
        
        return affected_ports

    def advanced_vulnerability_matching(self, host_info: Dict, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Perform sophisticated vulnerability matching for a specific host.
        
        Args:
            host_info (Dict): Detailed information about the host
            vulnerabilities (List[Dict]): All known vulnerabilities
        
        Returns:
            List of matched vulnerabilities with confidence scores
        """
        matched_vulnerabilities = []
        
        for vulnerability in vulnerabilities:
            match_confidence = 0
            
            # Service-based matching
            if vulnerability.get('affected_services'):
                for port in host_info.get('open_ports', []):
                    if port in vulnerability['affected_services']:
                        match_confidence += 0.4
            
            # Severity-based weighting
            if vulnerability.get('severity', 0) > 7.0:
                match_confidence += 0.3
            
            # Temporal relevance (prioritize recent vulnerabilities)
            published_date = datetime.fromisoformat(vulnerability.get('published_date', datetime.now().isoformat()))
            if (datetime.now() - published_date) < timedelta(days=365):
                match_confidence += 0.2
            
            if match_confidence > 0.5:
                vulnerability['match_confidence'] = round(match_confidence, 2)
                matched_vulnerabilities.append(vulnerability)
        
        return sorted(matched_vulnerabilities, key=lambda x: x['match_confidence'], reverse=True)

    def find_exploit_modules(self, cve_id: str) -> List[str]:
        """
        Find potential Metasploit exploit modules for a given CVE.
        
        Args:
            cve_id (str): CVE identifier
        
        Returns:
            List of potential Metasploit modules
        """
        modules = []
        for category, cves in self.metasploit_modules.items():
            if cve_id in cves:
                modules.append(cves[cve_id])
        return modules

class NetworkScanner:
    def __init__(self, target_network: str):
        """
        Initialize network scanner with target network.
        
        Args:
            target_network (str): Network range to scan
        """
        self.target_network = target_network
        self.open_ports = {}
        self.discovered_hosts = []
        self.service_fingerprints = {}

    def validate_network(self) -> bool:
        """
        Validate network range input.
        
        Returns:
            bool: True if network is valid, False otherwise
        """
        try:
            ipaddress.ip_network(self.target_network)
            return True
        except ValueError:
            logger.error(f"Invalid network range: {self.target_network}")
            return False

    def scan_network(self) -> List[str]:
        """
        Perform comprehensive network scan using multiple techniques.
        
        Returns:
            List of discovered host IP addresses
        """
        if not self.validate_network():
            return []

        try:
            # Use nmap for comprehensive scanning
            nm = nmap.PortScanner()
            nm.scan(hosts=self.target_network, arguments='-sn')

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    self.discovered_hosts.append(host)
                    logger.info(f"Host discovered: {host}")

            return self.discovered_hosts
        except Exception as e:
            logger.error(f"Network scanning error: {e}")
            return []

    def port_scan(self, hosts: List[str], ports: List[int] = None) -> Dict:
        """
        Perform port scanning on discovered hosts with service fingerprinting.
        
        Args:
            hosts (List[str]): List of host IP addresses
            ports (List[int]): List of ports to scan
        
        Returns:
            Dict of open ports and service info for each host
        """
        if not ports:
            ports = [21, 22, 80, 443, 445, 3306, 3389]

        def scan_host(host: str) -> Tuple[str, Dict]:
            open_ports = []
            service_info = {}
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
                        service_info[port] = self._fingerprint_service(host, port)
                    sock.close()
                except Exception:
                    pass
            return host, {'open_ports': open_ports, 'services': service_info}

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = dict(executor.map(scan_host, hosts))

        self.open_ports = {host: data['open_ports'] for host, data in results.items()}
        self.service_fingerprints = {host: data['services'] for host, data in results.items()}
        return results

    def _fingerprint_service(self, host: str, port: int) -> Dict:
        """
        Perform basic service fingerprinting.
        
        Args:
            host (str): Target host IP
            port (int): Target port
        
        Returns:
            Dictionary with service details
        """
        service_mapping = {
            21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS',
            445: 'SMB', 3306: 'MySQL', 3389: 'RDP'
        }
        
        try:
            # Basic banner grabbing
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((host, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                
                return {
                    'name': service_mapping.get(port, 'Unknown'),
                    'port': port,
                    'banner': banner
                }
        except Exception:
            return {
                'name': service_mapping.get(port, 'Unknown'),
                'port': port,
                'banner': 'Unable to grab banner'
            }

class AdvancedExploitFramework:
    @staticmethod
    def generate_comprehensive_exploit_report(network_scanner, vuln_db):
        """
        Generate a highly detailed exploit potential report with risk assessment.
        
        Returns:
            Comprehensive vulnerability and exploit report
        """
        comprehensive_report = {
            'network_summary': {
                'total_hosts': len(network_scanner.discovered_hosts),
                'total_vulnerabilities': 0,
                'average_network_risk': 0.0
            },
            'host_vulnerabilities': []
        }
        
        all_vulnerabilities = vuln_db.fetch_multiple_cve_sources()
        
        for host in network_scanner.discovered_hosts:
            host_info = {
                'ip': host,
                'open_ports': network_scanner.open_ports.get(host, []),
                'services': network_scanner.service_fingerprints.get(host, {})
            }
            
            # Advanced vulnerability matching
            matched_vulnerabilities = vuln_db.advanced_vulnerability_matching(
                host_info, 
                all_vulnerabilities
            )
            
            host_report = {
                'ip': host,
                'open_ports': host_info['open_ports'],
                'services': host_info['services'],
                'vulnerabilities': matched_vulnerabilities,
                'exploit_modules': [],
                'risk_score': 0.0
            }
            
            # Calculate host risk score
            host_report['risk_score'] = sum(
                vuln.get('match_confidence', 0) * vuln.get('severity', 0) 
                for vuln in matched_vulnerabilities
            )
            
            # Find potential exploit modules
            for vulnerability in matched_vulnerabilities:
                exploit_modules = vuln_db.find_exploit_modules(vulnerability['id'])
                host_report['exploit_modules'].extend(exploit_modules)
            
            comprehensive_report['host_vulnerabilities'].append(host_report)
            comprehensive_report['network_summary']['total_vulnerabilities'] += len(matched_vulnerabilities)
        
        # Calculate overall network risk
        comprehensive_report['network_summary']['average_network_risk'] = (
            sum(host['risk_score'] for host in comprehensive_report['host_vulnerabilities']) / 
            len(comprehensive_report['host_vulnerabilities'])
        ) if comprehensive_report['host_vulnerabilities'] else 0.0
        
        return comprehensive_report

# (Previous code remains the same)

def print_banner():
    """Print tool banner with ASCII art and colorful introduction."""
    banner = f"""{Colors.CYAN}
    ██   ██  ██████  ██████  ██████  ██████  ███████  ███████  ███████  
    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ 
    █████   ██ ██ ██ ██████  ██████  ███████  ████████  ████████  
    ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ 
    ██   ██  ██████  ██████  ███████  ████████  ████████  ████████  
{Colors.GREEN}Welcome to k0bra - The Advanced Network Vulnerability Scanner{Colors.RESET}
"""
    print(banner)

def save_report(report: Dict, filename: str = 'vulnerability_report.json'):
    """
    Save comprehensive vulnerability report to a JSON file.
    
    Args:
        report (Dict): Comprehensive vulnerability report
        filename (str): Output filename
    """
    try:
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        logger.info(f"Report saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving report: {e}")

def display_report(report: Dict):
    """
    Display a formatted vulnerability report in the console.
    
    Args:
        report (Dict): Comprehensive vulnerability report
    """
    print(f"\n{Colors.GREEN}=== Network Vulnerability Assessment ==={Colors.RESET}")
    
    # Network Summary
    network_summary = report.get('network_summary', {})
    print(f"{Colors.BLUE}Network Overview:{Colors.RESET}")
    print(f"Total Hosts Discovered: {network_summary.get('total_hosts', 0)}")
    print(f"Total Vulnerabilities: {network_summary.get('total_vulnerabilities', 0)}")
    print(f"Average Network Risk Score: {network_summary.get('average_network_risk', 0.0):.2f}/10")
    print("\n" + "="*50)
    
    # Host-level details
    for host_report in report.get('host_vulnerabilities', []):
        print(f"\n{Colors.YELLOW}Host: {host_report['ip']}{Colors.RESET}")
        print(f"Open Ports: {host_report['open_ports']}")
        print(f"Risk Score: {host_report['risk_score']:.2f}/10")
        
        # Vulnerabilities
        if host_report['vulnerabilities']:
            print("\nDetected Vulnerabilities:")
            for vuln in host_report['vulnerabilities']:
                print(f"  - {vuln['id']} (Confidence: {vuln.get('match_confidence', 0):.2f}, Severity: {vuln.get('severity', 0):.2f})")
                print(f"    Description: {vuln.get('description', 'No description')}")
        
        # Potential Exploits
        if host_report['exploit_modules']:
            print("\nPotential Exploit Modules:")
            for module in host_report['exploit_modules']:
                print(f"  - {module}")
        
        print("-"*50)

async def main():
    """Main asynchronous execution flow."""
    print_banner()

    # Disable SSL warnings to prevent console noise
    requests.packages.urllib3.disable_warnings()

    try:
        # Initialize components
        vuln_db = VulnerabilityDatabase()
        
        # Get target network
        target_network = input(f"{Colors.YELLOW}Enter target network (e.g., 192.168.1.0/24): {Colors.RESET}").strip()
        
        # Perform network scanning
        network_scanner = NetworkScanner(target_network)
        discovered_hosts = network_scanner.scan_network()
        
        if not discovered_hosts:
            print(f"{Colors.RED}No hosts discovered in the network.{Colors.RESET}")
            return
        
        # Perform port scanning
        network_scanner.port_scan(discovered_hosts)
        
        # Generate comprehensive exploit report
        exploit_report = AdvancedExploitFramework.generate_comprehensive_exploit_report(network_scanner, vuln_db)
        
        # Save report to file
        save_report(exploit_report)
        
        # Display report in console
        display_report(exploit_report)
    
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Scan interrupted by user.{Colors.RESET}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"{Colors.RED}An unexpected error occurred: {e}{Colors.RESET}")

def cli_entry_point():
    """Command-line entry point for the tool."""
    import warnings
    warnings.filterwarnings('ignore')
    
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Critical error: {e}")
        logger.critical(f"Unhandled exception: {e}")

if __name__ == "__main__":
    cli_entry_point()
