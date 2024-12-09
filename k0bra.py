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

import scapy.all as scapy
import requests
import nmap
from jsonschema import validate, ValidationError, RefResolver, Draft7Validator
from jsonschema.exceptions import RefResolutionError
from typing import List, Dict, Optional, Tuple

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

# Expanded Vulnerability Database
class VulnerabilityDatabase:
    def __init__(self):
        """Initialize vulnerability database with multiple sources."""
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

    def fetch_cve_data(self, source='CIRCL') -> List[Dict]:
        """
        Fetch CVE data from multiple sources with advanced error handling.
        
        Args:
            source (str): Source of CVE data (default: CIRCL)
        
        Returns:
            List of CVE dictionaries
        """
        try:
            response = requests.get(self.sources[source], timeout=10)
            response.raise_for_status()
            return response.json().get('CVE_Items', response.json())
        except requests.RequestException as e:
            logger.error(f"CVE fetch error from {source}: {e}")
            return []

    def validate_cve_data(self, cve_data: List[Dict]) -> List[Dict]:
        """
        Advanced CVE data validation with detailed error reporting.
        
        Args:
            cve_data (List[Dict]): Raw CVE data to validate
        
        Returns:
            List of validated CVE entries
        """
        valid_cves = []
        for cve in cve_data:
            try:
                # Normalize CVE data structure
                normalized_cve = {
                    'id': cve.get('cve', {}).get('CVE_data_meta', {}).get('ID', 'Unknown'),
                    'description': cve.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value', 'No description'),
                    'published': cve.get('publishedDate', 'Unknown'),
                    'severity': cve.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 0.0)
                }
                valid_cves.append(normalized_cve)
            except Exception as e:
                logger.warning(f"CVE validation error: {e}")
        return valid_cves

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
        Perform port scanning on discovered hosts.
        
        Args:
            hosts (List[str]): List of host IP addresses
            ports (List[int]): List of ports to scan (default: common ports)
        
        Returns:
            Dict of open ports for each host
        """
        if not ports:
            ports = [21, 22, 80, 443, 445, 3306, 3389]

        def scan_host(host: str) -> Tuple[str, List[int]]:
            open_ports = []
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except Exception:
                    pass
            return host, open_ports

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(scan_host, hosts))

        self.open_ports = dict(results)
        return self.open_ports

class ExploitFramework:
    @staticmethod
    def generate_exploit_report(network_scanner, vuln_db):
        """
        Generate comprehensive exploit potential report.
        
        Args:
            network_scanner (NetworkScanner): Network scanner instance
            vuln_db (VulnerabilityDatabase): Vulnerability database instance
        """
        report = []
        for host, ports in network_scanner.open_ports.items():
            host_report = {
                'ip': host,
                'open_ports': ports,
                'potential_exploits': []
            }
            
            # Simulate vulnerability matching logic
            for port in ports:
                # Basic port-based vulnerability matching
                if port == 445:
                    potential_cves = ['CVE-2017-0143', 'CVE-2021-34527']
                elif port == 80:
                    potential_cves = ['CVE-2017-5638', 'CVE-2021-26084']
                else:
                    potential_cves = []
                
                for cve in potential_cves:
                    exploit_modules = vuln_db.find_exploit_modules(cve)
                    host_report['potential_exploits'].extend(exploit_modules)
            
            report.append(host_report)
        
        return report

def print_banner():
    """Print tool banner with ASCII art."""
    banner = f"""{Colors.CYAN}
    ██   ██  ██████  ██████  ██████  ██████  ███████  ███████  ███████  
    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ 
    █████   ██ ██ ██ ██████  ██████  ███████  ████████  ████████  
    ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ 
    ██   ██  ██████  ██████  ███████  ████████  ████████  ████████  
{Colors.GREEN}Welcome to k0bra - The Advanced Network Vulnerability Scanner{Colors.RESET}
"""
    print(banner)

async def main():
    """Main asynchronous execution flow."""
    print_banner()

    # Initialize components
    vuln_db = VulnerabilityDatabase()
    
    # Fetch and process CVE data
    cve_data = vuln_db.fetch_cve_data()
    validated_cves = vuln_db.validate_cve_data(cve_data)
    
    # Save validated CVEs
    with open('validated_cves.json', 'w') as f:
        json.dump(validated_cves, f, indent=4)
    
    # Get target network
    target_network = input(f"{Colors.YELLOW}Enter target network (e.g., 192.168.1.0/24): {Colors.RESET}").strip()
    
    # Perform network scanning
    network_scanner = NetworkScanner(target_network)
    discovered_hosts = network_scanner.scan_network()
    
    if not discovered_hosts:
        print(f"{Colors.RED}No hosts discovered in the network.{Colors.RESET}")
        return
    
    # Perform port scanning
    open_ports = network_scanner.port_scan(discovered_hosts)
    
    # Generate exploit report
    exploit_report = ExploitFramework.generate_exploit_report(network_scanner, vuln_db)
    
    # Save and display report
    with open('exploit_report.json', 'w') as f:
        json.dump(exploit_report, f, indent=4)
    
    print(f"\n{Colors.GREEN}Exploit Potential Report:{Colors.RESET}")
    for entry in exploit_report:
        print(f"Host: {entry['ip']}")
        print(f"Open Ports: {entry['open_ports']}")
        print(f"Potential Exploits: {entry['potential_exploits']}\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Scan interrupted by user.{Colors.RESET}")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
