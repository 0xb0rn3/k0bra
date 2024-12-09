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
from datetime import datetime, timedelta
import random

import scapy.all as scapy
import requests
import nmap
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from jsonschema import validate, ValidationError, RefResolver, Draft7Validator
from jsonschema.exceptions import RefResolutionError
from typing import List, Dict, Optional, Tuple

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('k0bra.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ANSI Color Codes
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
        return f"{color}{text}{cls.RESET}"

# Banner
def print_banner():
    """Print tool banner."""
    banner = f"""
{Colors.CYAN}
    ██   ██  ██████  ██████  ██████  ██████  ███████  ███████  ███████  
    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ 
    █████   ██ ██ ██ ██████  ██████  ███████  ████████  ████████  
    ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ██   ██ 
    ██   ██  ██████  ██████  ███████  ████████  ████████  ████████  
{Colors.GREEN}Welcome to k0bra - The Advanced Network Vulnerability Scanner
Developed by: b0urn3
GitHub: https://github.com/q4n0
Contact: Email: b0urn3@proton.me | Instagram: onlybyhive
{Colors.RESET}
"""
    print(banner)

# Machine Learning Risk Predictor
class RiskPredictor:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()

    def prepare_training_data(self, historical_scans):
        features = []
        labels = []
        for scan in historical_scans:
            feature_vector = [
                len(scan.get('open_ports', [])),
                len(set(scan.get('services', {}).keys())),
                len([s for s in scan.get('services', {}).values() if s['name'] == 'HTTP']),
                len([s for s in scan.get('services', {}).values() if s['name'] == 'SSH']),
                sum(len(banner) for banner in scan.get('service_banners', [])),
                len(scan.get('vulnerabilities', []))
            ]
            features.append(feature_vector)
            labels.append(scan.get('risk_label', 0))

        X = self.scaler.fit_transform(features)
        X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2)
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(X_train, y_train)

    def predict_network_risk(self, network_scan):
        if not self.model:
            return 0.5
        feature_vector = [
            len(network_scan.get('open_ports', [])),
            len(set(network_scan.get('services', {}).keys())),
            len([s for s in network_scan.get('services', {}).values() if s['name'] == 'HTTP']),
            len([s for s in network_scan.get('services', {}).values() if s['name'] == 'SSH']),
            sum(len(banner) for banner in network_scan.get('service_banners', [])),
            len(network_scan.get('vulnerabilities', []))
        ]
        scaled_features = self.scaler.transform([feature_vector])
        risk_prediction = self.model.predict_proba(scaled_features)[0][1]
        return risk_prediction

# Vulnerability Database
class VulnerabilityDatabase:
    def __init__(self):
        self.sources = {
            'CIRCL': 'https://cve.circl.lu/api/last',
            'NVD': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        }
        self.service_port_mapping = {
            21: 'FTP', 22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP'
        }

    def fetch_vulnerabilities(self):
        all_vulnerabilities = []
        for source, url in self.sources.items():
            try:
                response = requests.get(url, timeout=15, verify=False)
                response.raise_for_status()
                all_vulnerabilities.extend(self._parse_vulnerabilities(response.json()))
            except Exception as e:
                logger.warning(f"Failed to fetch from {source}: {e}")
        return {v['id']: v for v in all_vulnerabilities}.values()

    def _parse_vulnerabilities(self, raw_data):
        vulnerabilities = []
        for item in raw_data.get('CVE_Items', []):
            vulnerabilities.append({
                'id': item.get('cve', {}).get('CVE_data_meta', {}).get('ID'),
                'description': item.get('cve', {}).get('description', {}).get('description_data', [{}])[0].get('value'),
                'severity': item.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 0.0),
                'published_date': item.get('publishedDate'),
            })
        return vulnerabilities

# Network Scanner
class NetworkScanner:
    def __init__(self, target_network):
        self.target_network = target_network

    def scan_network(self):
        nm = nmap.PortScanner()
        nm.scan(hosts=self.target_network, arguments='-sS -T4')
        hosts = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                hosts.append(host)
        return hosts

# Main Execution
async def main():
    print_banner()
    target_network = input(f"{Colors.YELLOW}Enter target network (e.g., 192.168.1.0/24): {Colors.RESET}").strip()
    vuln_db = VulnerabilityDatabase()
    network_scanner = NetworkScanner(target_network)
    risk_predictor = RiskPredictor()

    # Fetch and aggregate vulnerabilities
    vulnerabilities = vuln_db.fetch_vulnerabilities()

    # Scan the network
    hosts = network_scanner.scan_network()
    print(f"{Colors.GREEN}Discovered Hosts: {hosts}{Colors.RESET}")

    # Generate risk predictions
    for host in hosts:
        risk = risk_predictor.predict_network_risk({'open_ports': [80, 443], 'vulnerabilities': list(vulnerabilities)})
        print(f"{Colors.BLUE}Host: {host} | Risk: {risk:.2f}{Colors.RESET}")

    # Save report
    with open('network_report.json', 'w') as f:
        json.dump({'hosts': hosts, 'vulnerabilities': vulnerabilities}, f, indent=4)
    print(f"{Colors.GREEN}Report saved as network_report.json{Colors.RESET}")

if __name__ == "__main__":
    asyncio.run(main())
