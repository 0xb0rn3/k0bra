#!/usr/bin/env python3
import sqlite3
import logging
import scapy.all as scapy
import requests
import subprocess
import asyncio
import json
import csv
import re
from jsonschema import validate, ValidationError
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

# Load the CVE JSON schema (replace '/path/to/schema.json' with the actual path to your schema file)
with open('/mnt/data/CVE_Record_Format.json', 'r') as schema_file:
    CVE_SCHEMA = json.load(schema_file)

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

# Fetch CVE data dynamically from CIRCL API
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

# Validate CVE data against the provided schema
def validate_cve_data(cve_data):
    """Validates the fetched CVE data against the provided schema."""
    valid_cves = []
    for cve in cve_data:
        try:
            validate(instance=cve, schema=CVE_SCHEMA)
            valid_cves.append(cve)
        except ValidationError as e:
            print(f"{YELLOW}Invalid CVE format for {cve.get('id', 'Unknown')}: {e}{RESET}")
    return valid_cves

# Display CVE details
def display_cve_data(cve_data):
    """Displays validated CVE data."""
    if cve_data:
        print(GREEN + "Validated CVEs:" + RESET)
        for cve in cve_data:
            print(f"{CYAN}CVE ID: {cve['id']}{RESET}")
            print(f"{YELLOW}Description: {cve['summary']}{RESET}")
            print(f"{RED}Published Date: {cve['Published']}{RESET}")
            print(f"{YELLOW}CVSS Score: {cve['cvss']}\n{RESET}")
    else:
        print(RED + "No valid CVE data available." + RESET)

# Function to save validated CVE data
def save_cve_data_to_file(cve_data):
    """Saves validated CVE data to a file."""
    try:
        with open('validated_cves.json', 'w') as f:
            json.dump(cve_data, f, indent=4)
        print(GREEN + "Validated CVE data saved to validated_cves.json" + RESET)
    except Exception as e:
        print(f"{RED}Error saving CVE data to file: {e}{RESET}")

# Main function to integrate CVE fetching and schema validation
async def main():
    print_banner()

    # Get user input for target network
    target_network = get_user_input()

    # Fetch and validate CVE data
    cve_data = fetch_cve_data()
    if cve_data:
        validated_cves = validate_cve_data(cve_data)
        display_cve_data(validated_cves)
        save_cve_data_to_file(validated_cves)
    else:
        print(RED + "No CVE data fetched. Skipping vulnerability mapping." + RESET)

    # Placeholder for further scanning and exploitation logic
    print(GREEN + "Scanning and exploitation functionality can proceed here." + RESET)

if __name__ == "__main__":
    asyncio.run(main())
