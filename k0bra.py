#!/usr/bin/env python3
import scapy.all as scapy
import netifaces
import sys
import csv
import subprocess
import os
import signal
import time
import requests
import re
import logging
import asyncio
import aiohttp
from typing import List, Dict

# Set up logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_header():
    print(CYAN + "    ██   ██  ██████  ██████  ██████   █████  ")
    print("    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ")
    print("    █████   ██ ██ ██ ██████  ██████  ███████ ")
    print("    ██  ██  ████  ██ ██   ██ ██   ██ ██   ██ ")
    print("    ██   ██  ██████  ██████  ██   ██ ██   ██ " + RESET)
    print(GREEN + "Welcome to k0bra - The Network Scavenger! Developed by b0urn3.")
    print("Other tools found at https://github.com/q4n0")
    print("Email: b0urn3@proton.me Instagram: onlybyhive\n" + RESET)

def handle_exit(signum, frame):
    """Handle clean exit on Ctrl + C."""
    print(RED + "\nExiting gracefully... (Ctrl + C detected)" + RESET)
    sys.exit(0)

def is_masscan_installed() -> bool:
    try:
        subprocess.run(["masscan", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def install_masscan():
    print(YELLOW + "Masscan not found. Installing in the background..." + RESET)
    os.system("sudo apt-get install -y masscan &")

def get_active_interfaces() -> List[str]:
    interfaces = netifaces.interfaces()
    active_interfaces = []
    for iface in interfaces:
        try:
            iface_info = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in iface_info:
                active_interfaces.append(iface)
        except (ValueError, KeyError):
            pass  # Skip interfaces with no valid IP configuration
    return active_interfaces

def get_ip_range(interface: str) -> str:
    try:
        iface_info = netifaces.ifaddresses(interface)
        ip_info = iface_info[netifaces.AF_INET]
        ip = ip_info[0]['addr']
        subnet_mask = ip_info[0]['netmask']
        
        ip_parts = ip.split('.')
        mask_parts = subnet_mask.split('.')
        network_address = '.'.join(str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4))
        return f"{network_address}/24"
    except KeyError:
        print(RED + f"Could not retrieve IP information for interface: {interface}" + RESET)
        sys.exit(1)

def get_gateway(interface: str) -> str:
    gateways = netifaces.gateways()
    if interface in gateways[netifaces.AF_INET]:
        return gateways[netifaces.AF_INET][interface][0]
    return None

def validate_ip(ip: str) -> bool:
    """Validate the format of an IP address."""
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(/\d{1,2})?$"
    return re.match(pattern, ip) is not None

def get_ip_mac_pairs(ip_range: str, timeout: int = 2) -> List[Dict[str, str]]:
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device_info = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        devices.append(device_info)
        mac_info = asyncio.run(get_mac_info(device_info['MAC']))  # Fetch MAC info asynchronously
        vendor = mac_info.get('vendorDetails', {}).get('companyName', 'Unknown')
        print(f"{GREEN}Found device: IP: {device_info['IP']}, MAC: {device_info['MAC']}, Vendor: {vendor}{RESET}")
        time.sleep(1)  # Delay to avoid hitting API rate limits
    return devices

async def fetch_mac_info(mac_address: str, session: aiohttp.ClientSession) -> dict:
    """Asynchronously fetch MAC address info from the API."""
    api_key = os.getenv("MAC_API_KEY")  # Use environment variable for the API key
    url = f"https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={mac_address}"
    
    async with session.get(url) as response:
        if response.status == 200:
            return await response.json()  # Parses the JSON response
        else:
            logging.error(f"Failed to fetch MAC info for {mac_address}. Error code: {response.status}")
            return {}

async def get_mac_info(mac_address: str) -> dict:
    """Wrapper function to fetch MAC info with aiohttp."""
    async with aiohttp.ClientSession() as session:
        return await fetch_mac_info(mac_address, session)

def masscan_scan(ip_range: str, port_range: str = "0-65535", rate: int = 50000) -> Dict[str, List[int]]:
    masscan_results = {}
    stealth_options = f"--rate {rate}"  # Stealth options for Masscan
    command = f"masscan {ip_range} -p{port_range} {stealth_options} --wait 2"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        for line in result.splitlines():
            if line.startswith('Discovered'):
                parts = line.split()
                port = int(parts[3].split('/')[0])
                ip = parts[5]
                if ip not in masscan_results:
                    masscan_results[ip] = []
                masscan_results[ip].append(port)
    except subprocess.CalledProcessError as e:
        print(RED + f"Masscan failed: {e}" + RESET)
    return masscan_results

def scan_all_ports(devices: List[Dict[str, str]], port_range: str = "0-65535", rate: int = 50000) -> Dict[str, List[int]]:
    results = {}
    ip_range = ','.join(device['IP'] for device in devices)
    print(BLUE + f"Using Masscan to scan range: {ip_range}" + RESET)
    masscan_results = masscan_scan(ip_range, port_range=port_range, rate=rate)
    
    for device in devices:
        ip = device['IP']
        if ip in masscan_results:
            results[ip] = masscan_results[ip]
    return results

def save_results_to_csv(devices: List[Dict[str, str]], open_ports: Dict[str, List[int]], output_file: str):
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'MAC', 'Open Ports']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            ip = device['IP']
            mac = device['MAC']
            ports = ', '.join(map(str, open_ports.get(ip, [])))
            writer.writerow({'IP': ip, 'MAC': mac, 'Open Ports': ports})

    print(GREEN + f"Results saved to {output_file}" + RESET)

def main():
    # Handle Ctrl+C for clean exit
    signal.signal(signal.SIGINT, handle_exit)

    print_header()

    if not is_masscan_installed():
        install_masscan()
        print(YELLOW + "Please run the script again after Masscan installation." + RESET)
        sys.exit(1)

    active_interfaces = get_active_interfaces()
    if not active_interfaces:
        print(RED + "No active network interfaces found." + RESET)
        sys.exit(1)

    current_interface = active_interfaces[0]
    print(f"{GREEN}Current connected interface: {current_interface}{RESET}")
    
    print("Other active network interfaces:")
    for i, iface in enumerate(active_interfaces):
        if iface != current_interface:
            print(f"  {i + 1}. {iface}")

    iface_choice = input(f"Enter the number of the network interface you want to use (default is {current_interface}): ")
    chosen_interface = current_interface
    if iface_choice.isdigit() and 0 < int(iface_choice) <= len(active_interfaces):
        chosen_interface = active_interfaces[int(iface_choice) - 1]

    gateway = get_gateway(chosen_interface)
    print(f"{CYAN}Gateway for interface {chosen_interface}: {gateway}{RESET}")

    ip_range = input(f"Enter the IP range to scan (default is calculated from your interface): ").strip()
    if not ip_range:
        ip_range = get_ip_range(chosen_interface)

    if not validate_ip(ip_range):
        print(RED + "Invalid IP range format." + RESET)
        return

    timeout = input("Enter timeout for ARP scan in seconds (default is 2): ").strip()
    timeout = int(timeout) if timeout.isdigit() and int(timeout) > 0 else 2

    devices = get_ip_mac_pairs(ip_range, timeout=timeout)

    open_ports = scan_all_ports(devices)

    save_choice = input(f"Do you want to save the results to a CSV file? (y/n): ").strip().lower()
    if save_choice == 'y':
        output_file = input("Enter the output file name (default is results.csv): ").strip()
        output_file = output_file if output_file else "results.csv"
        save_results_to_csv(devices, open_ports, output_file)

if __name__ == "__main__":
    main()
