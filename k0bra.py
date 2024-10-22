#!/usr/bin/env python3
import scapy.all as scapy
import netifaces
import sys
import csv
import subprocess
import os
import signal
import time
from typing import List, Dict

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

def is_nmap_installed() -> bool:
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def install_nmap():
    print(YELLOW + "Nmap not found. Installing in the background..." + RESET)
    os.system("sudo apt-get install -y nmap &")

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

def get_ip_mac_pairs(ip_range: str, timeout: int = 2) -> List[Dict[str, str]]:
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device_info = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        devices.append(device_info)
        print(f"{GREEN}Found device: IP: {device_info['IP']}, MAC: {device_info['MAC']}{RESET}")
        time.sleep(1)  # Delay to avoid hitting API rate limits
    return devices

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

def nmap_scan(ip_range: str, port_range: str = "1-65535") -> Dict[str, List[int]]:
    nmap_results = {}
    command = f"nmap -p {port_range} {ip_range} -oG -"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        for line in result.splitlines():
            if '/tcp' in line:
                parts = line.split()
                port = int(parts[1])
                ip = parts[0]
                if ip not in nmap_results:
                    nmap_results[ip] = []
                nmap_results[ip].append(port)
    except subprocess.CalledProcessError as e:
        print(RED + f"Nmap failed: {e}" + RESET)
    return nmap_results

def scan_all_ports(devices: List[Dict[str, str]], port_range: str = "0-65535", scanning_tool: str = "masscan") -> Dict[str, List[int]]:
    results = {}
    ip_range = ' '.join(device['IP'] for device in devices)  # Space-separated IPs for Nmap
    print(BLUE + f"Scanning using {scanning_tool.upper()} on range: {ip_range}" + RESET)

    if scanning_tool == "masscan":
        masscan_results = masscan_scan(ip_range, port_range)
        for device in devices:
            ip = device['IP']
            if ip in masscan_results:
                results[ip] = masscan_results[ip]
    elif scanning_tool == "nmap":
        nmap_results = nmap_scan(ip_range, port_range)
        for device in devices:
            ip = device['IP']
            if ip in nmap_results:
                results[ip] = nmap_results[ip]
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
    print_header()
    signal.signal(signal.SIGINT, handle_exit)

    if not is_masscan_installed():
        install_masscan()
    if not is_nmap_installed():
        install_nmap()

    active_interfaces = get_active_interfaces()
    print(YELLOW + "Available interfaces:" + RESET)
    for idx, interface in enumerate(active_interfaces):
        print(f"{idx}: {interface}")

    chosen_interface_index = input(f"Enter the number of the network interface you want to use (default is {active_interfaces[0]}): ")
    chosen_interface = active_interfaces[int(chosen_interface_index) if chosen_interface_index.isdigit() else 0]

    gateway = get_gateway(chosen_interface)
    print(f"Gateway for interface {chosen_interface}: {gateway if gateway else 'None'}")

    ip_range = input("Enter the IP range to scan (default is calculated from your interface): ")
    if not ip_range:
        ip_range = get_ip_range(chosen_interface)
        print(f"{GREEN}Using default IP range: {ip_range}{RESET}")

    devices = get_ip_mac_pairs(ip_range)

    scanning_tool = input(f"Choose scanning tool (1 for Masscan, 2 for Nmap, default is Masscan): ")
    if scanning_tool == '2':
        scanning_tool = "nmap"
    else:
        scanning_tool = "masscan"

    open_ports = scan_all_ports(devices, port_range="0-65535", scanning_tool=scanning_tool)

    output_file = input("Enter output CSV file name (default is results.csv): ").strip() or "results.csv"
    save_results_to_csv(devices, open_ports, output_file)

if __name__ == "__main__":
    main()
