#!/usr/bin/env python3 
import scapy.all as scapy
import netifaces
import sys
import csv
import subprocess
import os
from typing import List, Dict

def print_header():
    print("    ██   ██  ██████  ██████  ██████   █████  ")
    print("    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ")
    print("    █████   ██ ██ ██ ██████  ██████  ███████ ")
    print("    ██  ██  ████  ██ ██   ██ ██   ██ ██   ██ ")
    print("    ██   ██  ██████  ██████  ██   ██ ██   ██ ")
    print("Welcome to k0bra - The Network Scavenger! Developed by b0urn3.")
    print("Other tools found at https://github.com/q4n0")
    print("Email: b0urn3@proton.me Instagram: onlybyhive\n")

def is_masscan_installed() -> bool:
    """Check if Masscan is installed."""
    try:
        subprocess.run(["masscan", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False

def install_masscan():
    """Install Masscan in the background."""
    print("Masscan not found. Installing in the background...")
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
        
        # Calculate the network address
        ip_parts = ip.split('.')
        mask_parts = subnet_mask.split('.')
        network_address = '.'.join(str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4))
        return f"{network_address}/24"
    except KeyError:
        print(f"Could not retrieve IP information for interface: {interface}")
        sys.exit(1)

def get_gateway(interface: str) -> str:
    """Retrieve the gateway for the chosen interface."""
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
        print(f"Found device: IP: {device_info['IP']}, MAC: {device_info['MAC']}")  # Debug output
    return devices

def masscan_scan(ip_range: str, port_range: str = "0-65535", rate: int = 50000) -> Dict[str, List[int]]:
    """Use Masscan to scan ports with configurable parameters."""
    masscan_results = {}
    
    # Set stealth parameters
    stealth_options = f"--rate {rate}"  # Stealth options for Masscan

    # Run Masscan command
    command = f"masscan {ip_range} -p{port_range} {stealth_options} --wait 2"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        for line in result.splitlines():
            if line.startswith('Discovered'):
                parts = line.split()
                # The correct format of masscan output is:
                # 'Discovered open port <port>/<protocol> on <ip>'
                port = int(parts[3].split('/')[0])  # Extract port from <port>/<protocol>
                ip = parts[5]  # Extract IP address
                if ip not in masscan_results:
                    masscan_results[ip] = []
                masscan_results[ip].append(port)
    except subprocess.CalledProcessError as e:
        print(f"Masscan failed: {e}")
    return masscan_results


def scan_all_ports(devices: List[Dict[str, str]], port_range: str = "0-65535", rate: int = 50000) -> Dict[str, List[int]]:
    """Scan open ports on all devices using Masscan."""
    results = {}
    ip_range = ','.join(device['IP'] for device in devices)
    print(f"Using Masscan to scan range: {ip_range}")
    masscan_results = masscan_scan(ip_range, port_range=port_range, rate=rate)
    
    for device in devices:
        ip = device['IP']
        if ip in masscan_results:
            results[ip] = masscan_results[ip]  # Store open ports for each IP
    return results

def save_results_to_csv(devices: List[Dict[str, str]], open_ports: Dict[str, List[int]], output_file: str):
    """Save the found devices and their open ports to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'MAC', 'Open Ports']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for device in devices:
            ip = device['IP']
            mac = device['MAC']
            ports = ', '.join(map(str, open_ports.get(ip, [])))
            writer.writerow({'IP': ip, 'MAC': mac, 'Open Ports': ports})

    print(f"Results saved to {output_file}")

def main():
    print_header()

    if not is_masscan_installed():
        install_masscan()
        print("Please run the script again after Masscan installation.")
        sys.exit(1)

    active_interfaces = get_active_interfaces()
    if not active_interfaces:
        print("No active network interfaces found.")
        sys.exit(1)

    current_interface = active_interfaces[0]
    print(f"Current connected interface: {current_interface}")
    
    print("Other active network interfaces:")
    for i, iface in enumerate(active_interfaces):
        if iface != current_interface:
            print(f"  {i + 1}. {iface}")

    iface_choice = input(f"Enter the number of the network interface you want to use (default is {current_interface}): ")
    if iface_choice.isdigit() and 0 < int(iface_choice) <= len(active_interfaces):
        chosen_interface = active_interfaces[int(iface_choice) - 1]
    else:
        chosen_interface = current_interface

    # Get the gateway for the chosen interface
    gateway = get_gateway(chosen_interface)
    print(f"Gateway for interface {chosen_interface}: {gateway}")

    # Customize IP range
    ip_range = input("Enter the IP range to scan (default is calculated from your interface): ").strip()
    if not ip_range:
        ip_range = get_ip_range(chosen_interface)
    
    timeout = input("Enter timeout for ARP scan in seconds (default is 2): ").strip()
    timeout = int(timeout) if timeout.isdigit() else 2

    print(f"\nStarting scan on interface: {chosen_interface}")
    print(f"Scanning IP range: {ip_range} with a timeout of {timeout} seconds.\n")

    devices = get_ip_mac_pairs(ip_range, timeout=timeout)

    if not devices:
        print("No devices found on the network.")
    else:
        print("\nDevices found:")
        for device in devices:
            print(f"IP: {device['IP']}, MAC: {device['MAC']}")

        port_range = input("Enter port range to scan (default is 0-65535): ").strip() or "0-65535"
        rate = input("Enter scan rate for Masscan (default is 50000): ").strip()
        rate = int(rate) if rate.isdigit() else 50000

        open_ports = scan_all_ports(devices, port_range=port_range, rate=rate)

        for ip, ports in open_ports.items():
            print(f"IP: {ip}, Open Ports: {ports}")
        
        save_option = input("Do you want to save the results to a CSV file? (y/n): ").strip().lower()
        if save_option == 'y':
            output_file = input("Enter the output CSV file name (default is 'scan_results.csv'): ").strip() or "scan_results.csv"
            save_results_to_csv(devices, open_ports, output_file)

if __name__ == "__main__":
    main()
