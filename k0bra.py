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
import nmap
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import tkinter as tk
from tkinter import ttk
import argparse
import socket

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
    print(CYAN + "    ██   ██  ██████  ██████  ██████  ██████   █████  ")
    print("    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ ██   ██ ")
    print("    █████   ██ ██ ██ ██████  ██████  ██████  ███████ ")
    print("    ██  ██  ████  ██   ██ ██   ██ ██   ██ ██   ██ ")
    print("    ██   ██  ██████  ██   ██ ██   ██ ██   ██ ██   ██ " + RESET)
    print(GREEN + "Welcome to k0bra - The Network Scavenger! Developed by b0urn3.")
    print("Other tools found at https://github.com/q4n0")
    print("Email: b0urn3@proton.me Instagram: onlybyhive\n" + RESET)

def handle_exit(signum, frame):
    """Handle clean exit on Ctrl + C."""
    logging.info("Exiting gracefully... (Ctrl + C detected)")
    print(RED + "\nExiting gracefully... (Ctrl + C detected)" + RESET)
    sys.exit(0)

def is_masscan_installed() -> bool:
    try:
        subprocess.run(["masscan", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        logging.error("Masscan not found.")
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
    except KeyError as e:
        logging.error(f"Could not retrieve IP information for interface: {interface}. Error: {e}")
        print(RED + f"Could not retrieve IP information for interface: {interface}" + RESET)
        sys.exit(1)

def get_gateway(interface: str) -> str:
    gateways = netifaces.gateways()
    if interface in gateways[netifaces.AF_INET]:
        return gateways[netifaces.AF_INET][interface][0]
    return None

async def get_ip_mac_pairs(ip_range: str, timeout: int = 2) -> List[Dict[str, str]]:
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = await asyncio.create_task(scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False))

    devices = []
    for element in answered_list[0]:
        device_info = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        devices.append(device_info)
        print(f"{GREEN}Found device: IP: {device_info['IP']}, MAC: {device_info['MAC']}{RESET}")
        await asyncio.sleep(1)  # Delay to avoid hitting API rate limits
    return devices

def masscan_scan(ip_range: str, port_range: str = "0-65535", rate: int = 50000, decoy: str = None, randomize: bool = False, wait: int = 2) -> Dict[str, List[int]]:
    masscan_results = {}
    stealth_options = f"--rate {rate}"  # Stealth options for Masscan
    if decoy:
        stealth_options += f" --randomize-hosts {decoy}"
    if randomize:
        stealth_options += " --randomize-hosts"
    command = f"masscan {ip_range} -p{port_range} {stealth_options} --wait {wait}"
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
        logging.error(f"Masscan failed: {e}")
        print(RED + f"Masscan failed: {e}" + RESET)
    return masscan_results

def nmap_scan(ip_range: str, port_range: str = "1-65535", scan_type="sS", decoy=None, fragment=False, proxies=None, source_port=None, timing=3, scripts=None, service_detection=False, os_detection=False) -> Dict[str, List[int]]:
    nm = nmap.PortScanner()
    print(BLUE + f"Scanning using Nmap on range: {ip_range}" + RESET)

    try:
        nmap_args = f'-p {port_range} -{scan_type} -T{timing}'

        if decoy:
            nmap_args += f' -D {decoy}'
        if fragment:
            nmap_args += ' -f'
        if proxies:
            nmap_args += f' --proxies {proxies}'
        if source_port:
            nmap_args += f' -g {source_port}'
        if scripts:
            nmap_args += f' --script {scripts}'
        if service_detection:
            nmap_args += ' -sV'
        if os_detection:
            nmap_args += ' -O'

        nm.scan(hosts=ip_range, arguments=nmap_args)
    except Exception as e:
        logging.error(f"Nmap scan failed: {e}")
        print(RED + f"Nmap scan failed: {e}" + RESET)
        return {}

    nmap_results = {}
    for host in nm.all_hosts():
        if 'tcp' in nm[host]:
            open_ports = [port for port in nm[host]['tcp'] if nm[host]['tcp'][port]['state'] == 'open']
            nmap_results[host] = open_ports
            print(f"{GREEN}Found open ports on {host}: {open_ports}{RESET}")

    return nmap_results

async def scan_all_ports(devices: List[Dict[str, str]], port_range: str = "0-65535", scan_tool: str = "masscan", **kwargs) -> Dict[str, List[int]]:
    results = {}
    ip_range = ','.join(device['IP'] for device in devices)

    loop = asyncio.get_event_loop()
    if scan_tool == "masscan":
        print(BLUE + f"Using Masscan to scan range: {ip_range}" + RESET)
        future = loop.run_in_executor(None, masscan_scan, ip_range, port_range, **kwargs)
        masscan_results = await future

        for device in devices:
            ip = device['IP']
            if ip in masscan_results:
                results[ip] = masscan_results[ip]
    elif scan_tool == "nmap":
        future = loop.run_in_executor(None, nmap_scan, ip_range, port_range, **kwargs)
        results = await future

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

def parse_arguments():
    parser = argparse.ArgumentParser(description="k0bra - The Network Scavenger")
    parser.add_argument('--interface', type=str, help='Network interface to use')
    parser.add_argument('--ip-range', type=str, help='IP range to scan')
    parser.add_argument('--timeout', type=int, default=2, help='Timeout for ARP scan in seconds')
    parser.add_argument('--scan-tool', choices=['masscan', 'nmap'], default='masscan', help='Scanning tool to use')
    parser.add_argument('--output', type=str, default='results.csv', help='Output CSV file name')
    parser.add_argument('--target', type=str, help='Custom target IP range to scan')
    return parser.parse_args()

def create_gui():
    root = tk.Tk()
    root.title("k0bra - The Network Scavenger")

    frame = ttk.Frame(root, padding="10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    ttk.Label(frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W)
    interface_var = tk.StringVar()
    interface_entry = ttk.Entry(frame, textvariable=interface_var)
    interface_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

    ttk.Label(frame, text="IP Range:").grid(row=1, column=0, sticky=tk.W)
    ip_range_var = tk.StringVar()
    ip_range_entry = ttk.Entry(frame, textvariable=ip_range_var)
    ip_range_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))

    ttk.Label(frame, text="Custom Target:").grid(row=2, column=0, sticky=tk.W)
    target_var = tk.StringVar()
    target_entry = ttk.Entry(frame, textvariable=target_var)
    target_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))

    ttk.Label(frame, text="Scan Tool:").grid(row=3, column=0, sticky=tk.W)
    scan_tool_var = tk.StringVar(value="masscan")
    ttk.Radiobutton(frame, text="Masscan", variable=scan_tool_var, value="masscan").grid(row=3, column=1, sticky=tk.W)
    ttk.Radiobutton(frame, text="Nmap", variable=scan_tool_var, value="nmap").grid(row=4, column=1, sticky=tk.W)

    ttk.Button(frame, text="Start Scan", command=lambda: start_scan(interface_var.get(), ip_range_var.get(), scan_tool_var.get(), target_var.get())).grid(row=5, column=1, sticky=tk.E)

    root.mainloop()

def start_scan(interface, ip_range, scan_tool, target):
    # Implement the scan logic here
    args = argparse.Namespace(interface=interface, ip_range=ip_range, scan_tool=scan_tool, output='results.csv', target=target)
    asyncio.run(main(args))

def interactive_menu():
    print_banner()
    print(GREEN + "Interactive Menu:" + RESET)
    print("1. Scan Local Network")
    print("2. Scan WAN Target")
    print("3. Exit")

    choice = input("Enter your choice: ")
    if choice == '1':
        asyncio.run(scan_local_network())
    elif choice == '2':
        asyncio.run(scan_wan_target())
    elif choice == '3':
        sys.exit(0)
    else:
        print(RED + "Invalid choice. Please try again." + RESET)
        interactive_menu()

async def scan_local_network():
    active_interfaces = get_active_interfaces()
    if not active_interfaces:
        print(RED + "No active network interfaces found." + RESET)
        sys.exit(1)

    print(f"{GREEN}Active interfaces: {active_interfaces}{RESET}")
    print(f"{GREEN}Available interfaces:{RESET}")
    for i, iface in enumerate(active_interfaces):
        print(f"  {i + 1}. {iface}")
    iface_choice = input(f"Enter the number of the network interface you want to use: ")
    if iface_choice.isdigit() and 0 < int(iface_choice) <= len(active_interfaces):
        chosen_interface = active_interfaces[int(iface_choice) - 1]
    else:
        print(RED + "Invalid choice. Using default interface." + RESET)
        chosen_interface = active_interfaces[0]

    print(f"{GREEN}Current connected interface: {chosen_interface}{RESET}")
    ip_range = get_ip_range(chosen_interface)

    perform_arp = input("Do you want to perform an ARP scan? (yes/no): ").strip().lower()
    if perform_arp == 'yes':
        timeout = input("Enter timeout for ARP scan in seconds (default is 2): ").strip()
        timeout = int(timeout) if timeout.isdigit() else 2
        devices = await get_ip_mac_pairs(ip_range, timeout=timeout)

        if not devices:
            print(RED + "No devices found." + RESET)
            return

        scan_tool = input("Choose scanning tool (1 for Masscan, 2 for Nmap, default is Masscan): ").strip()
        if not scan_tool or scan_tool == '1':
            port_range = input("Enter port range for Masscan (default is 0-65535): ").strip()
            port_range = port_range if port_range else "0-65535"
            rate = input("Enter rate for Masscan (default is 50000): ").strip()
            rate = int(rate) if rate.isdigit() else 50000
            decoy = input("Enter decoy IPs for Masscan (comma-separated, default is none): ").strip()
            randomize = input("Randomize scan order for Masscan? (yes/no, default is no): ").strip().lower() == 'yes'
            wait = input("Enter wait time between scans for Masscan (default is 2): ").strip()
            wait = int(wait) if wait.isdigit() else 2
            open_ports = await scan_all_ports(devices, scan_tool='masscan', port_range=port_range, rate=rate, decoy=decoy, randomize=randomize, wait=wait)
        elif scan_tool == '2':
            scan_type = input("Choose scan type for Nmap (sS for SYN scan, sT for TCP connect, sU for UDP scan, default is sS): ").strip()
            scan_type = scan_type if scan_type in ['sS', 'sT', 'sU'] else 'sS'
            service_detection = input("Enable service version detection for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
            os_detection = input("Enable OS detection for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
            decoy = input("Enter decoy IPs for Nmap (comma-separated, default is none): ").strip()
            fragment = input("Enable fragmentation for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
            proxies = input("Enter proxies for Nmap (default is none): ").strip()
            source_port = input("Enter source port for Nmap (default is none): ").strip()
            timing = input("Enter timing template for Nmap (0 to 5, default is 3): ").strip()
            timing = int(timing) if timing.isdigit() and 0 <= int(timing) <= 5 else 3
            scripts = input("Enter NSE scripts for Nmap (comma-separated, default is none): ").strip()
            open_ports = await scan_all_ports(devices, scan_tool='nmap', scan_type=scan_type, service_detection=service_detection, os_detection=os_detection, decoy=decoy, fragment=fragment, proxies=proxies, source_port=source_port, timing=timing, scripts=scripts)

        output_file = input("Enter output CSV file name (default is results.csv): ").strip()
        if not output_file:
            output_file = 'results.csv'

        save_results_to_csv(devices, open_ports, output_file)
        print_scan_results(devices, open_ports)
    else:
        print(YELLOW + "Skipping ARP scan." + RESET)
        await target_scan(chosen_interface, ip_range)

async def scan_wan_target():
    target = input("Enter the WAN target (IP or domain name): ").strip()
    try:
        ip_range = socket.gethostbyname(target)
        print(f"{GREEN}Resolved target {target} to IP: {ip_range}{RESET}")
    except socket.gaierror:
        print(RED + f"Could not resolve target {target}. Please check the target and try again." + RESET)
        return

    scan_tool = input("Choose scanning tool (1 for Masscan, 2 for Nmap, default is Masscan): ").strip()
    if not scan_tool or scan_tool == '1':
        port_range = input("Enter port range for Masscan (default is 0-65535): ").strip()
        port_range = port_range if port_range else "0-65535"
        rate = input("Enter rate for Masscan (default is 50000): ").strip()
        rate = int(rate) if rate.isdigit() else 50000
        decoy = input("Enter decoy IPs for Masscan (comma-separated, default is none): ").strip()
        randomize = input("Randomize scan order for Masscan? (yes/no, default is no): ").strip().lower() == 'yes'
        wait = input("Enter wait time between scans for Masscan (default is 2): ").strip()
        wait = int(wait) if wait.isdigit() else 2
        open_ports = await scan_all_ports([{'IP': ip_range}], scan_tool='masscan', port_range=port_range, rate=rate, decoy=decoy, randomize=randomize, wait=wait)
    elif scan_tool == '2':
        scan_type = input("Choose scan type for Nmap (sS for SYN scan, sT for TCP connect, sU for UDP scan, default is sS): ").strip()
        scan_type = scan_type if scan_type in ['sS', 'sT', 'sU'] else 'sS'
        service_detection = input("Enable service version detection for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
        os_detection = input("Enable OS detection for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
        decoy = input("Enter decoy IPs for Nmap (comma-separated, default is none): ").strip()
        fragment = input("Enable fragmentation for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
        proxies = input("Enter proxies for Nmap (default is none): ").strip()
        source_port = input("Enter source port for Nmap (default is none): ").strip()
        timing = input("Enter timing template for Nmap (0 to 5, default is 3): ").strip()
        timing = int(timing) if timing.isdigit() and 0 <= int(timing) <= 5 else 3
        scripts = input("Enter NSE scripts for Nmap (comma-separated, default is none): ").strip()
        open_ports = await scan_all_ports([{'IP': ip_range}], scan_tool='nmap', scan_type=scan_type, service_detection=service_detection, os_detection=os_detection, decoy=decoy, fragment=fragment, proxies=proxies, source_port=source_port, timing=timing, scripts=scripts)

    output_file = input("Enter output CSV file name (default is results.csv): ").strip()
    if not output_file:
        output_file = 'results.csv'

    save_results_to_csv([{'IP': ip_range}], open_ports, output_file)
    print_scan_results([{'IP': ip_range}], open_ports)

async def target_scan(interface, ip_range):
    scan_tool = input("Choose scanning tool (1 for Masscan, 2 for Nmap, default is Masscan): ").strip()
    if not scan_tool or scan_tool == '1':
        port_range = input("Enter port range for Masscan (default is 0-65535): ").strip()
        port_range = port_range if port_range else "0-65535"
        rate = input("Enter rate for Masscan (default is 50000): ").strip()
        rate = int(rate) if rate.isdigit() else 50000
        decoy = input("Enter decoy IPs for Masscan (comma-separated, default is none): ").strip()
        randomize = input("Randomize scan order for Masscan? (yes/no, default is no): ").strip().lower() == 'yes'
        wait = input("Enter wait time between scans for Masscan (default is 2): ").strip()
        wait = int(wait) if wait.isdigit() else 2
        open_ports = await scan_all_ports([{'IP': ip_range}], scan_tool='masscan', port_range=port_range, rate=rate, decoy=decoy, randomize=randomize, wait=wait)
    elif scan_tool == '2':
        scan_type = input("Choose scan type for Nmap (sS for SYN scan, sT for TCP connect, sU for UDP scan, default is sS): ").strip()
        scan_type = scan_type if scan_type in ['sS', 'sT', 'sU'] else 'sS'
        service_detection = input("Enable service version detection for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
        os_detection = input("Enable OS detection for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
        decoy = input("Enter decoy IPs for Nmap (comma-separated, default is none): ").strip()
        fragment = input("Enable fragmentation for Nmap? (yes/no, default is no): ").strip().lower() == 'yes'
        proxies = input("Enter proxies for Nmap (default is none): ").strip()
        source_port = input("Enter source port for Nmap (default is none): ").strip()
        timing = input("Enter timing template for Nmap (0 to 5, default is 3): ").strip()
        timing = int(timing) if timing.isdigit() and 0 <= int(timing) <= 5 else 3
        scripts = input("Enter NSE scripts for Nmap (comma-separated, default is none): ").strip()
        open_ports = await scan_all_ports([{'IP': ip_range}], scan_tool='nmap', scan_type=scan_type, service_detection=service_detection, os_detection=os_detection, decoy=decoy, fragment=fragment, proxies=proxies, source_port=source_port, timing=timing, scripts=scripts)

    output_file = input("Enter output CSV file name (default is results.csv): ").strip()
    if not output_file:
        output_file = 'results.csv'

    save_results_to_csv([{'IP': ip_range}], open_ports, output_file)
    print_scan_results([{'IP': ip_range}], open_ports)

def print_scan_results(devices, open_ports):
    print(GREEN + "Scan Results:" + RESET)
    for device in devices:
        ip = device['IP']
        mac = device.get('MAC', 'N/A')
        ports = ', '.join(map(str, open_ports.get(ip, [])))
        print(f"IP: {ip}, MAC: {mac}, Open Ports: {ports}")

async def main(args=None):
    if args is None:
        args = parse_arguments()

    # Handle Ctrl+C for clean exit
    signal.signal(signal.SIGINT, handle_exit)

    print_banner()

    if not is_masscan_installed():
        install_masscan()
        print(YELLOW + "Please run the script again after Masscan installation." + RESET)
        sys.exit(1)

    await interactive_menu()

if __name__ == "__main__":
    asyncio.run(main())
