import scapy.all as scapy
import netifaces as ni
import time
import concurrent.futures
from tabulate import tabulate
import os
import json
import argparse
import socket
import asyncio
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
import platform

# Set up logging
logging.basicConfig(filename='k0bra.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Known MAC addresses for whitelist
KNOWN_MACS = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]  # Add known trusted devices here

def display_banner():
    banner = """
██   ██  ██████  ██████  ██████   █████  
██  ██  ██  ████ ██   ██ ██   ██ ██   ██ 
█████   ██ ██ ██ ██████  ██████  ███████ 
██  ██  ████  ██ ██   ██ ██   ██ ██   ██ 
██   ██  ██████  ██████  ██   ██ ██   ██ 
                                         
  """
    print(banner)
    print("Welcome to k0bra - The Network Scavenger! Developed by b0urn3.\n other tools found at https://github.com/q4n0\nEmail: b0urn3@proton.me Instagram: onlybyhive")

def get_mac(ip: str) -> str:
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered_list:
            mac = answered_list[0][1].hwsrc
            return mac
        return "N/A"
    except Exception as e:
        logging.error(f"Error getting MAC for IP {ip}: {e}")
        return "Error"

def detect_unauthorized_device(mac: str) -> bool:
    if mac not in KNOWN_MACS and mac != "N/A":
        logging.warning(f"Unauthorized device detected: MAC {mac}")
        print(f"⚠️  Unauthorized device detected! MAC: {mac}")
        return True
    return False

def get_interface() -> str:
    interfaces = ni.interfaces()
    current_iface = ni.gateways()['default'][ni.AF_INET][1]
    print(f"\nCurrent connected interface: {current_iface}")
    print("Other active network interfaces:")
    for i, iface in enumerate(interfaces):
        if iface == current_iface:
            continue
        print(f"  {i+1}. {iface}")

    choice = input("\nEnter the number of the network interface you want to use (default current interface): ")
    if choice:
        selected_iface = interfaces[int(choice)-1]
    else:
        selected_iface = current_iface
    return selected_iface

def get_ip_mac_pairs(interface: str, ip_range: str) -> List[Dict[str, str]]:
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    devices = []
    for element in answered_list:
        device = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        devices.append(device)
        # Check for unauthorized device
        detect_unauthorized_device(device['MAC'])
    return devices

def scan_ports(ip: str, ports: List[int]) -> List[int]:
    open_ports = []

    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
        except Exception as e:
            logging.error(f"Error scanning port {port} on IP {ip}: {e}")
        finally:
            sock.close()

    with ThreadPoolExecutor() as executor:
        executor.map(check_port, ports)

    return open_ports

async def async_scan(ip_range: str, interface: str, ports: List[int], save_results_option: bool, filters: Dict[str, str]):
    loop = asyncio.get_event_loop()
    devices = await loop.run_in_executor(None, lambda: get_ip_mac_pairs(interface, ip_range))
    
    filtered_devices = apply_filters(devices, filters)
    display_results(filtered_devices, ports)
    
    if save_results_option:
        save_results(filtered_devices, 'scan_results.json')

def apply_filters(devices: List[Dict[str, str]], filters: Dict[str, str]) -> List[Dict[str, str]]:
    filtered_devices = []
    for device in devices:
        if 'ip' in filters and not device['IP'].startswith(filters['ip']):
            continue
        if 'mac_prefix' in filters and not device['MAC'].startswith(filters['mac_prefix']):
            continue
        filtered_devices.append(device)
    return filtered_devices

def display_results(devices: List[Dict[str, str]], ports: List[int]):
    if devices:
        table = tabulate(devices, headers="keys", tablefmt="fancy_grid")
        print(table)
        for device in devices:
            open_ports = scan_ports(device['IP'], ports)
            if open_ports:
                print(f"\nOpen ports for {device['IP']}: {', '.join(map(str, open_ports))}")
    else:
        print("No devices found on the network.")

def save_results(devices: List[Dict[str, str]], filename: str):
    try:
        with open(filename, 'w') as f:
            json.dump(devices, f, indent=4)
        print(f"Results saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving results: {e}")

def scan_network(interface: str, save_results_option: bool, ports: List[int], filters: Dict[str, str]):
    ip_info = ni.ifaddresses(interface).get(ni.AF_INET)
    if not ip_info:
        print("No IP address found for the selected interface.")
        return
    
    ips = ip_info[0]['addr']
    ip_parts = ips.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    print(f"\nScanning IP range: {ip_range}")
    
    try:
        asyncio.run(async_scan(ip_range, interface, ports, save_results_option, filters))
    except KeyboardInterrupt:
        print("\nScan interrupted. Exiting gracefully...")
        clear_terminal()
        print("Exiting k0bra. Goodbye!")
        exit(0)

def load_previous_scan(filename: str) -> List[Dict[str, str]]:
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading previous scan results: {e}")
    return []

def clear_terminal():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(description="k0bra - Network Scanner")
    parser.add_argument("-s", "--save", action="store_true", help="Save results to a file")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[22, 80, 443], help="Specify ports to scan")
    parser.add_argument("-r", "--restore", action="store_true", help="Restore and compare with previous scan results")
    parser.add_argument("--ip-filter", type=str, help="Filter devices by IP range prefix")
    parser.add_argument("--mac-filter", type=str, help="Filter devices by MAC address prefix")
    args = parser.parse_args()

    selected_iface = get_interface()
    print(f"Selected network interface: {selected_iface}")

    filters = {}
    if args.ip_filter:
        filters['ip'] = args.ip_filter
    if args.mac_filter:
        filters['mac_prefix'] = args.mac_filter
    
    if args.restore:
        previous_scan = load_previous_scan('scan_results.json')
        print("\nPrevious Scan Results:")
        print(tabulate(previous_scan, headers="keys", tablefmt="fancy_grid"))

    scan_network(selected_iface, args.save, args.ports, filters)

if __name__ == "__main__":
    main()
