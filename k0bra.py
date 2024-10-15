import subprocess
import json
import argparse
import logging
import os
import platform
from tabulate import tabulate
import netifaces as ni
import time

# Set up logging
logging.basicConfig(filename='k0bra.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def display_banner():
    banner = """
    ██   ██  ██████  ██████  ██████   █████  
    ██  ██  ██  ████ ██   ██ ██   ██ ██   ██ 
    █████   ██ ██ ██ ██████  ██████  ███████ 
    ██  ██  ████  ██ ██   ██ ██   ██ ██   ██ 
    ██   ██  ██████  ██████  ██   ██ ██   ██ 
    """
    print(banner)
    print("Welcome to k0bra - The Network Scavenger! Developed by b0urn3.\nOther tools found at https://github.com/q4n0\nEmail: b0urn3@proton.me Instagram: onlybyhive")

def get_interface() -> str:
    interfaces = ni.interfaces()
    current_iface = ni.gateways()['default'][ni.AF_INET][1]
    print(f"\nCurrent connected interface: {current_iface}")
    print("Other active network interfaces:")
    for i, iface in enumerate(interfaces):
        if iface == current_iface:
            continue
        print(f"  {i+1}. {iface}")

    choice = input("\nEnter the number of the network interface you want to use (default is the current interface): ")
    if choice:
        selected_iface = interfaces[int(choice)-1]
    else:
        selected_iface = current_iface
    return selected_iface

def run_go_scan(ip_range: str) -> list:
    try:
        result = subprocess.run(["./k0bra_go", ip_range], capture_output=True, text=True)
        return json.loads(result.stdout)
    except Exception as e:
        logging.error(f"Error executing Go scan: {e}")
        return []

def display_results(devices: list):
    if devices:
        table = tabulate(devices, headers="keys", tablefmt="fancy_grid")
        print(table)
    else:
        print("No devices found on the network.")

def save_results(devices: list, filename: str):
    try:
        with open(filename, 'w') as f:
            json.dump(devices, f, indent=4)
        print(f"Results saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving results: {e}")

def clear_terminal():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def main():
    display_banner()

    parser = argparse.ArgumentParser(description="k0bra - Network Scanner")
    parser.add_argument("-s", "--save", action="store_true", help="Save results to a file")
    parser.add_argument("--ip-filter", type=str, help="Filter devices by IP range prefix")
    args = parser.parse_args()

    selected_iface = get_interface()
    print(f"\nStarting scan on interface: {selected_iface}\n")
    time.sleep(1)

    ip_info = ni.ifaddresses(selected_iface).get(ni.AF_INET)
    if not ip_info:
        print("No IP address found for the selected interface.")
        return

    ips = ip_info[0]['addr']
    ip_parts = ips.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    print(f"\nScanning IP range: {ip_range}")
    devices = run_go_scan(ip_range)

    if args.ip_filter:
        devices = [device for device in devices if device['IP'].startswith(args.ip_filter)]
    
    display_results(devices)

    if args.save:
        save_results(devices, 'scan_results.json')

if __name__ == "__main__":
    main()
