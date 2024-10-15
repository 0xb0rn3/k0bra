import scapy.all as scapy
import netifaces
import sys
import csv
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

def get_active_interfaces() -> List[str]:
    interfaces = netifaces.interfaces()
    active_interfaces = []
    for iface in interfaces:
        iface_info = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_info:
            active_interfaces.append(iface)
    return active_interfaces

def get_ip_range(interface: str) -> str:
    iface_info = netifaces.ifaddresses(interface)
    ip_info = iface_info[netifaces.AF_INET]
    ip = ip_info[0]['addr']
    subnet_mask = ip_info[0]['netmask']
    
    # Calculate the network address
    ip_parts = ip.split('.')
    mask_parts = subnet_mask.split('.')
    network_address = '.'.join(str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4))
    
    return f"{network_address}/24"

def get_gateway(interface: str) -> str:
    """Retrieve the gateway for the chosen interface."""
    gateways = netifaces.gateways()
    if interface in gateways[netifaces.AF_INET]:
        return gateways[netifaces.AF_INET][interface][0]
    return None

def get_ip_mac_pairs(ip_range: str) -> List[Dict[str, str]]:
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device_info = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        devices.append(device_info)
        print(f"Found device: IP: {device_info['IP']}, MAC: {device_info['MAC']}")  # Debug output
    return devices

def save_results_to_csv(devices: List[Dict[str, str]], output_file: str):
    """Save the found devices to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'MAC']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for device in devices:
            writer.writerow(device)

    print(f"Results saved to {output_file}")

def main():
    print_header()

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
    print(f"\nStarting scan on interface: {chosen_interface}")
    print(f"Scanning IP range: {ip_range}\n")

    devices = get_ip_mac_pairs(ip_range)

    if not devices:
        print("No devices found on the network.")
    else:
        print("\nDevices found:")
        for device in devices:
            print(f"IP: {device['IP']}, MAC: {device['MAC']}")

        # Prompt to save results
        save_choice = input("Do you want to save the results to a CSV file? (y/n): ").strip().lower()
        if save_choice == 'y':
            output_file = input("Enter the output filename (default is 'scan_results.csv'): ").strip() or 'scan_results.csv'
            save_results_to_csv(devices, output_file)

if __name__ == "__main__":
    main()
