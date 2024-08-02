import scapy.all as scapy
import netifaces as ni
import time
from tabulate import tabulate

def display_banner():
    banner = """
@@@@@@@@@@@@@@@@@@@@
@@@@@@@*###*#@@@@@@@
@@@@@@*+#*#*+%@@@@@@
@@@@@@*+*##+*%@@@@@@
@@@@@@+--#=-*%@@@@@@
@@@@@@*::=-:=@@@@@@@
@@@@@@@=-*+-*@@@@@@@
@@@@@@@@*++*@@@@@@@@
@@@@@@@@@*-#%%@@@@@@
@@@@@%*#*-:++*%@@@@@
@@@@@#*=::*+**#@@@@@
@@@@@#*++%*=+**@@@@@
@@@@@@%@@@@%%@@@@@@@
@@@@@@@@@@@@@@@@@@@@
    """
    print(banner)
    print("Welcome to k0bra - The Python Network Scavenger! Developed by b0urn3.\n")

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        return "N/A"
    except Exception as e:
        print(f"Error getting MAC for IP {ip}: {e}")
        return "Error"

def get_interface():
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

def get_ip_mac_pairs(interface):
    ip_info = ni.ifaddresses(interface).get(ni.AF_INET)
    if not ip_info:
        return []
    
    ips = ip_info[0]['addr']
    ip_parts = ips.split('.')
    ip_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    
    print(f"\nScanning IP range: {ip_range}")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        devices.append({"IP": element[1].psrc, "MAC": element[1].hwsrc})
    return devices

def main():
    display_banner()
    print("Ready to hunt down the hidden prey on your network!\n")
    
    selected_iface = get_interface()
    print(f"\nStarting scan on interface: {selected_iface}\n")
    time.sleep(1)
    
    devices = get_ip_mac_pairs(selected_iface)
    
    print(f"\nInformation for interface: {selected_iface}\n")
    if devices:
        table = tabulate(devices, headers="keys", tablefmt="fancy_grid")
        print(table)
    else:
        print("No devices found on the network. Did the snakes slither away?\n")

    print("\nScan complete. The hunt is over. Time to slither back!\n")

if __name__ == "__main__":
    main()
