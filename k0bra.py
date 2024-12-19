#!/usr/bin/env python3
import asyncio
import os
import ipaddress
import json
import socket
import termcolor
import sys
import xml.etree.ElementTree as ET
import random
import curses
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from typing import List, Dict, Optional, Any

# Previous scanner code remains the same until the menu implementation

class ScannerMenu:
    """Interactive menu system for the Enhanced Network Scanner."""
    
    def __init__(self):
        self.config = {
            'network': '',
            'port_range': '1-1000',
            'batch_size': 500,
            'timeout_ms': 1500,
            'ulimit': 5000,
            'scan_order': 'serial',
            'max_retries': 3,
            'output_format': 'fancy',
            'max_workers': 50,
            'verbose': False,
            'skip_empty_ranges': True,
            'greppable': False,
            'custom_ports': [],
            'service_detection': True,
            'banner_grabbing': True,
            'aggressive_scan': False
        }
        
        self.menu_items = {
            'main': [
                "1. Set Target Network",
                "2. Configure Scan Options",
                "3. Configure Performance Settings",
                "4. Configure Output Settings",
                "5. Advanced Options",
                "6. Start Scan",
                "7. Save Configuration",
                "8. Load Configuration",
                "9. Exit"
            ],
            'scan_options': [
                "1. Set Port Range",
                "2. Add Custom Ports",
                "3. Toggle Service Detection",
                "4. Toggle Banner Grabbing",
                "5. Set Scan Order (Serial/Random)",
                "6. Toggle Aggressive Scan",
                "7. Back to Main Menu"
            ],
            'performance': [
                "1. Set Batch Size",
                "2. Set Timeout (ms)",
                "3. Set Ulimit",
                "4. Set Max Workers",
                "5. Set Max Retries",
                "6. Toggle Skip Empty Ranges",
                "7. Back to Main Menu"
            ],
            'output': [
                "1. Set Output Format",
                "2. Toggle Verbose Mode",
                "3. Toggle Greppable Output",
                "4. Configure Custom Output Path",
                "5. Back to Main Menu"
            ],
            'advanced': [
                "1. Configure Proxy Settings",
                "2. Set Custom User Agent",
                "3. Configure Rate Limiting",
                "4. Set Custom Scripts",
                "5. Configure Host Discovery Methods",
                "6. Back to Main Menu"
            ]
        }

    def display_banner(self):
        """Display the scanner banner with enhanced ASCII art."""
        banner = """
╔══════════════════════════════════════════════════╗
║     Enhanced Network Scanner v2.0                ║
║                                                  ║
║  _      ___   _                                 ║
║ | | __ / _ \\ | |__   _ __   __ _               ║
║ | |/ /| | | || '_ \\ | '__| / _` |              ║
║ |   < | |_| || |_) || |   | (_| |              ║
║ |_|\\_\\ \\___/ |_.__/ |_|    \\__,_|              ║
║                                                  ║
║  Combined with RustScan Features                 ║
╚══════════════════════════════════════════════════╝
"""
        print(banner)

    def display_menu(self, menu_type='main'):
        """Display the specified menu type with enhanced formatting."""
        self.clear_screen()
        self.display_banner()
        
        if menu_type == 'main':
            print("\n=== Main Menu ===")
        elif menu_type == 'scan_options':
            print("\n=== Scan Configuration ===")
        elif menu_type == 'performance':
            print("\n=== Performance Settings ===")
        elif menu_type == 'output':
            print("\n=== Output Settings ===")
        elif menu_type == 'advanced':
            print("\n=== Advanced Options ===")
            
        print("\nCurrent Configuration:")
        self.display_current_config()
        
        print("\nAvailable Options:")
        for item in self.menu_items[menu_type]:
            print(item)

    def display_current_config(self):
        """Display the current configuration settings."""
        important_settings = {
            'Network': self.config['network'],
            'Port Range': self.config['port_range'],
            'Batch Size': self.config['batch_size'],
            'Scan Order': self.config['scan_order'],
            'Output Format': self.config['output_format'],
            'Verbose': self.config['verbose']
        }
        
        for key, value in important_settings.items():
            print(f"{key}: {value}")

    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def get_input(self, prompt, valid_options=None):
        """Get user input with validation."""
        while True:
            user_input = input(prompt).strip()
            if valid_options is None or user_input in valid_options:
                return user_input
            print(f"Invalid input. Please choose from: {', '.join(valid_options)}")

    def handle_main_menu(self):
        """Handle the main menu interactions."""
        while True:
            self.display_menu('main')
            choice = self.get_input("\nEnter your choice (1-9): ", [str(i) for i in range(1, 10)])
            
            if choice == '1':
                self.config['network'] = self.get_input("Enter target network (e.g., 192.168.1.0/24): ")
            elif choice == '2':
                self.handle_scan_options()
            elif choice == '3':
                self.handle_performance_settings()
            elif choice == '4':
                self.handle_output_settings()
            elif choice == '5':
                self.handle_advanced_options()
            elif choice == '6':
                self.start_scan()
            elif choice == '7':
                self.save_configuration()
            elif choice == '8':
                self.load_configuration()
            elif choice == '9':
                if self.confirm_exit():
                    break

    def handle_scan_options(self):
        """Handle scan options menu."""
        while True:
            self.display_menu('scan_options')
            choice = self.get_input("\nEnter your choice (1-7): ", [str(i) for i in range(1, 8)])
            
            if choice == '1':
                self.config['port_range'] = self.get_input("Enter port range (e.g., 1-1000): ")
            elif choice == '2':
                ports = self.get_input("Enter custom ports (comma-separated): ")
                self.config['custom_ports'] = [int(p.strip()) for p in ports.split(',')]
            elif choice == '3':
                self.config['service_detection'] = not self.config['service_detection']
                print(f"Service detection {'enabled' if self.config['service_detection'] else 'disabled'}")
            elif choice == '4':
                self.config['banner_grabbing'] = not self.config['banner_grabbing']
                print(f"Banner grabbing {'enabled' if self.config['banner_grabbing'] else 'disabled'}")
            elif choice == '5':
                self.config['scan_order'] = self.get_input("Enter scan order (serial/random): ", ['serial', 'random'])
            elif choice == '6':
                self.config['aggressive_scan'] = not self.config['aggressive_scan']
                print(f"Aggressive scan {'enabled' if self.config['aggressive_scan'] else 'disabled'}")
            elif choice == '7':
                break

    def handle_performance_settings(self):
        """Handle performance settings menu."""
        while True:
            self.display_menu('performance')
            choice = self.get_input("\nEnter your choice (1-7): ", [str(i) for i in range(1, 8)])
            
            if choice == '1':
                self.config['batch_size'] = int(self.get_input("Enter batch size (default 500): "))
            elif choice == '2':
                self.config['timeout_ms'] = int(self.get_input("Enter timeout in milliseconds (default 1500): "))
            elif choice == '3':
                self.config['ulimit'] = int(self.get_input("Enter ulimit value (default 5000): "))
            elif choice == '4':
                self.config['max_workers'] = int(self.get_input("Enter max workers (default 50): "))
            elif choice == '5':
                self.config['max_retries'] = int(self.get_input("Enter max retries (default 3): "))
            elif choice == '6':
                self.config['skip_empty_ranges'] = not self.config['skip_empty_ranges']
                print(f"Skip empty ranges {'enabled' if self.config['skip_empty_ranges'] else 'disabled'}")
            elif choice == '7':
                break

    def handle_output_settings(self):
        """Handle output settings menu."""
        while True:
            self.display_menu('output')
            choice = self.get_input("\nEnter your choice (1-5): ", [str(i) for i in range(1, 6)])
            
            if choice == '1':
                formats = ['fancy', 'json', 'xml', 'text']
                self.config['output_format'] = self.get_input(
                    f"Enter output format ({'/'.join(formats)}): ",
                    formats
                )
            elif choice == '2':
                self.config['verbose'] = not self.config['verbose']
                print(f"Verbose mode {'enabled' if self.config['verbose'] else 'disabled'}")
            elif choice == '3':
                self.config['greppable'] = not self.config['greppable']
                print(f"Greppable output {'enabled' if self.config['greppable'] else 'disabled'}")
            elif choice == '4':
                self.config['output_path'] = self.get_input("Enter output file path: ")
            elif choice == '5':
                break

    def handle_advanced_options(self):
        """Handle advanced options menu."""
        while True:
            self.display_menu('advanced')
            choice = self.get_input("\nEnter your choice (1-6): ", [str(i) for i in range(1, 7)])
            
            if choice == '1':
                proxy = self.get_input("Enter proxy (e.g., socks5://127.0.0.1:9050): ")
                self.config['proxy'] = proxy
            elif choice == '2':
                user_agent = self.get_input("Enter custom User-Agent: ")
                self.config['user_agent'] = user_agent
            elif choice == '3':
                rate = self.get_input("Enter rate limit (packets per second): ")
                self.config['rate_limit'] = int(rate)
            elif choice == '4':
                script = self.get_input("Enter path to custom script: ")
                self.config['custom_script'] = script
            elif choice == '5':
                methods = ['arp', 'ping', 'both']
                method = self.get_input(f"Enter host discovery method ({'/'.join(methods)}): ", methods)
                self.config['host_discovery'] = method
            elif choice == '6':
                break

    def confirm_exit(self):
        """Confirm before exiting the program."""
        return self.get_input("Are you sure you want to exit? (y/n): ").lower() == 'y'

    def save_configuration(self):
        """Save current configuration to a JSON file."""
        filename = self.get_input("Enter filename to save configuration: ")
        with open(filename, 'w') as f:
            json.dump(self.config, f, indent=2)
        print(f"Configuration saved to {filename}")

    def load_configuration(self):
        """Load configuration from a JSON file."""
        filename = self.get_input("Enter filename to load configuration: ")
        try:
            with open(filename, 'r') as f:
                self.config = json.load(f)
            print(f"Configuration loaded from {filename}")
        except FileNotFoundError:
            print("Configuration file not found.")

    def start_scan(self):
        """Initialize and start the network scan."""
        if not self.config['network']:
            print("Error: Target network not set!")
            input("Press Enter to continue...")
            return
            
        print("\nInitiating scan with current configuration...")
        scanner = EnhancedNetworkScanner(**self.config)
        try:
            results = asyncio.run(scanner.run())
            print(results)
            input("\nScan complete. Press Enter to continue...")
        except Exception as e:
            print(f"Scan error: {e}")
            input("Press Enter to continue...")

def main():
    """Main entry point with menu-driven interface."""
    if not (hasattr(os, 'geteuid') and os.geteuid() == 0):
        print("[ERROR] This tool requires root/sudo privileges")
        sys.exit(1)
        
    menu = ScannerMenu()
    menu.handle_main_menu()

if __name__ == "__main__":
    main()
