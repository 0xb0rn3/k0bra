#!/usr/bin/env python3
import asyncio
import os
import ipaddress
import json
import socket
import termcolor
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from typing import List, Dict, Optional, Any
import argparse
from simple_term_menu import TerminalMenu
import time
import ipaddress

class K0braNetworkScanner:
    # ASCII art banner for the scanner
    BANNER = """
    ██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ 
    ██║ ██╔╝██╔═████╗██╔══██╗██╔══██╗██╔══██╗
    █████╔╝ ██║██╔██║██████╔╝██████╔╝███████║
    ██╔═██╗ ████╔╝██║██╔══██╗██╔══██╗██╔══██║
    ██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    Network Scanner v0.2 - By b0urn3
    """

    @dataclass
    class HostResult:
        """Data class to store host scanning results"""
        ip: str
        mac: Optional[str] = None
        hostname: Optional[str] = None
        ports: Optional[List[Dict[str, Any]]] = None

    def __init__(self, network: str = "192.168.1.0/24"):
        """Initialize the scanner with default network"""
        self.network = ipaddress.ip_network(network, strict=False)
        self.output_format = 'fancy'  # Default output format

    async def dns_resolution(self, ip: str) -> Optional[str]:
        """Resolve IP address to hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
# Service fingerprinting database
SERVICE_DB = {
    21: {'name': 'FTP', 'banner': True},
    22: {'name': 'SSH', 'banner': True},
    23: {'name': 'Telnet', 'banner': True},
    25: {'name': 'SMTP', 'banner': True},
    53: {'name': 'DNS', 'banner': False},
    80: {'name': 'HTTP', 'banner': True},
    110: {'name': 'POP3', 'banner': True},
    143: {'name': 'IMAP', 'banner': True},
    443: {'name': 'HTTPS', 'banner': True},
    445: {'name': 'SMB', 'banner': False},
    1433: {'name': 'MSSQL', 'banner': True},
    3306: {'name': 'MySQL', 'banner': True},
    3389: {'name': 'RDP', 'banner': False},
    5432: {'name': 'PostgreSQL', 'banner': True},
    6379: {'name': 'Redis', 'banner': True},
    8080: {'name': 'HTTP-Proxy', 'banner': True},
    27017: {'name': 'MongoDB', 'banner': True}
}

class EnhancedK0braScanner(K0braNetworkScanner):
    def __init__(self, **kwargs):
        super().__init__(network="192.168.1.0/24")
        
        # Scanner configuration
        self.batch_size = kwargs.get('batch_size', 500)
        self.ulimit = kwargs.get('ulimit', 1024)
        self.timeout = kwargs.get('timeout', 1.5)
        self.max_retries = kwargs.get('max_retries', 3)
        self.scan_order = kwargs.get('scan_order', 'serial')
        self.skip_empty = kwargs.get('skip_empty', True)
        self.rate_limit = kwargs.get('rate_limit', 1000)
        self.scan_ports = kwargs.get('ports', range(1, 1024))
        self.verbose_logging = kwargs.get('verbose', False)
        
        # Performance monitoring
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Logging setup
        self.log_file = kwargs.get('log_file', 'k0bra_scan.log')
        self._setup_logging()

    def _setup_logging(self):
        """Configure logging with different levels and output formats"""
        import logging
        logging.basicConfig(
            filename=self.log_file,
            level=logging.DEBUG if self.verbose_logging else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('K0braScanner')

    async def show_interactive_menu(self):
        """Enhanced interactive menu system"""
        while True:
            options = [
                "📡 Start Network Scan",
                "🎯 Configure Target",
                "⚙️  Scanning Options",
                "🚀 Performance Settings",
                "📊 Output Configuration",
                "📋 View Current Settings",
                "📝 View Scan History",
                "❌ Exit Scanner"
            ]
            
            terminal_menu = TerminalMenu(
                options,
                title="K0bra Network Scanner - Enhanced Edition",
                menu_cursor="➜",
                menu_cursor_style=("fg_purple", "bold"),
                menu_highlight_style=("bg_purple", "fg_black"),
            )
            
            choice = terminal_menu.show()
            
            if choice == 0:
                await self.execute_scan()
            elif choice == 1:
                await self.configure_target()
            elif choice == 2:
                await self.show_scanning_options()
            elif choice == 3:
                await self.configure_performance()
            elif choice == 4:
                await self.configure_output()
            elif choice == 5:
                self.display_current_config()
            elif choice == 6:
                self.display_scan_history()
            elif choice == 7 or choice is None:
                print(colored("\nExiting K0bra Scanner. Goodbye!", "cyan"))
                break

    async def execute_scan(self):
        """Execute full network scan with progress monitoring"""
        try:
            self.scan_start_time = time.time()
            print(colored("\nInitiating network scan...", "cyan"))
            
            # ARP scan for host discovery
            print(colored("Phase 1: Host Discovery", "yellow"))
            discovered_hosts = await self.enhanced_arp_scan()
            
            if not discovered_hosts:
                print(colored("No live hosts found in target network", "red"))
                return
            
            print(colored(f"\nDiscovered {len(discovered_hosts)} live hosts", "green"))
            
            # Port scanning phase
            print(colored("\nPhase 2: Port Scanning", "yellow"))
            scan_results = []
            
            for host in discovered_hosts:
                print(colored(f"\nScanning {host.ip}...", "cyan"))
                ports = await self.enhanced_port_scan(host.ip)
                host.ports = ports
                scan_results.append(host)
            
            self.scan_end_time = time.time()
            scan_duration = self.scan_end_time - self.scan_start_time
            
            # Export and display results
            output = self.export_results(scan_results)
            print(output)
            print(colored(f"\nScan completed in {scan_duration:.2f} seconds", "green"))
            
            # Save scan history
            self._save_scan_history(scan_results, scan_duration)
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            print(colored(f"Scan failed: {str(e)}", "red"))

    async def enhanced_arp_scan(self) -> List[HostResult]:
        """Improved ARP scanning with retry mechanism"""
        discovered_hosts = []
        
        try:
            # Create ARP request packet
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.network))
            
            for attempt in range(self.max_retries):
                # Send ARP requests with timeout
                answered, _ = srp(arp_request, timeout=2, verbose=False)
                
                for sent, received in answered:
                    host = self.HostResult(
                        ip=received[ARP].psrc,
                        mac=received[Ether].src,
                        hostname=await self.dns_resolution(received[ARP].psrc)
                    )
                    if host not in discovered_hosts:
                        discovered_hosts.append(host)
                
                if discovered_hosts or attempt == self.max_retries - 1:
                    break
                
                await asyncio.sleep(0.5)
            
            self.logger.info(f"ARP scan discovered {len(discovered_hosts)} hosts")
            
        except Exception as e:
            self.logger.error(f"ARP scan failed: {str(e)}")
            raise
        
        return discovered_hosts

    async def enhanced_port_scan(self, target: str) -> List[Dict[str, Any]]:
        """Advanced port scanning with service detection and banner grabbing"""
        open_ports = []
        ports = list(self.scan_ports)
        
        if self.scan_order == 'random':
            import random
            random.shuffle(ports)
        
        # Split ports into batches for efficient scanning
        port_batches = [ports[i:i + self.batch_size] for i in range(0, len(ports), self.batch_size)]
        
        for batch in port_batches:
            batch_tasks = []
            for port in batch:
                task = self.scan_single_port_with_retry(target, port)
                batch_tasks.append(task)
            
            # Concurrent port scanning with rate limiting
            batch_results = await asyncio.gather(*batch_tasks)
            open_ports.extend([result for result in batch_results if result])
            
            if self.rate_limit:
                await asyncio.sleep(len(batch) / self.rate_limit)
        
        return open_ports

    async def scan_single_port_with_retry(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Scan individual port with retry mechanism and service detection"""
        for attempt in range(self.max_retries):
            try:
                # Initial TCP connection attempt
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=self.timeout
                )
                
                # Service detection and banner grabbing
                service_info = SERVICE_DB.get(port, {'name': 'unknown', 'banner': False})
                banner = None
                
                if service_info['banner']:
                    try:
                        banner_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                        banner = banner_data.decode().strip()
                    except:
                        pass
                
                writer.close()
                await writer.wait_closed()
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service_info['name'],
                    'banner': banner
                }
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                if attempt == self.max_retries - 1:
                    return None
                await asyncio.sleep(0.1)

    async def show_scanning_options(self):
        """Configure advanced scanning options"""
        while True:
            options = [
                f"🔄 Scan Order: {self.scan_order}",
                f"⏱️  Connection Timeout: {self.timeout}s",
                f"🔁 Maximum Retries: {self.max_retries}",
                f"⏭️  Skip Empty Ranges: {self.skip_empty}",
                "📊 Port Range Configuration",
                "🔙 Back to Main Menu"
            ]
            
            menu = TerminalMenu(
                options,
                title="Advanced Scanning Options",
                menu_cursor="➜",
                menu_cursor_style=("fg_purple", "bold"),
                menu_highlight_style=("bg_purple", "fg_black"),
            )
            
            choice = menu.show()
            
            if choice == 0:
                self.scan_order = 'random' if self.scan_order == 'serial' else 'serial'
            elif choice == 1:
                self.timeout = float(input("Enter new timeout value (seconds): "))
            elif choice == 2:
                self.max_retries = int(input("Enter maximum retry attempts: "))
            elif choice == 3:
                self.skip_empty = not self.skip_empty
            elif choice == 4:
                await self.configure_port_range()
            elif choice == 5 or choice is None:
                break

    async def configure_port_range(self):
        """Configure port scanning range"""
        print("\nPort Range Configuration")
        print("1. Common ports only")
        print("2. Full range (1-65535)")
        print("3. Custom range")
        
        choice = input("Select option (1-3): ")
        
        if choice == '1':
            self.scan_ports = list(SERVICE_DB.keys())
        elif choice == '2':
            self.scan_ports = range(1, 65536)
        elif choice == '3':
            try:
                start = int(input("Start port: "))
                end = int(input("End port: "))
                if 1 <= start <= end <= 65535:
                    self.scan_ports = range(start, end + 1)
                else:
                    print(colored("Invalid port range", "red"))
            except ValueError:
                print(colored("Invalid input", "red"))

    def _save_scan_history(self, results: List[HostResult], duration: float):
        """Save scan results and metadata to history"""
        history_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'network': str(self.network),
            'duration': duration,
            'hosts_scanned': len(results),
            'config': {
                'batch_size': self.batch_size,
                'timeout': self.timeout,
                'scan_order': self.scan_order,
                'max_retries': self.max_retries
            },
            'results': [asdict(host) for host in results]
        }
        
        try:
            with open('scan_history.json', 'a') as f:
                json.dump(history_entry, f)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to save scan history: {str(e)}")

    def display_scan_history(self):
        """Display historical scan information"""
        try:
            with open('scan_history.json', 'r') as f:
                history = [json.loads(line) for line in f]
            
            print("\nScan History:")
            print("=" * 50)
            
            for entry in history[-10:]:  # Show last 10 scans
                print(f"Timestamp: {entry['timestamp']}")
                print(f"Network: {entry['network']}")
                print(f"Duration: {entry['duration']:.2f} seconds")
                print(f"Hosts Scanned: {entry['hosts_scanned']}")
                print("-" * 30)
            
        except FileNotFoundError:
            print("No scan history available")
        except Exception as e:
            print(f"Error reading scan history: {str(e)}")

    async def configure_performance(self):
        """Configure scanner performance settings and resource limits"""
        while True:
            options = [
                f"📦 Batch Size: {self.batch_size}",
                f"⚡ Rate Limit: {self.rate_limit}/s",
                f"📈 File Descriptor Limit: {self.ulimit}",
                f"🔄 Adaptive Performance: {getattr(self, 'adaptive_mode', False)}",
                f"💻 Thread Pool Size: {getattr(self, 'thread_pool_size', 50)}",
                "🔙 Back to Main Menu"
            ]
            
            menu = TerminalMenu(
                options,
                title="Performance Settings",
                menu_cursor="➜",
                menu_cursor_style=("fg_purple", "bold"),
                menu_highlight_style=("bg_purple", "fg_black"),
            )
            
            choice = menu.show()
            
            if choice == 0:
                try:
                    new_size = int(input("Enter new batch size (50-1000): "))
                    if 50 <= new_size <= 1000:
                        self.batch_size = new_size
                    else:
                        print(colored("Invalid batch size range", "red"))
                except ValueError:
                    print(colored("Invalid input", "red"))
            
            elif choice == 1:
                try:
                    new_rate = int(input("Enter new rate limit (ports/second): "))
                    if new_rate > 0:
                        self.rate_limit = new_rate
                    else:
                        print(colored("Rate limit must be positive", "red"))
                except ValueError:
                    print(colored("Invalid input", "red"))
            
            elif choice == 2:
                try:
                    new_limit = int(input("Enter new file descriptor limit: "))
                    if new_limit > 0:
                        self.ulimit = new_limit
                        # Actually set the system limit
                        import resource
                        resource.setrlimit(resource.RLIMIT_NOFILE, (new_limit, new_limit))
                    else:
                        print(colored("Limit must be positive", "red"))
                except ValueError:
                    print(colored("Invalid input", "red"))
                except resource.error as e:
                    print(colored(f"Failed to set limit: {e}", "red"))
            
            elif choice == 3:
                self.adaptive_mode = not getattr(self, 'adaptive_mode', False)
                if self.adaptive_mode:
                    self._setup_adaptive_scanning()
            
            elif choice == 4:
                try:
                    new_size = int(input("Enter thread pool size (10-200): "))
                    if 10 <= new_size <= 200:
                        self.thread_pool_size = new_size
                    else:
                        print(colored("Invalid thread pool size range", "red"))
                except ValueError:
                    print(colored("Invalid input", "red"))
            
            elif choice == 5 or choice is None:
                break

    def _setup_adaptive_scanning(self):
        """Configure adaptive scanning parameters based on system resources"""
        import psutil
        
        # Adjust batch size based on available memory
        available_memory = psutil.virtual_memory().available
        self.batch_size = min(1000, max(50, int(available_memory / (1024 * 1024 * 10))))
        
        # Adjust thread pool size based on CPU cores
        cpu_count = psutil.cpu_count()
        self.thread_pool_size = min(200, max(10, cpu_count * 4))
        
        # Adjust file descriptor limit based on system limits
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            self.ulimit = min(hard, max(1024, soft))
        except:
            self.ulimit = 1024
        
        self.logger.info(f"Adaptive mode configured: batch_size={self.batch_size}, "
                        f"thread_pool_size={self.thread_pool_size}, ulimit={self.ulimit}")

    async def configure_target(self):
        """Enhanced network target configuration"""
        while True:
            options = [
                f"🌐 Network: {self.network}",
                "📡 Select Interface",
                "🎯 Custom IP Range",
                "⚙️  Advanced Network Options",
                "🔙 Back to Main Menu"
            ]
            
            menu = TerminalMenu(
                options,
                title="Target Configuration",
                menu_cursor="➜",
                menu_cursor_style=("fg_purple", "bold"),
                menu_highlight_style=("bg_purple", "fg_black"),
            )
            
            choice = menu.show()
            
            if choice == 0:
                try:
                    network = input("Enter target network (CIDR format, e.g., 192.168.1.0/24): ")
                    self.network = ipaddress.ip_network(network, strict=False)
                    print(colored(f"Target network set to: {self.network}", "green"))
                except ValueError as e:
                    print(colored(f"Invalid network format: {e}", "red"))
            
            elif choice == 1:
                await self._select_interface()
            
            elif choice == 2:
                await self._configure_custom_range()
            
            elif choice == 3:
                await self._configure_advanced_network()
            
            elif choice == 4 or choice is None:
                break

    async def _select_interface(self):
        """Select network interface for scanning"""
        import netifaces
        
        interfaces = netifaces.interfaces()
        interface_menu = TerminalMenu(
            interfaces,
            title="Select Network Interface",
            menu_cursor="➜",
            menu_cursor_style=("fg_purple", "bold"),
            menu_highlight_style=("bg_purple", "fg_black"),
        )
        
        choice = interface_menu.show()
        if choice is not None:
            interface = interfaces[choice]
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    netmask = addrs[netifaces.AF_INET][0]['netmask']
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    self.network = network
                    print(colored(f"Network set to: {self.network}", "green"))
                else:
                    print(colored(f"No IPv4 address found for {interface}", "red"))
            except Exception as e:
                print(colored(f"Error configuring interface: {e}", "red"))

    async def _configure_custom_range(self):
        """Configure custom IP range for scanning"""
        try:
            start_ip = input("Enter start IP address: ")
            end_ip = input("Enter end IP address: ")
            
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            if start <= end:
                # Find the smallest network that contains both IPs
                network = ipaddress.summarize_address_range(start, end)
                self.network = next(network)
                print(colored(f"Network range set to: {self.network}", "green"))
            else:
                print(colored("Invalid IP range: start IP must be <= end IP", "red"))
        except ValueError as e:
            print(colored(f"Invalid IP address format: {e}", "red"))

    async def configure_output(self):
        """Configure scan output settings"""
        while True:
            options = [
                f"📊 Output Format: {self.output_format}",
                "📁 Output Directory",
                "📝 Log Level Configuration",
                "🎨 Color Settings",
                "🔙 Back to Main Menu"
            ]
            
            menu = TerminalMenu(
                options,
                title="Output Configuration",
                menu_cursor="➜",
                menu_cursor_style=("fg_purple", "bold"),
                menu_highlight_style=("bg_purple", "fg_black"),
            )
            
            choice = menu.show()
            
            if choice == 0:
                format_options = ['fancy', 'json', 'xml', 'text', 'grep']
                format_menu = TerminalMenu(
                    format_options,
                    title="Select Output Format",
                    menu_cursor="➜",
                    menu_cursor_style=("fg_purple", "bold"),
                    menu_highlight_style=("bg_purple", "fg_black"),
                )
                format_choice = format_menu.show()
                if format_choice is not None:
                    self.output_format = format_options[format_choice]
            
            elif choice == 1:
                directory = input("Enter output directory path: ")
                if os.path.isdir(directory):
                    self.output_directory = directory
                else:
                    create = input("Directory doesn't exist. Create it? (y/n): ")
                    if create.lower() == 'y':
                        try:
                            os.makedirs(directory)
                            self.output_directory = directory
                        except Exception as e:
                            print(colored(f"Failed to create directory: {e}", "red"))
            
            elif choice == 2:
                self._configure_logging()
            
            elif choice == 3:
                self._configure_colors()
            
            elif choice == 4 or choice is None:
                break

    def export_results(self, results: List[HostResult]) -> str:
        """Enhanced export functionality with multiple output formats"""
        if self.output_format == 'fancy':
            return self._fancy_format_output(results)
        
        elif self.output_format == 'json':
            json_data = {
                'scan_info': {
                    'network': str(self.network),
                    'start_time': self.scan_start_time,
                    'end_time': self.scan_end_time,
                    'duration': self.scan_end_time - self.scan_start_time if self.scan_end_time else None,
                    'scanner_version': '0.2'
                },
                'hosts': [asdict(host) for host in results]
            }
            return json.dumps(json_data, indent=2)
        
        elif self.output_format == 'xml':
            root = ET.Element('scan_results')
            
            # Add scan information
            info = ET.SubElement(root, 'scan_info')
            ET.SubElement(info, 'network').text = str(self.network)
            ET.SubElement(info, 'start_time').text = str(self.scan_start_time)
            ET.SubElement(info, 'end_time').text = str(self.scan_end_time)
            
            # Add host results
            hosts = ET.SubElement(root, 'hosts')
            for host in results:
                host_elem = ET.SubElement(hosts, 'host')
                for key, value in asdict(host).items():
                    if value is not None:
                        ET.SubElement(host_elem, key).text = str(value)
            
            return ET.tostring(root, encoding='unicode', pretty_print=True)
        
        elif self.output_format == 'grep':
            # Format: host:port:protocol:service:banner
            lines = []
            for host in results:
                if host.ports:
                    for port in host.ports:
                        line = f"{host.ip}:{port['port']}:tcp:{port['service']}:{port.get('banner', '')}"
                        lines.append(line)
            return '\n'.join(lines)
        
        else:  # Plain text
            output = []
            output.append("K0bra Network Scan Results")
            output.append("=" * 50)
            output.append(f"Network: {self.network}")
            output.append(f"Scan Duration: {self.scan_end_time - self.scan_start_time:.2f}s")
            output.append("")
            
            for host in results:
                output.append(f"Host: {host.ip}")
                if host.hostname:
                    output.append(f"Hostname: {host.hostname}")
                if host.mac:
                    output.append(f"MAC Address: {host.mac}")
                
                if host.ports:
                    output.append("Open Ports:")
                    for port in host.ports:
                        port_line = f"  {port['port']}/tcp\t{port['service']}"
                        if port.get('banner'):
                            port_line += f"\t{port['banner']}"
                        output.append(port_line)
                
                output.append("")
            
            return '\n'.join(output)

    def _fancy_format_output(self, results: List[HostResult]) -> str:
        """Create visually appealing formatted output with colors and icons"""
        output = []
        
        # Header
        output.extend([
            colored("🌐 K0bra Network Scan Results", "cyan", attrs=['bold']),
            colored("=" * 50, "cyan"),
            colored(f"Network: {self.network}", "blue"),
            colored(f"Scan Duration: {self.scan_end_time - self.scan_start_time:.2f}s", "blue"),
            ""
        ])
        
        # Statistics
        total_hosts = len(results)
        hosts_with_ports = sum(1 for host in results if host.ports)
        total_open_ports = sum(len(host.ports) for host in results if host.ports)
        
        output.extend([
            colored("📊 Scan Statistics:", "yellow"),
            colored(f"  • Total Hosts: {total_hosts}", "green"),
            colored(f"  • Hosts with Open Ports: {hosts_with_ports}", "green"),
            colored(f"  • Total Open Ports: {total_open_ports}", "green"),
            ""
        ])
        
        # Detailed Results
        for host in sorted(results, key=lambda x: ipaddress.ip_address(x.ip)):
            # Host header with IP and hostname
            host_header = f"🖥️  {colored(host.ip, 'cyan', attrs=['bold'])}"
            if host.hostname:
                host_header += f" ({colored(host.hostname, 'blue')})"
            output.append(host_header)
            
            # MAC address if available
            if host.mac:
                output.append(f"   📱 MAC: {colored(host.mac, 'magenta')}")
            
            # Port information
            if host.ports:
                output.append(colored("   🔍 Open Ports:", "yellow"))
                for port in sorted(host.ports, key=lambda x: x['port']):
                    port_line = f"      {colored(str(port['port']), 'green')}/tcp"
                    port_line += f" - {colored(port['service'], 'yellow')}"
                    port_line = f"      {colored(str(port['port']), 'green')}/tcp"
                    port_line += f" - {colored(port['service'], 'yellow')}"
                    
                    # Add banner information if available
                    if port.get('banner'):
                        banner_preview = port['banner'][:50] + '...' if len(port['banner']) > 50 else port['banner']
                        port_line += f"\n        💭 {colored(banner_preview, 'blue')}"
                    
                    output.append(port_line)
            else:
                output.append(colored("   No open ports detected", "red"))
            
            output.append("")  # Add spacing between hosts
        
        # Add footer with scan configuration
        output.extend([
            colored("Scan Configuration:", "cyan"),
            colored(f"  • Batch Size: {self.batch_size}", "blue"),
            colored(f"  • Timeout: {self.timeout}s", "blue"),
            colored(f"  • Max Retries: {self.max_retries}", "blue"),
            colored(f"  • Scan Order: {self.scan_order}", "blue")
        ])
        
        return "\n".join(output)

    def _configure_logging(self):
        """Configure logging levels and output"""
        log_levels = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR
        }
        
        options = [
            f"Current Level: {logging.getLevelName(self.logger.level)}",
            "Set to DEBUG (Most Verbose)",
            "Set to INFO (Standard)",
            "Set to WARNING (Important Only)",
            "Set to ERROR (Problems Only)",
            "Back"
        ]
        
        menu = TerminalMenu(
            options,
            title="Log Level Configuration",
            menu_cursor="➜",
            menu_cursor_style=("fg_purple", "bold"),
            menu_highlight_style=("bg_purple", "fg_black"),
        )
        
        choice = menu.show()
        
        if choice in [1, 2, 3, 4]:
            level_name = options[choice].split()[2]
            self.logger.setLevel(log_levels[level_name])
            print(colored(f"Log level set to {level_name}", "green"))

    def _configure_colors(self):
        """Configure color settings for output"""
        if not HAVE_COLOR:
            print(colored("Terminal color support not available. Install 'termcolor' package.", "yellow"))
            return
        
        options = [
            "Toggle Color Output",
            "Configure Color Scheme",
            "Reset to Default Colors",
            "Back"
        ]
        
        menu = TerminalMenu(
            options,
            title="Color Configuration",
            menu_cursor="➜",
            menu_cursor_style=("fg_purple", "bold"),
            menu_highlight_style=("bg_purple", "fg_black"),
        )
        
        choice = menu.show()
        
        if choice == 0:
            self.use_colors = not getattr(self, 'use_colors', True)
            status = "enabled" if self.use_colors else "disabled"
            print(colored(f"Color output {status}", "green"))
        
        elif choice == 1:
            self._configure_color_scheme()
        
        elif choice == 2:
            self.color_scheme = {
                'header': 'cyan',
                'success': 'green',
                'warning': 'yellow',
                'error': 'red',
                'info': 'blue'
            }
            print(colored("Color scheme reset to defaults", "green"))

    def _configure_color_scheme(self):
        """Configure individual colors for different elements"""
        available_colors = ['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white']
        elements = ['header', 'success', 'warning', 'error', 'info']
        
        for element in elements:
            print(f"\nSelect color for {element} text:")
            menu = TerminalMenu(
                available_colors,
                title=f"Color for {element}",
                menu_cursor="➜",
                menu_cursor_style=("fg_purple", "bold"),
                menu_highlight_style=("bg_purple", "fg_black"),
            )
            
            choice = menu.show()
            if choice is not None:
                if not hasattr(self, 'color_scheme'):
                    self.color_scheme = {}
                self.color_scheme[element] = available_colors[choice]

    async def _configure_advanced_network(self):
        """Configure advanced network scanning options"""
        while True:
            options = [
                f"🔍 Scan Depth: {getattr(self, 'scan_depth', 'Normal')}",
                f"📡 Protocol Selection: {getattr(self, 'protocols', ['TCP'])}",
                f"🎯 Target Prioritization: {getattr(self, 'target_priority', 'Sequential')}",
                f"⏱️  Host Timeout: {getattr(self, 'host_timeout', '5s')}",
                "🔙 Back"
            ]
            
            menu = TerminalMenu(
                options,
                title="Advanced Network Configuration",
                menu_cursor="➜",
                menu_cursor_style=("fg_purple", "bold"),
                menu_highlight_style=("bg_purple", "fg_black"),
            )
            
            choice = menu.show()
            
            if choice == 0:
                depth_options = ['Quick', 'Normal', 'Deep']
                depth_menu = TerminalMenu(depth_options)
                depth_choice = depth_menu.show()
                if depth_choice is not None:
                    self.scan_depth = depth_options[depth_choice]
                    # Adjust scanning parameters based on depth
                    self._adjust_scan_depth()
            
            elif choice == 1:
                protocol_options = ['TCP', 'UDP', 'ICMP']
                selected = []
                while True:
                    remaining = [p for p in protocol_options if p not in selected]
                    if not remaining:
                        break
                    menu = TerminalMenu(remaining, title="Select Protocols (Space to select, Enter when done)")
                    choice = menu.show()
                    if choice is None:
                        break
                    selected.append(remaining[choice])
                if selected:
                    self.protocols = selected
            
            elif choice == 2:
                priority_options = ['Sequential', 'Random', 'Smart']
                priority_menu = TerminalMenu(priority_options)
                priority_choice = priority_menu.show()
                if priority_choice is not None:
                    self.target_priority = priority_options[priority_choice]
            
            elif choice == 3:
                try:
                    timeout = float(input("Enter host timeout in seconds: "))
                    if timeout > 0:
                        self.host_timeout = f"{timeout}s"
                    else:
                        print(colored("Timeout must be positive", "red"))
                except ValueError:
                    print(colored("Invalid timeout value", "red"))
            
            elif choice == 4 or choice is None:
                break

    def _adjust_scan_depth(self):
        """Adjust scanning parameters based on scan depth"""
        if self.scan_depth == 'Quick':
            self.batch_size = 1000
            self.timeout = 1.0
            self.max_retries = 1
            self.scan_ports = list(range(1, 1024))  # Common ports only
        
        elif self.scan_depth == 'Normal':
            self.batch_size = 500
            self.timeout = 1.5
            self.max_retries = 2
            self.scan_ports = list(range(1, 10000))  # Extended port range
        
        elif self.scan_depth == 'Deep':
            self.batch_size = 250
            self.timeout = 2.0
            self.max_retries = 3
            self.scan_ports = list(range(1, 65536))  # Full port range

    def __str__(self):
        """String representation of the scanner configuration"""
        return f"K0bra Scanner v0.2 - Network: {self.network}, Batch Size: {self.batch_size}, " \
               f"Timeout: {self.timeout}s, Max Retries: {self.max_retries}, Scan Order: {self.scan_order}"

def main():
    """Enhanced main entry point with error handling and setup"""
    try:
        print(K0braNetworkScanner.BANNER)
        
        # Check for root/sudo privileges
        if not (hasattr(os, 'geteuid') and os.geteuid() == 0):
            print(colored("[ERROR] This tool requires root/sudo privileges", "red"))
            sys.exit(1)
        
        # Check for required packages
        missing_packages = []
        try:
            import netifaces
        except ImportError:
            missing_packages.append('netifaces')
        try:
            import psutil
        except ImportError:
            missing_packages.append('psutil')
        
        if missing_packages:
            print(colored("Missing required packages:", "yellow"))
            print("  " + ", ".join(missing_packages))
            install = input("Would you like to install them now? (y/n): ")
            if install.lower() == 'y':
                import subprocess
                for package in missing_packages:
                    try:
                        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    except subprocess.CalledProcessError as e:
                        print(colored(f"Failed to install {package}: {e}", "red"))
                        sys.exit(1)
        
        # Initialize and run scanner
        scanner = EnhancedK0braScanner()
        asyncio.run(scanner.show_interactive_menu())
    
    except KeyboardInterrupt:
        print(colored("\n[INFO] Scanner interrupted by user", "yellow"))
    except Exception as e:
        print(colored(f"[CRITICAL] Unexpected error: {e}", "red"))
        if hasattr(scanner, 'logger'):
            scanner.logger.error(f"Critical error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
