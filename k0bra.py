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
 
#color support
try:
    from termcolor import colored
    HAVE_COLOR = True
except ImportError:
    HAVE_COLOR = False
    def colored(text, color=None, attrs=None):
        return text

class K0braNetworkScanner:
    """
         Advanced network scanning tool.
    Developed by github.com/q4n0 (IG: onlybyhive)
    """
    
    BANNER = r"""
 _      ___   _                  
| | __ / _ \ | |__   _ __   __ _ 
| |/ /| | | || '_ \ | '__| / _` |
|   < | |_| || |_) || |   | (_| |
|_|\_\ \___/ |_.__/ |_|    \__,_|
                                 
K0BRA Network Scanner v0.1
GitHub: https://github.com/q4n0/k0bra
Developed by q4n0 Ig: onlybyhive
"""
    
    def __init__(
        self, 
        network: str, 
        output_format: str = 'fancy', 
        max_workers: int = 50,
        verbose: bool = False
    ):
        """
        Initialize K0bra Network Scanner with advanced configuration.
        
        :param network: Network CIDR (e.g., '192.168.1.0/24')
        :param output_format: Output format ('fancy', 'json', 'xml', 'text')
        :param max_workers: Maximum concurrent workers for scanning
        :param verbose: Enable detailed logging
        """
        try:
            self.network = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            print(f"[ERROR] Invalid network format: {e}")
            sys.exit(1)
        
        self.output_format = output_format
        self.max_workers = max_workers
        self.verbose = verbose
    
    @dataclass
    class HostResult:
        """Structured result for each discovered host."""
        ip: str
        mac: Optional[str] = None
        hostname: Optional[str] = None
        ports: List[Dict[str, Any]] = None
        services: List[Dict[str, str]] = None
    
    async def arp_scan(self) -> List[HostResult]:
        """
        Perform ARP network discovery to identify live hosts.
        
        :return: List of discovered hosts
        """
        discovered_hosts = []
        
        try:
            # Create ARP request packet
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.network))
            
            # Send and receive ARP requests
            result = srp(arp_request, timeout=2, verbose=False)[0]
            
            for sent, received in result:
                host = self.HostResult(
                    ip=received[ARP].psrc,
                    mac=received[Ether].src
                )
                discovered_hosts.append(host)
            
            if self.verbose:
                print(f"[INFO] Discovered {len(discovered_hosts)} hosts")
        
        except Exception as e:
            print(f"[ERROR] ARP scan failed: {e}")
        
        return discovered_hosts
    
    async def dns_resolution(self, ip_address: str) -> Optional[str]:
        """
        Attempt to resolve hostname for an IP address.
        
        :param ip_address: IP to resolve
        :return: Hostname if resolvable
        """
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror):
            return None
    
    async def port_scan(
        self, 
        target: str, 
        ports: List[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Perform comprehensive port scanning.
        
        :param target: Target IP address
        :param ports: List of ports to scan
        :return: List of open ports with details
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389]
        
        open_ports = []
        
        async def scan_single_port(port):
            try:
                # Create TCP connection with timeout
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), 
                    timeout=1
                )
                writer.close()
                await writer.wait_closed()
                
                service = self._detect_service(port)
                return {
                    'port': port,
                    'state': 'open',
                    'service': service
                }
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
        
        # Use asyncio.gather for concurrent scanning
        port_tasks = [scan_single_port(port) for port in ports]
        results = await asyncio.gather(*port_tasks)
        
        # Filter out None results (closed ports)
        open_ports = [result for result in results if result is not None]
        
        return open_ports
    
    def _detect_service(self, port: int) -> str:
        """
        Basic service detection based on common port numbers.
        """
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 
            3389: 'RDP'
        }
        return services.get(port, 'Unknown')
    
    async def comprehensive_scan(self) -> List[HostResult]:
        """
        Perform comprehensive network scan with error handling.
        
        :return: Detailed scan results
        """
        try:
            discovered_hosts = await self.arp_scan()
            
            async def enrich_host(host):
                try:
                    # Resolve hostname
                    host.hostname = await self.dns_resolution(host.ip)
                    
                    # Perform port scan
                    host.ports = await self.port_scan(host.ip)
                    
                    return host
                except Exception as e:
                    if self.verbose:
                        print(f"[WARNING] Could not fully scan {host.ip}: {e}")
                    return host
            
            # Concurrently enrich host information
            enriched_hosts = await asyncio.gather(
                *[enrich_host(host) for host in discovered_hosts]
            )
            
            return enriched_hosts
        
        except Exception as e:
            print(f"[CRITICAL] Scan failed: {e}")
            return []
    
    def _fancy_format_output(self, results: List[HostResult]) -> str:
        """
        Create a visually appealing formatted output for network scan results.
        
        :param results: Scan results
        :return: Formatted output string
        """
        # Network overview
        output = [
            colored("🌐 K0BRA Network Scan Results", "cyan", attrs=['bold']),
            colored("=" * 50, "cyan")
        ]
        
        # Summary statistics
        total_hosts = len(results)
        hosts_with_ports = sum(1 for host in results if host.ports)
        
        output.extend([
            colored(f"📊 Total Hosts Discovered: {total_hosts}", "green"),
            colored(f"🔍 Hosts with Open Ports: {hosts_with_ports}", "yellow"),
            colored("=" * 50, "cyan"), ""
        ])
        
        # Detailed host information
        for host in sorted(results, key=lambda x: ipaddress.ip_address(x.ip)):
            # Host header
            host_header = f"🖥️  Host: {colored(host.ip, 'blue', attrs=['bold'])}"
            if host.hostname:
                host_header += f" ({colored(host.hostname, 'green')})"
            output.append(host_header)
            
            # MAC address
            if host.mac:
                output.append(f"   MAC: {colored(host.mac, 'magenta')}")
            
            # Port information
            if host.ports:
                output.append(colored("   Open Ports:", "yellow"))
                for port in host.ports:
                    port_info = (
                        f"     • {colored(str(port['port']), 'red')} "
                        f"({colored(port['service'], 'green')}) "
                        f"- {colored('OPEN', 'green', attrs=['bold'])}"
                    )
                    output.append(port_info)
            else:
                output.append(colored("   No open ports detected", "grey"))
            
            output.append("")  # Blank line between hosts
        
        return "\n".join(output)
    
    def export_results(
        self, 
        results: List[HostResult]
    ) -> str:
        """
        Export scan results in specified format with improved readability.
        
        :param results: Scan results
        :return: Formatted output string
        """
        # Convert results to dictionary for serialization
        formatted_results = [
            {k: v for k, v in asdict(result).items() if v is not None} 
            for result in results
        ]
        
        if self.output_format == 'fancy':
            return self._fancy_format_output(results)
        
        elif self.output_format == 'json':
            return json.dumps(formatted_results, indent=2)
        
        elif self.output_format == 'xml':
            root = ET.Element('network_scan')
            for host in formatted_results:
                host_elem = ET.SubElement(root, 'host')
                for key, value in host.items():
                    ET.SubElement(host_elem, key).text = str(value)
            
            return ET.tostring(root, encoding='unicode')
        
        else:  # Plain text
            output = []
            for host in formatted_results:
                output.append(f"IP: {host.get('ip', 'N/A')}")
                output.append(f"MAC: {host.get('mac', 'N/A')}")
                output.append(f"Hostname: {host.get('hostname', 'N/A')}")
                
                if 'ports' in host and host['ports']:
                    output.append("Open Ports:")
                    for port in host['ports']:
                        output.append(
                            f"  Port {port['port']} - {port['service']} "
                            f"(State: {port['state']})"
                        )
                output.append("\n")
            
            return "\n".join(output)
    
    async def run(self) -> str:
        """
        Execute full network scan and return formatted results.
        
        :return: Scan results in specified output format
        """
        results = await self.comprehensive_scan()
        return self.export_results(results)

def main():
    """
    Command-line interface for K0bra network scanner.
    """
    import argparse
    
    # Print banner
    print(K0braNetworkScanner.BANNER)
    
    parser = argparse.ArgumentParser(
        description='K0bra Comprehensive Network Scanner'
    )
    parser.add_argument(
        'network', 
        help='Network CIDR to scan (e.g., 192.168.1.0/24)'
    )
    parser.add_argument(
        '-f', '--format', 
        choices=['fancy', 'json', 'xml', 'text'], 
        default='fancy', 
        help='Output format (default: fancy)'
    )
    parser.add_argument(
        '-w', '--workers', 
        type=int, 
        default=50, 
        help='Maximum concurrent workers (default: 50)'
    )
    parser.add_argument(
        '-v', '--verbose', 
        action='store_true', 
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Check for color support
    if not HAVE_COLOR:
        print("[WARNING] Install 'termcolor' for colored output")
    
    # Require root/sudo for network scanning
    if not (hasattr(os, 'geteuid') and os.geteuid() == 0):
        print("[ERROR] This tool requires root/sudo privileges")
        sys.exit(1)
    
    try:
        # Run scanner
        scanner = K0braNetworkScanner(
            args.network, 
            output_format=args.format, 
            max_workers=args.workers,
            verbose=args.verbose
        )
        
        # Run async event loop
        results = asyncio.run(scanner.run())
        print(results)
    
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted by user")
    except Exception as e:
        print(f"[CRITICAL] Unexpected error: {e}")

if __name__ == "__main__":
    main()
