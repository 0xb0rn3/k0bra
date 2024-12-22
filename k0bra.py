#!/usr/bin/env python3 
import asyncio
import json
import logging
import os
import socket
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
import time
from typing import List, Dict, Optional, Any, Union
import resource
import tempfile
import fcntl

# Third-party imports
import ipaddress
import netifaces
import psutil
from scapy.all import ARP, Ether, srp, IP, TCP, sr1
from simple_term_menu import TerminalMenu

# Terminal color support check
HAVE_COLOR = True
try:
    from termcolor import colored
except ImportError:
    HAVE_COLOR = False
    def colored(text, color=None, *args, **kwargs):
        return text

# ---- Data Models ----
@dataclass
class HostResult:
    """
    Data class for storing host scanning results
    
    Attributes:
        ip (str): IP address of the scanned host
        mac (Optional[str]): MAC address if discovered during ARP scan
        hostname (Optional[str]): DNS hostname if resolution is successful
        ports (Optional[List[Dict[str, Any]]]): List of discovered open ports and services
        last_seen (float): Timestamp of last successful scan
        scan_duration (float): Time taken to scan this host
    """
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    ports: Optional[List[Dict[str, Any]]] = None
    last_seen: float = 0.0
    scan_duration: float = 0.0

async def dns_resolution(self, ip: str) -> Optional[str]:
    """
    Resolve IP address to hostname with timeout and error handling
    
    Args:
        ip (str): IP address to resolve
        
    Returns:
        Optional[str]: Resolved hostname or None if resolution fails
    """
    try:
        return await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: socket.gethostbyaddr(ip)[0]
        )
    except (socket.herror, socket.gaierror):
        return None
    except Exception as e:
        self.logger.debug(f"DNS resolution failed for {ip}: {str(e)}")
        return None
    
# ---- Constants and Configuration ----
SERVICE_DB = {
    21: {'name': 'FTP', 'banner': True, 'default_banner_length': 1024},
    22: {'name': 'SSH', 'banner': True, 'default_banner_length': 512},
    23: {'name': 'Telnet', 'banner': True, 'default_banner_length': 1024},
    25: {'name': 'SMTP', 'banner': True, 'default_banner_length': 512},
    53: {'name': 'DNS', 'banner': False, 'protocol': 'UDP'},
    80: {'name': 'HTTP', 'banner': True, 'default_banner_length': 2048},
    110: {'name': 'POP3', 'banner': True, 'default_banner_length': 512},
    143: {'name': 'IMAP', 'banner': True, 'default_banner_length': 512},
    443: {'name': 'HTTPS', 'banner': True, 'default_banner_length': 2048},
    445: {'name': 'SMB', 'banner': False, 'protocol': 'TCP'},
    3306: {'name': 'MySQL', 'banner': True, 'default_banner_length': 512},
    5432: {'name': 'PostgreSQL', 'banner': True, 'default_banner_length': 512}
}

class K0braNetworkScanner:
    """Base network scanner class with core functionality"""
    
    BANNER = """
    ██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ 
    ██║ ██╔╝██╔═████╗██╔══██╗██╔══██╗██╔══██╗
    █████╔╝ ██║██╔██║██████╔╝██████╔╝███████║
    ██╔═██╗ ████╔╝██║██╔══██╗██╔══██╗██╔══██║
    ██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    Network Scanner v0.4 - By 0xb0urn3
    """

class EnhancedK0braScanner(K0braNetworkScanner):
    """Enhanced scanner with improved error handling and features"""
    def __init__(self, **kwargs):
        
def _setup_thread_pool(self):
    """Initialize thread pool executor with proper resource limits"""
    max_workers = min(32, (os.cpu_count() or 1) * 4)
    self._thread_pool = ThreadPoolExecutor(
        max_workers=max_workers,
        thread_name_prefix="ScannerThread"
    )
    self._resources.append(self._thread_pool)

def _cleanup_resources(self):
    """Clean up allocated resources safely"""
    for resource in self._resources:
        try:
            if hasattr(resource, 'close'):
                if asyncio.iscoroutinefunction(resource.close):
                    asyncio.create_task(resource.close())
                else:
                    resource.close()
        except Exception as e:
            self.logger.error(f"Resource cleanup failed: {str(e)}")
    self._resources.clear()
        """
        Initialize scanner with robust error checking and parameter validation
        """
        self._resources = []  # Track allocated resources
        self._host_list_lock = asyncio.Lock()  # Lock for thread-safe host list operations
        
        try:
            # Network configuration
            network = kwargs.get('network', "192.168.1.0/24")
            try:
                self.network = ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid network format: {e}")

            # Scanner parameters with validation
            self.batch_size = self._validate_positive_int(
                kwargs.get('batch_size', 500),
                'batch_size',
                max_value=1000
            )
            self.timeout = self._validate_positive_float(
                kwargs.get('timeout', 1.5),
                'timeout'
            )
            self.max_retries = self._validate_positive_int(
                kwargs.get('max_retries', 3),
                'max_retries'
            )
            # Additional configuration
            self.scan_order = kwargs.get('scan_order', 'serial')
            self.skip_empty = kwargs.get('skip_empty', True)
            self.rate_limit = self._validate_positive_int(
                kwargs.get('rate_limit', 1000),
                'rate_limit'
            )
            self.scan_ports = kwargs.get('ports', range(1, 1024))
            
            # Logging configuration
            self.verbose_logging = kwargs.get('verbose', False)
            self.log_file = kwargs.get('log_file', 'k0bra_scan.log')
            self._setup_logging()
            
            # Output configuration
            self.output_format = kwargs.get('output_format', 'fancy')
            self.output_directory = kwargs.get('output_directory', '.')
            
            # Performance monitoring
            self.scan_start_time: Optional[float] = None
            self.scan_end_time: Optional[float] = None
            
            # Initialize thread pool
            self._setup_thread_pool()
        except Exception:
            self._cleanup_resources()
            raise
        
    def _validate_positive_int(self, value: Any, param_name: str, max_value: Optional[int] = None) -> int:
        """

        
        Args:
            value: Value to validate
            param_name: Parameter name for error messages
            max_value: Optional maximum allowed value
            
        Returns:
            int: Validated integer value
            
        Raises:
            ValueError: If validation fails
        """
        try:
            int_value = int(value)
            if int_value <= 0:
                raise ValueError
            if max_value and int_value > max_value:
                raise ValueError(f"{param_name} must be <= {max_value}")
            return int_value
        except (TypeError, ValueError):
            raise ValueError(f"{param_name} must be a positive integer")
        
 # Scanner configuration with proper typing
        self.batch_size: int = kwargs.get('batch_size', 500)
        self.ulimit: int = kwargs.get('ulimit', 1024)
        self.timeout: float = kwargs.get('timeout', 1.5)
        self.max_retries: int = kwargs.get('max_retries', 3)
        self.scan_order: str = kwargs.get('scan_order', 'serial')
        self.skip_empty: bool = kwargs.get('skip_empty', True)
        self.rate_limit: int = kwargs.get('rate_limit', 1000)
        self.scan_ports: range = kwargs.get('ports', range(1, 1024))
        self.verbose_logging: bool = kwargs.get('verbose', False)
        self.log_file = kwargs.get('log_file', 'k0bra_scan.log')
        self._setup_logging()
        self.output_format = kwargs.get('output_format', 'fancy')
        self.output_directory = kwargs.get('output_directory', '.')
        # Performance monitoring
        self.scan_start_time: Optional[float] = None
        self.scan_end_time: Optional[float] = None

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

    async def _periodic_cleanup(self):
        """Periodic cleanup of resources"""
        while True:
            try:
                # Clean up unused resources
                for resource in self._resources:
                    if hasattr(resource, 'close'):
                        await resource.close()
                self._resources.clear()
                
                # Sleep for cleanup interval
                await asyncio.sleep(60)  # Cleanup every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup error: {str(e)}")

    async def enhanced_arp_scan(self) -> List[HostResult]:
        """
        Perform enhanced ARP scan with retry logic and proper error handling
        """
        discovered_hosts = []
        scan_lock = asyncio.Lock()

        try:
            async with scan_lock:
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.network))
                
                for attempt in range(self.max_retries):
                    try:
                        answered, _ = srp(arp_request, timeout=2, verbose=False)
                        
                        async with self._host_list_lock:
                            for sent, received in answered:
                                host = HostResult(
                                    ip=received[ARP].psrc,
                                    mac=received[Ether].src,
                                    hostname=await self.dns_resolution(received[ARP].psrc),
                                    last_seen=time.time()
                                )
                                if host not in discovered_hosts:
                                    discovered_hosts.append(host)
                                    
                        if discovered_hosts or attempt == self.max_retries - 1:
                            break
                            
                        await asyncio.sleep(0.5)
                        
                    except Exception as e:
                        self.logger.error(f"ARP scan attempt {attempt + 1} failed: {str(e)}")
                        if attempt == self.max_retries - 1:
                            raise
                
            self.logger.info(f"ARP scan discovered {len(discovered_hosts)} hosts")
            
        except Exception as e:
            self.logger.error(f"ARP scan failed: {str(e)}")
            raise
        
        return discovered_hosts
async def _check_port_service(self, target: str, port: int) -> Optional[Dict[str, Any]]:
    """
    Check individual port and identify service with proper error handling
    
    Args:
        target (str): Target IP address
        port (int): Port number to check
        
    Returns:
        Optional[Dict[str, Any]]: Port information dictionary or None if port is closed
    """
    try:
        # Initial TCP connection check
        tcp_packet = IP(dst=target)/TCP(dport=port, flags="S")
        response = await asyncio.get_event_loop().run_in_executor(
            self._thread_pool,
            lambda: sr1(tcp_packet, timeout=self.timeout, verbose=False)
        )
        
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            service_info = SERVICE_DB.get(port, {'name': 'unknown', 'banner': False})
            
            # Attempt banner grab if supported
            banner = None
            if service_info['banner']:
                banner = await self._grab_service_banner(target, port, service_info)
                
            return {
                'port': port,
                'state': 'open',
                'service': service_info['name'],
                'banner': banner
            }
            
        return None
        
    except Exception as e:
        self.logger.debug(f"Port check failed for {target}:{port} - {str(e)}")
        return None

async def _grab_service_banner(self, target: str, port: int, service_info: Dict[str, Any]) -> Optional[str]:
    """
    Attempt to grab service banner with timeout protection
    
    Args:
        target (str): Target IP address
        port (int): Port number
        service_info (Dict[str, Any]): Service information dictionary
        
    Returns:
        Optional[str]: Service banner or None if banner grab fails
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=service_info.get('banner_timeout', 1.0)
        )
        
        try:
            banner_data = await asyncio.wait_for(
                reader.read(service_info['default_banner_length']),
                timeout=1.0
            )
            
            return banner_data.decode('utf-8', errors='ignore').strip()
            
        finally:
            writer.close()
            await writer.wait_closed()
            
    except Exception as e:
        self.logger.debug(f"Banner grab failed for {target}:{port} - {str(e)}")
        return None
    
    async def enhanced_port_scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform enhanced port scanning with improved concurrency and error handling
        """
        semaphore = asyncio.Semaphore(self.batch_size)
        port_batches = [self.scan_ports[i:i + self.batch_size] 
                       for i in range(0, len(self.scan_ports), self.batch_size)]
        
        async def scan_with_semaphore(port):
            async with semaphore:
                return await self.scan_single_port_with_retry(target, port)
        
        open_ports = []
        for batch in port_batches:
            batch_tasks = [scan_with_semaphore(port) for port in batch]
            results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    self.logger.debug(f"Port scan error: {str(result)}")
                    continue
                if result:
                    open_ports.append(result)
            
            if self.rate_limit:
                await asyncio.sleep(len(batch) / self.rate_limit)
        
        return open_ports

    async def scan_single_port_with_retry(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Scan a single port with retry logic and proper error handling
        """
        writer = None
        for attempt in range(self.max_retries):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=self.timeout
                )
                
                service_info = SERVICE_DB.get(port, {'name': 'unknown', 'banner': False})
                banner = None
                
                if service_info['banner']:
                    try:
                        banner_length = service_info.get('default_banner_length', 1024)
                        banner_data = await asyncio.wait_for(
                            reader.read(banner_length),
                            timeout=service_info.get('banner_timeout', 1.0)
                        )
                        
                        try:
                            banner = banner_data.decode('utf-8').strip()
                        except UnicodeDecodeError:
                            banner = banner_data.decode('latin1', errors='ignore').strip()
                            
                    except Exception as e:
                        self.logger.debug(f"Banner grab failed for {target}:{port} - {str(e)}")
                
                return {
                    'port': port,
                    'state': 'open',
                    'service': service_info['name'],
                    'banner': banner
                }
                
            except (asyncio.TimeoutError, ConnectionRefusedError):
                if attempt == self.max_retries - 1:
                    return None
                await asyncio.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Unexpected error scanning {target}:{port} - {str(e)}")
                return None
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception as e:
                        self.logger.debug(f"Error closing connection to {target}:{port} - {str(e)}")
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
    """Save scan results and metadata to history with proper file handling"""
    import fcntl
    import tempfile
    import os
    
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
    
    # Use atomic write with file locking
    history_file = 'scan_history.json'
    temp_file = None
    
    try:
        # Create temporary file
        fd, temp_path = tempfile.mkstemp(prefix='scan_history_', dir=os.path.dirname(history_file))
        temp_file = os.fdopen(fd, 'w')
        
        # Lock the original file
        with open(history_file, 'a+') as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            
            # Write to temp file
            json.dump(history_entry, temp_file)
            temp_file.write('\n')
            temp_file.flush()
            os.fsync(temp_file.fileno())
            
            # Atomic rename
            os.rename(temp_path, history_file)
            
    except Exception as e:
        self.logger.error(f"Failed to save scan history: {str(e)}")
        raise
    finally:
        if temp_file:
            temp_file.close()
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
        """Export scan results with proper XML handling and error checking"""
        if self.output_format == 'xml':
            root = ET.Element('scan_results')
            
            # Add scan information
            info = ET.SubElement(root, 'scan_info')
            ET.SubElement(info, 'network').text = str(self.network)
            ET.SubElement(info, 'start_time').text = str(self.scan_start_time)
            ET.SubElement(info, 'end_time').text = str(self.scan_end_time)
            
            # Add host results with proper error handling
            hosts = ET.SubElement(root, 'hosts')
            for host in results:
                host_elem = ET.SubElement(hosts, 'host')
                host_dict = asdict(host)
                for key, value in host_dict.items():
                    if value is not None:
                        # Convert complex types to JSON strings
                        if isinstance(value, (dict, list)):
                            value = json.dumps(value)
                        child = ET.SubElement(host_elem, key)
                        child.text = str(value)
            
            # Use custom pretty printing instead of lxml dependency
            return self._pretty_print_xml(root)
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
    
def _pretty_print_xml(self, element: ET.Element, indent: str = '  ') -> str:
    """Custom XML pretty printer without external dependencies"""
    
    def escape_xml(text: str) -> str:
        return (text.replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&apos;'))
    
    def _format_xml(element: ET.Element, level: int = 0) -> str:
        result = f"{indent * level}{element.tag}"
        
        # Handle attributes with proper escaping
        if element.attrib:
            attributes = [f'{k}="{escape_xml(v)}"' 
                        for k, v in element.attrib.items()]
            result += f" {' '.join(attributes)}"
        
        # Handle element content
        if element.text and element.text.strip():
            result += f">{escape_xml(element.text.strip())}"
            if len(element):
                result += "\n"
        elif len(element):
            result += ">"
        else:
            result += "/>"
            return result
        
        # Handle children
        for child in element:
            result += f"\n{_format_xml(child, level + 1)}"
            if child.tail and child.tail.strip():
                result += escape_xml(child.tail.strip())
        
        if len(element):
            result += f"\n{indent * level}"
        result += f"</{element.tag}>"
        return result
    
    return f'<?xml version="1.0" encoding="UTF-8"?>\n{_format_xml(element)}'
    
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

async def main(self):
    """Main entry point with proper error handling and cleanup"""
    def signal_handler(signum, frame):
        raise KeyboardInterrupt()
    
    # Set up signal handlers
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if os.name != 'nt' and os.geteuid() != 0:
            raise PermissionError("This tool requires root/sudo privileges")
            
        # Create cleanup task
        cleanup_task = asyncio.create_task(self._periodic_cleanup())
        
        try:
            await self.show_interactive_menu()
        finally:
            cleanup_task.cancel()
            try:
                await cleanup_task
            except asyncio.CancelledError:
                pass

            # Initialize scanner
            self.scan_start_time = time.time()
            
            try:
                await self.show_interactive_menu()
            except Exception as e:
                self.logger.error(f"Scanner error: {str(e)}")
                raise
            finally:
                self.scan_end_time = time.time()

        except KeyboardInterrupt:
            print(colored("\nScanner interrupted by user", "yellow"))
            self.logger.info("Scanner interrupted by user")
            return 1
        except Exception as e:
            print(colored(f"Critical error: {str(e)}", "red"))
            self.logger.error(f"Critical error: {str(e)}", exc_info=True)
            return 1
        finally:
            pass

        return 0


if __name__ == "__main__":
    # Set up signal handlers
    import signal
    
    def signal_handler(signum, frame):
        raise KeyboardInterrupt()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run scanner
    try:
        scanner = EnhancedK0braScanner()
        sys.exit(asyncio.run(scanner.main()))
    except KeyboardInterrupt:
        print(colored("\nScanner interrupted by user", "yellow"))
        sys.exit(1)
    except Exception as e:
        print(colored(f"Critical error: {str(e)}", "red"))
        sys.exit(1)
