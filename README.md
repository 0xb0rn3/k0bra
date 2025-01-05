# K0bra Network Scanner

A powerful and efficient network scanning tool designed for network administrators and security professionals. K0bra has evolved from its original Python implementation to a high-performance C version, offering enhanced speed and capabilities for network discovery and security assessment.

## 🚨 Ethical Usage Warning

This tool is intended **ONLY** for authorized network security testing and network administration purposes. Usage of this scanner without explicit permission from network owners is prohibited and may be illegal in your jurisdiction. The authors and maintainers assume no liability for misuse of this software.

## 🔄 Version History

### Current Version (3.0) - Enhanced C Implementation
Our latest release brings significant improvements in performance and capability:
- Multi-threaded port scanning with configurable thread pool (up to 128 concurrent threads)
- Advanced service detection with version identification for common protocols
- JSON output support with detailed scan results
- Customizable scan rates (1 to 1000 packets per second)
- Support for both SYN and Connect scan types
- Enhanced banner grabbing with configurable timeouts
- Real-time progress tracking with visual progress bar
- Comprehensive service detection for 12+ common protocols
- Built-in network interface management with automatic detection

### Legacy Version (2.0) - Basic C Implementation
The initial C port focused on performance improvements:
- Multi-threaded port scanning
- Basic banner grabbing
- Color-coded terminal output
- Progress tracking
- Basic service detection

### Original Version (1.0) - Python Implementation
Our original release emphasized accessibility:
- Basic network scanning capabilities
- Single-threaded operation
- Cross-platform compatibility
- Easier to modify and extend
- Lower system requirements

## ✨ Features

### Core Functionality
- Multiple scan types (TCP Connect, SYN)
- Advanced service version detection
- Configurable rate limiting (1-1000 pps)
- JSON-formatted output
- Detailed service fingerprinting
- Customizable connection timeouts
- MAC address detection
- Custom port ranges
- Real-time statistics

### Service Detection
K0bra can identify and fingerprint multiple services including:
- FTP (21/tcp)
- SSH (22/tcp)
- Telnet (23/tcp)
- SMTP (25/tcp)
- DNS (53/udp)
- HTTP (80/tcp)
- POP3 (110/tcp)
- IMAP (143/tcp)
- HTTPS (443/tcp)
- MySQL (3306/tcp)
- PostgreSQL (5432/tcp)
- MongoDB (27017/tcp)

## 🛠 Requirements

### System Requirements
- CPU: Any modern x86_64 processor
- RAM: Minimum 512MB, recommended 1GB+
- Disk Space: 50MB for installation
- Network: Active network interface with root access
- Operating System: Linux (kernel 2.6+)

### Dependencies
- GCC compiler (4.8+)
- POSIX-compliant operating system
- pthread library
- json-c library
- libpcap
- Root/sudo privileges

## 📦 Installation

### Debian/Ubuntu
```bash
# Update package list
sudo apt update

# Install build dependencies
sudo apt install -y build-essential cmake git
sudo apt install -y libjson-c-dev libpcap-dev libpthread-stubs0-dev

# Clone repository
git clone https://github.com/0xb0rn3/k0bra.git
cd k0bra

# Compile
gcc k0bra.c -o k0bra -pthread -ljson-c -lpcap

# Optional: Install system-wide
sudo cp k0bra /usr/local/bin/
```

### Red Hat/Fedora/CentOS
```bash
# Install build dependencies
sudo dnf groupinstall "Development Tools"
sudo dnf install json-c-devel libpcap-devel

# Clone repository
git clone https://github.com/0xb0rn3/k0bra.git
cd k0bra

# Compile
gcc k0bra.c -o k0bra -pthread -ljson-c -lpcap

# Optional: Install system-wide
sudo cp k0bra /usr/local/bin/
```

### Arch Linux
```bash
# Install build dependencies
sudo pacman -Sy base-devel
sudo pacman -S json-c libpcap

# Clone repository
git clone https://github.com/0xb0rn3/k0bra.git
cd k0bra

# Compile
gcc k0bra.c -o k0bra -pthread -ljson-c -lpcap

# Optional: Install system-wide
sudo cp k0bra /usr/local/bin/
```

### OpenSUSE
```bash
# Install build dependencies
sudo zypper install -t pattern devel_basis
sudo zypper install json-c-devel libpcap-devel

# Clone repository
git clone https://github.com/0xb0rn3/k0bra.git
cd k0bra

# Compile
gcc k0bra.c -o k0bra -pthread -ljson-c -lpcap

# Optional: Install system-wide
sudo cp k0bra /usr/local/bin/
```

### Gentoo
```bash
# Install build dependencies
sudo emerge --ask sys-libs/json-c net-libs/libpcap

# Clone repository
git clone https://github.com/0xb0rn3/k0bra.git
cd k0bra

# Compile
gcc k0bra.c -o k0bra -pthread -ljson-c -lpcap

# Optional: Install system-wide
sudo cp k0bra /usr/local/bin/
```

## 🚀 Usage

### Basic Usage
```bash
# List available network interfaces
sudo k0bra -h

# Basic scan of a single host
sudo k0bra -i eth0 -t 192.168.1.1

# Scan specific port range
sudo k0bra -i eth0 -t 192.168.1.1 -p 1-1024

# Full scan with service detection
sudo k0bra -i eth0 -t 192.168.1.1 -p 1-65535 -b -v
```

### Advanced Options
```bash
Usage: k0bra [options]

Options:
  -i <interface>    Network interface to use
  -t <target>       Target IP address
  -p <port-range>   Port range (e.g., 1-1024)
  -s <scan-type>    Scan type (connect/syn)
  -r <rate>         Rate limit (packets per second)
  -o <file>         Output file (JSON format)
  -v                Verbose output
  -b                Enable banner grabbing
  -h                Show help message

Examples:
  # SYN scan with custom rate
  sudo k0bra -i eth0 -t 192.168.1.1 -s syn -r 500

  # Save results to JSON
  sudo k0bra -i eth0 -t 192.168.1.1 -o results.json

  # Full verbose scan
  sudo k0bra -i eth0 -t 192.168.1.1 -p 1-65535 -b -v -s syn -r 1000
```

## 🎯 Output Formats

### Terminal Output
```
    ██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ 
    ██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
    █████╔╝ ██║   ██║██████╔╝██████╔╝███████║
    ██╔═██╗ ██║   ██║██╔══██╗██╔══██╗██╔══██║
    ██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    Advanced Network Scanner v3.0

[*] Starting scan on 192.168.1.1 (eth0)
[*] Scanning ports 1-65535

[█████████████████████████████████████████████████] 100.0%

=== Scan Results ===

[+] Host: 192.168.1.1
    → 22/tcp - SSH (OpenSSH 8.2p1)
      Banner: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    → 80/tcp - HTTP (nginx 1.18.0)
    → 443/tcp - HTTPS
    → 3306/tcp - MySQL (8.0.32)
      Banner: 5.5.5-10.1.48-MariaDB

=== Summary ===
Total hosts scanned: 1
Hosts alive: 1
Total open ports: 4
Average open ports per host: 4.0
```

### JSON Output Format
```json
{
  "scan_info": {
    "scan_type": "TCP Connect",
    "start_time": 1704499200,
    "interface": "eth0",
    "rate_limit": 1000
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "ports": [
        {
          "port": 22,
          "state": "open",
          "service": "SSH",
          "version": "OpenSSH 8.2p1",
          "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        },
        {
          "port": 80,
          "state": "open",
          "service": "HTTP",
          "version": "nginx 1.18.0"
        }
      ]
    }
  ]
}
```

## 🔍 Features Comparison

| Feature                   | C Version (3.0) | C Version (2.0) | Python Version (1.0) |
|--------------------------|-----------------|-----------------|---------------------|
| Multi-threading          | ✅              | ✅              | ❌                  |
| Banner Grabbing          | ✅              | ✅              | ❌                  |
| Service Version Detection| ✅              | ❌              | ❌                  |
| JSON Output              | ✅              | ❌              | ❌                  |
| Rate Limiting            | ✅              | ❌              | ❌                  |
| SYN Scanning            | ✅              | ❌              | ❌                  |
| Progress Bar            | ✅              | ✅              | ❌                  |
| Color Output            | ✅              | ✅              | ❌                  |
| Cross-platform          | ❌              | ❌              | ✅                  |
| Memory Efficiency       | ✅              | ✅              | ❌                  |
| Execution Speed         | ✅              | ✅              | ❌                  |
| Ease of Modification    | ❌              | ❌              | ✅                  |

## 🔧 Troubleshooting

### Common Issues and Solutions

1. **Permission Denied**
   ```bash
   # Solution: Run with sudo
   sudo ./k0bra [options]
   ```

2. **Interface Not Found**
   ```bash
   # List available interfaces
   ip addr show
   # Use correct interface name
   sudo ./k0bra -i <correct_interface>
   ```

3. **Compilation Errors**
   ```bash
   # Ensure all dependencies are installed
   # Debian/Ubuntu:
   sudo apt install build-essential libjson-c-dev libpcap-dev
   ```

4. **Rate Limiting by Target**
   ```bash
   # Lower the scan rate
   sudo ./k0bra -i eth0 -t 192.168.1.1 -r 100
   ```

## 🤝 Contributing

While this project doesn't have a formal license, contributions are welcome through pull requests. Please ensure:

1. Code follows existing style
2. New features include documentation
3. Changes maintain ethical use requirements
4. Tests are included where appropriate

## 📞 Support and Contact

- GitHub Issues: [Project Issues Page](https://github.com/0xb0rn3/k0bra/issues)
- Author: [@0xb0rn3](https://github.com/0xb0rn3)

## ⚠️ Disclaimer

This tool is provided as-is without any warranties. Users are solely responsible for ensuring they have appropriate authorization before scanning any networks. The authors and maintainers are not responsible for any misuse or damage caused by this tool.

## 🔐 Security Best Practices

1. Always obtain explicit permission before scanning
2. Use rate limiting to avoid triggering security systems
3. Handle scan results securely
4. Be aware of local network scanning regulations
5. Monitor system logs during scans
6. Use appropriate timeouts for different network conditions

## 🔄 Regular Updates

The project is actively maintained with regular updates for:
- Security patches
- New service fingerprints
- Performance improvements
- Bug fixes
- Feature enhancements

Check the GitHub repository regularly for the latest updates and improvements.
