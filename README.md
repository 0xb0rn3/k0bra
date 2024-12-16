# K0bra Network Scanner 🌐🔍

## Overview

K0bra is an advanced, multi-purpose network scanning tool designed for comprehensive network reconnaissance and host discovery. Built with Python and leveraging powerful async networking libraries, K0bra provides robust network scanning capabilities with flexible output formats and advanced discovery techniques.

## 🚀 Features

### Host Discovery
- **ARP Network Scanning**: Efficiently identifies live hosts on a network
- **DNS Hostname Resolution**: Attempts to resolve hostnames for discovered IP addresses
- **Concurrent Discovery**: Utilizes asyncio for high-performance scanning

### Port Scanning
- **TCP Connection Scanning**: Identifies open ports on discovered hosts
- **Service Detection**: Recognizes common services based on port numbers
- **Configurable Port List**: Supports custom port specification
- **Parallel Scanning**: Concurrent port scanning for maximum efficiency

### Output Formats
- **Fancy**: Colorful, human-readable console output (default)
- **JSON**: Structured, machine-readable format
- **XML**: Standardized XML representation
- **Plain Text**: Simple console output

## 🔧 Requirements

### System Requirements
- Python 3.7+
- Root/sudo privileges
- Linux/macOS recommended

### Python Dependencies
- `scapy`
- `termcolor` (optional, for enhanced color output)

## 🛠 Installation

1. Clone the repository:
```bash
git clone https://github.com/q4n0/k0bra.git
cd k0bra
```

2. Install required dependencies:
```bash
pip install scapy
pip install termcolor  # Optional
```

## 🖥 Usage

### Basic Scan
```bash
sudo python3 k0bra.py 192.168.1.0/24
```

### Advanced Usage
```bash
# Specify output format
sudo python3 k0bra.py 192.168.1.0/24 -f json

# Customize worker count
sudo python3 k0bra.py 192.168.1.0/24 -w 100

# Enable verbose logging
sudo python3 k0bra.py 192.168.1.0/24 -v
```

### Command-Line Options
- `network`: Network CIDR to scan (required)
- `-f, --format`: Output format (fancy/json/xml/text, default: fancy)
- `-w, --workers`: Maximum concurrent workers (default: 50)
- `-v, --verbose`: Enable detailed logging

## 📋 Output Examples

### Fancy Output (Default)
- Colorful console display
- Emoji-enhanced readability
- Sorted host information
- Network scan summary statistics

### JSON Output
- Structured data suitable for programmatic processing
- Includes IP, MAC, hostname, and port details

## ⚠️ Legal and Ethical Use

K0bra is intended for network administrators and security professionals to assess and manage their own networks. Always obtain proper authorization before scanning networks you do not own or manage.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👥 Contact

Project Developer: q4n0
- GitHub: [@q4n0](https://github.com/q4n0)
- Instagram: [@onlybyhive](https://instagram.com/onlybyhive)

## 🙏 Acknowledgments

- [Scapy](https://scapy.net/) for powerful network packet manipulation
- [Python Asyncio](https://docs.python.org/3/library/asyncio.html) for concurrent networking
