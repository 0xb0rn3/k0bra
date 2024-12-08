# k0bra - The Network Scavenger

**k0bra** is a comprehensive network scanning tool developed by **b0urn3**. It integrates both **Masscan** and **Nmap**, allowing fast and stealthy scanning for IPs, MAC addresses, open ports, and services on your local network.

## Features:
- **Fast Scanning**: Utilizes **Masscan** for rapid port scans with customizable rate control.
- **Stealthy Scanning**: Leverage **Nmap's evasion features** like decoy IPs, fragmentation, and source port manipulation.
- **Comprehensive Results**: Supports **Nmap’s** full capabilities for OS and service version detection.
- **Cross-tool Functionality**: Switch between **Masscan** and **Nmap** based on scan speed and precision.
- **Interactive Menu**: Choose scan types, interfaces, and output preferences interactively.
- **CSV Output**: Save results in a clean CSV format, including IP, MAC, and open ports.

## Requirements:
- Python 3.x
- **Scapy**: `pip install scapy`
- **Netifaces**: `pip install netifaces`
- **Nmap**: Install via `pip install python-nmap `
- **Masscan**

## Usage:
1. Run the script:
    ```bash
    sudo python3 k0bra.py
    ```
2. Follow the interactive prompts to select scan types, network interfaces, and output preferences.

## Evasion Features:
- **Nmap**: Includes **decoy scanning** (`-D`), **packet fragmentation** (`-f`), **source port manipulation** (`-g`), and **proxy routing** (`--proxies`).
- **Masscan**: Includes **rate control** and **stealth scanning** features.

## License:
This tool is licensed under the MIT License.

---

**Developed by b0urn3.**  
Find more tools at: [https://github.com/q4n0](https://github.com/q4n0)

