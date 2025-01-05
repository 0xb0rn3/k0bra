# K0bra Network Scanner

A powerful and efficient network scanning tool designed for network administrators and security professionals. K0bra has evolved from its original Python implementation to a high-performance C version, offering enhanced speed and capabilities.

## 🚨 Ethical Usage Warning

This tool is intended **ONLY** for authorized network security testing and network administration purposes. Usage of this scanner without explicit permission from network owners is prohibited and may be illegal in your jurisdiction. The authors and maintainers assume no liability for misuse of this software.

## 🔄 Version History

### Current Version (2.0) - C Implementation
- Multi-threaded port scanning
- Real-time banner grabbing
- Enhanced performance through native C implementation
- Color-coded terminal output
- Progress tracking with visual progress bar
- Comprehensive service detection
- Built-in network interface management

### Legacy Version (1.0) - Python Implementation
- Basic network scanning capabilities
- Single-threaded operation
- Cross-platform compatibility
- Easier to modify and extend
- Lower system requirements

## ✨ Features

- Network range scanning using CIDR notation
- Automatic network interface detection
- Service identification for common ports
- Banner grabbing for service identification
- Multi-threaded scanning for improved performance
- Real-time progress monitoring
- Detailed port and service reporting
- Summary statistics after scan completion

## 🛠 Requirements

### C Version (2.0)
- GCC compiler
- POSIX-compliant operating system (Linux/Unix)
- Root/sudo privileges
- pthread library
- Standard C networking libraries

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/0xb0rn3/k0bra.git
cd k0bra

# For C version (2.0)
gcc k0bra.c -o k0bra -pthread

```

## 🚀 Usage

### C Version (2.0)
```bash
# Run with sudo privileges
sudo ./k0bra

# Follow the interactive prompts to:
# 1. Select network interface
# 2. Enter target network in CIDR format (e.g., 192.168.1.0/24)
```

## 🎯 Output Example

```
    ██╗  ██╗ ██████╗ ██████╗ ██████╗  █████╗ 
    ██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗
    █████╔╝ ██║   ██║██████╔╝██████╔╝███████║
    ██╔═██╗ ██║   ██║██╔══██╗██╔══██╗██╔══██║
    ██║  ██╗╚██████╔╝██████╔╝██║  ██║██║  ██║
    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    Advanced Network Scanner v2.0

[+] Host 192.168.1.1: 3 ports (Response: 1s)
    → 80/tcp - HTTP
    → 443/tcp - HTTPS
    → 22/tcp - SSH
```

## 🔍 Features Comparison

| Feature                  | C Version (2.0) | Python Version (1.0) |
|-------------------------|-----------------|---------------------|
| Multi-threading         | ✅              | ❌                  |
| Banner Grabbing         | ✅              | ❌                  |
| Progress Bar            | ✅              | ❌                  |
| Color Output            | ✅              | ❌                  |
| Cross-platform          | ❌              | ✅                  |
| Memory Efficiency       | ✅              | ❌                  |
| Execution Speed         | ✅              | ❌                  |
| Ease of Modification    | ❌              | ✅                  |

## 🤝 Contributing

While this project doesn't have a formal license, contributions are welcome through pull requests. Please ensure any modifications maintain the ethical use requirements and include appropriate documentation.

## 👤 Author and Maintainer

- **0xb0rn3**
  - GitHub: [@0xb0rn3](https://github.com/0xb0rn3)

## ⚠️ Disclaimer

This tool is provided as-is without any warranties. Users are solely responsible for ensuring they have appropriate authorization before scanning any networks. The authors and maintainers are not responsible for any misuse or damage caused by this tool.

## 🔐 Security Considerations

- Always obtain explicit permission before scanning any network
- Be aware that aggressive scanning can trigger security systems
- Some networks may block or blacklist scanning activities
- Certain ports or services may be restricted in your jurisdiction
- Handle banner information and scan results securely

## 🐛 Known Issues

- C version requires POSIX compliance and may not work on Windows
- Root privileges required for low-level socket operations
- Some antivirus software may flag the scanner
- Banner grabbing may timeout on slow connections

## 📞 Support

For bugs, feature requests, or security concerns, please open an issue on the GitHub repository. Note that response times may vary, and not all feature requests can be accommodated.
