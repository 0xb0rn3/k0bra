# K0bra Network Scanner 🌐🔍

A powerful and flexible network scanning tool that combines the speed of RustScan with the comprehensive features of traditional network scanners. This tool provides an intuitive menu-driven interface for network discovery, port scanning, and service detection.

## Features

The Network Scanner brings together the best features of multiple scanning tools while adding new capabilities:

### Core Scanning Features
- Advanced port scanning with configurable batch sizes and timeouts
- Comprehensive service detection and banner grabbing
- Multiple host discovery methods (ARP, ICMP, TCP)
- Support for custom port ranges and specific port lists
- Adaptive scanning with empty range skipping
- Random and sequential port scanning modes

### Performance Optimizations
- Concurrent scanning with configurable worker pools
- Automatic resource limit management
- Configurable retry mechanisms for improved accuracy
- Rate limiting capabilities to avoid network saturation
- Batch processing with dynamic sizing

### Output Options
- Multiple output formats (fancy, JSON, XML, text)
- Greppable output for automation
- Verbose logging capabilities
- Custom output paths and formats
- Real-time scan progress indicators

### Advanced Features
- Proxy support for anonymous scanning
- Custom User-Agent configuration
- Rate limiting and throttling
- Integration with custom scripts
- Configuration saving and loading

## Installation

### Prerequisites
- Python 3.7 or higher
- Root/sudo privileges (required for raw socket operations)

### Required Python Packages
```bash
pip install -r requirements.txt
```

The requirements.txt should contain:
```
scapy>=2.4.5
termcolor>=1.1.0
ipaddress>=1.0.23
```

### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/q4n0/k0bra.git
cd k0bra
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable:
```bash
chmod +x k0bra.py
```

## Usage

### Basic Usage

Start the scanner with:
```bash
sudo python3 k0bra.py
```

This will launch the interactive menu interface where you can configure and run scans.

### Menu System

The tool features a hierarchical menu system:

1. Main Menu
   - Set target network
   - Configure scan options
   - Configure performance settings
   - Configure output settings
   - Advanced options
   - Start scan
   - Save/Load configuration

2. Scan Options
   - Port range configuration
   - Custom port selection
   - Service detection settings
   - Banner grabbing options
   - Scan order selection

3. Performance Settings
   - Batch size adjustment
   - Timeout configuration
   - Resource limit settings
   - Worker pool size
   - Retry attempts

4. Output Settings
   - Format selection
   - Verbose mode
   - Greppable output
   - Custom output paths

### Example Configurations

#### Quick Scan
```python
network: 192.168.1.0/24
port_range: 1-1000
batch_size: 500
timeout_ms: 1500
scan_order: serial
```

#### Thorough Scan
```python
network: 192.168.1.0/24
port_range: 1-65535
batch_size: 100
timeout_ms: 3000
max_retries: 3
aggressive_scan: true
```

#### Stealth Scan
```python
network: 192.168.1.0/24
port_range: 1-1000
batch_size: 50
timeout_ms: 2000
rate_limit: 100
proxy: socks5://127.0.0.1:9050
```

## Best Practices

### Performance Optimization
- Start with smaller port ranges and adjust based on network conditions
- Use appropriate batch sizes for your network (default: 500)
- Enable skip_empty_ranges for faster scans
- Adjust timeouts based on network latency

### Network Consideration
- Use rate limiting on sensitive networks
- Enable aggressive_scan only when necessary
- Consider proxy usage for sensitive scans
- Monitor system resources during large scans

### Output Management
- Use JSON format for programmatic processing
- Enable verbose mode for debugging
- Use greppable output for automation
- Save configurations for repeated scans

## Advanced Usage

### Custom Scripts Integration

Create custom scripts for post-scan processing:
```python
# custom_script.py
def process_results(scan_results):
    # Process scan results
    pass
```

### Configuration Files

Save and load scan configurations:
```json
{
  "network": "192.168.1.0/24",
  "port_range": "1-1000",
  "batch_size": 500,
  "timeout_ms": 1500,
  "scan_order": "serial",
  "aggressive_scan": false
}
```

## Troubleshooting

### Common Issues

1. Permission Errors
```bash
sudo python3 k0bra.py
```

2. Resource Limits
```bash
ulimit -n 5000
```

3. Network Timeouts
- Adjust timeout_ms setting
- Reduce batch_size
- Enable max_retries

## Contributing

Contributions are welcome! Please read my contributing guidelines before submitting pull requests.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Submit a pull request

## Acknowledgments

- RustScan for inspiration on performance features
- Nmap for service detection techniques
- The Python networking community

## Security Considerations

This tool should be used responsibly and only on networks you have permission to scan. Unauthorized scanning may be illegal in your jurisdiction.

## Support

For issues and feature requests, please use the GitHub issue tracker or contact the maintainers directly.

---
Created by [b0urn3]  
GitHub: [github.com/q4n0]  
Version: 0.2

Remember to scan responsibly and always obtain proper authorization before scanning any network.
