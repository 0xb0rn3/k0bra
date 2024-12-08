## k0bra - The Network Scavenger

k0bra is a powerful and versatile network security tool designed for vulnerability assessments and penetration testing. Developed by b0urn3, this tool is equipped with capabilities for scanning network devices, discovering open ports, fetching CVEs, and automating Metasploit exploits based on discovered vulnerabilities. It also stores results in a local database and generates detailed CSV reports.

## Features

- Network Scanning: Automatically scans for active devices within a specified IP range and maps their MAC addresses and open ports.
- CVE Fetching: Retrieves CVE details from the CIRCL API to stay up-to-date with the latest security vulnerabilities.
- Metasploit Integration: Automatically runs Metasploit exploit modules based on discovered vulnerabilities.
- Local Database: Stores scan results in an SQLite database for tracking and future analysis.
- Logging: Logs detailed information about scans, vulnerabilities, and any issues to ensure a clear and auditable record.
- CSV Report Generation: Generates a detailed CSV report summarizing network information, open ports, discovered vulnerabilities, and associated risk scores.

## Installation

Before running k0bra, ensure you have the following dependencies installed:

- Python 3.x
- requests library
- scapy library
- nmap tool
- Metasploit Framework (for Metasploit exploits)
- SQLite (for storing results)
## Step 1: Clone the Repository Clone the repository to your local machine:

git clone https://github.com/q4n0/k0bra.git
cd k0bra

## Step 2: Install Dependencies

Install the required Python dependencies using pip:

pip install -r requirements.txt

## Step 3: Install Metasploit

Make sure that Metasploit is installed on your system. You can follow the official Metasploit installation guide: Metasploit Installation

## Step 4: Set Permissions

Ensure you have the required permissions to run network scans (may need root/administrator privileges for certain scans).

## Usage

## 1. Run the Tool

To run the tool, simply execute the Python script:

python3 k0bra.py

You will be prompted to enter the target network or IP range (e.g., 192.168.1.0/24), and the path to the CVE JSON file. Alternatively, the tool can fetch the latest CVE details automatically from the CIRCL API.

## 2. Network Scan

- The tool will scan the provided target network and display discovered devices with their associated IP and MAC addresses.
- It will also check for open ports (TCP/UDP) on each device.

## 3. Vulnerability Assessment

- The script will compare the discovered services with known vulnerabilities (CVEs) from the CVE data source.
- The tool will suggest exploits based on the discovered vulnerabilities and automatically run Metasploit modules if available.

## 4. Report Generation

Once the scan is complete, a CSV report (scan_report.csv) will be generated with the following columns:
- IP Address
- Open Ports
- Vulnerabilities
- Risk Score

## 5. Logs

All actions and errors are logged in tool.log for auditing and troubleshooting.

Example Output

Please provide the target network or IP range (e.g., 192.168.1.0/24):
192.168.1.0/24

Please provide the path to the CVE JSON file (e.g., /path/to/cve_database.json):
/path/to/cve_database.json

Running network scan on 192.168.1.0/24...
Found device 192.168.1.1 with MAC address 00:1B:2A:3C:4D:5E
Open Ports: TCP: [80, 443], UDP: [53]
Checking for vulnerabilities...

Running Metasploit exploit for CVE-2017-0143 on 192.168.1.1...

Scan report saved as scan_report.csv

## Contribution

Feel free to fork the repository, submit issues, or create pull requests with bug fixes or improvements.

## Contact

- Developer: b0urn3
- Email: b0urn3@proton.me
- Instagram: @onlybyhive

## Disclaimer

This tool is intended for educational and authorized penetration testing use only. Always ensure you have explicit permission before performing any network scanning or exploitation on a network or system.
