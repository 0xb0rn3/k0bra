# k0bra

k0bra is a Python-based network scanning tool designed to detect devices on your local network by identifying their IP and MAC addresses. Developed by b0urn3, k0bra combines functionality with a touch of style and humor, making network scanning a bit more engaging.
Features

    Network Interface Selection: Choose from available network interfaces.
    IP and MAC Address Discovery: Scan your local network to identify devices and their MAC addresses.
    Customizable ASCII Banner: Display a fun and customizable ASCII banner.
    User-Friendly Output: Display scan results in a neatly formatted table.

Installation

To run k0bra, you'll need Python and a few dependencies. Follow these steps to get started:

    Clone the Repository:

    bash

git clone https://github.com/q4n0/k0bra.git
cd k0bra

Create a Virtual Environment (Optional but Recommended):

bash

python3 -m venv venv
source venv/bin/activate

Install Dependencies:

Create a requirements.txt file with the following content:

scapy
netifaces
tabulate
pillow
pyfiglet

Install the dependencies using pip:

bash
or skip and use the default one

    pip install -r requirements.txt

Usage

    Run the Script:

    bash

    python k0bra.py

    Follow the Prompts:
        Choose a network interface from the list.
        The script will scan the local network and display a table with IP and MAC addresses of detected devices.

Example

Here's an example of what the output might look like:

vbnet

@@@@@@@@@@@@@@@@@@@@
@@@@@@@*###*#@@@@@@@
@@@@@@*+#*#*+%@@@@@@
...
Ready to hunt down the hidden prey on your network!

Current connected interface: eth0
Other active network interfaces:
  1. wlan0

Enter the number of the network interface you want to use (default current interface): 

Scanning IP range: 192.168.1.0/24

Information for interface: eth0
+----------------+-------------------+
| IP             | MAC               |
+----------------+-------------------+
| 192.168.1.1    | 00:11:22:33:44:55 |
| 192.168.1.10   | aa:bb:cc:dd:ee:ff |
+----------------+-------------------+

No devices found on the network. Did the snakes slither away?

Scan complete. The hunt is over. Time to slither back!
