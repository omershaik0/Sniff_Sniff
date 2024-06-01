# Sniff Sniff (Packet Sniffing Tool)

This repository contains a Packet Sniffing tool for capturing HTTP and FTP data. The tool is written in Python and utilizes libraries such as Scapy, Colorama, and Cryptography.

## Features

- Capture HTTP requests (both GET and POST).
- Capture FTP credentials (username and password).
- Display captured information in a readable format with colored output.
- Validate FTP credentials using Hydra.

## Requirements

- Python 3.x
- Scapy
- Colorama
- Cryptography
- Hydra (Preinstalled in Kali)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/omershaik0/Sniff_Sniff.git
   cd Sniff_Sniff
   ```

2. Install the required Python libraries:
   ```bash
   pip install scapy colorama cryptography
   ```

3. Ensure Hydra is installed on your system. Refer to the [official Hydra documentation](https://github.com/vanhauser-thc/thc-hydra) for installation instructions.

## Usage

1. Run the script with root privileges:
   ```bash
   sudo python3 packet_sniffing_tool.py -i <interface> [options]
   ```

2. Arguments:
   - `-i`, `--interface`: Specify the network interface to sniff packets (required).
   - `-H`, `--http`: Enable capturing of HTTP data.
   - `-F`, `--ftp`: Enable capturing of FTP data.

3. Examples:
   - Capture HTTP packets on interface `eth0`:
     ```bash
     sudo python3 packet_sniffing_tool.py -i eth0 -H
     ```
   - Capture FTP packets on interface `wlan0`:
     ```bash
     sudo python3 packet_sniffing_tool.py -i wlan0 -F
     ```

## Output

The tool provides detailed information about the captured packets:
- Source and destination IP addresses.
- HTTP method (GET/POST), URL, host, user agent, and cookies.
- FTP login credentials (username and password).
- Validation of FTP credentials using Hydra.

## Script Flowchart

![ Alt Text](https://github.com/omershaik0/Sniff_Sniff/blob/main/sniff_sniff_flowchart.png)

## In Action

![ Alt Text](https://github.com/omershaik0/Sniff_Sniff/blob/main/sniff_sniff.gif)

## Disclaimer

This tool is intended for educational purposes only. Unauthorized use of this tool to intercept data without permission is illegal and unethical. The author is not responsible for any misuse of this tool.

---

For any questions or issues, please open an issue on GitHub.

Happy sniffing!
