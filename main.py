import argparse
import subprocess
import socket
import platform
import ipaddress
import netifaces
import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from scapy.all import ARP, Ether, srp
from scapy.all import sniff

console = Console()
nm = nmap.PortScanner()

def clear_screen():
    command = 'cls' if platform.system().lower() == 'windows' else 'clear'
    subprocess.call(command, shell=True)

def get_device_info(ip, passive, filter_expr):
    if passive:
        return sniff_passive(filter_expr)
    
    try:
        # Ping the device to see if it's active
        ping_command = f"ping -c 1 -W 1 {ip}" if platform.system().lower() != "windows" else f"ping -n 1 -w 1000 {ip}"
        output = subprocess.run(ping_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if output.returncode != 0:
            return None

        # Get the hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = "Unknown"

        # Use ARP to get the MAC address
        mac = get_mac_address(ip)

        # Use nmap to get OS type
        os_type = get_os_type(ip)

        return {
            "IP": ip,
            "Hostname": hostname,
            "MAC": mac if mac else "Unknown",
            "OS": os_type if os_type else "Unknown OS"
        }
    except Exception:
        return None

def sniff_passive(filter_expr):
    def process_packet(packet):
        if ARP in packet and packet[ARP].op == 2:  # ARP response (is-at)
            return {
                "IP": packet[ARP].psrc,
                "Hostname": "Unknown",
                "MAC": packet[ARP].hwsrc,
                "OS": "Unknown OS"
            }
        return None

    sniff(filter=filter_expr, prn=process_packet, store=0, timeout=10)

def get_mac_address(ip):
    try:
        # Create an ARP request packet
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        # Send the packet and receive responses
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        for sent, received in answered_list:
            return received.hwsrc
    except Exception:
        return None

def get_os_type(ip):
    try:
        nm.scan(ip, arguments='-O')
        if 'osclass' in nm[ip]:
            return nm[ip]['osclass'][0]['osfamily']
    except Exception:
        return None

def get_local_network_ranges():
    """Retrieve all local network ranges of the current machine."""
    networks = []
    for interface in netifaces.interfaces():
        ifaddresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in ifaddresses:
            for addr in ifaddresses[netifaces.AF_INET]:
                ip_address = addr['addr']
                netmask = addr['netmask']
                network = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)
                networks.append(str(network))
    return networks

def scan_network(ip_ranges, max_workers=100, sleep_time=0, count=1, hardcore=False, passive=False, filter_expr="arp", print_results=False, listen=False, no_header=False):
    table = Table(title="Connected Devices on Network")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="magenta")
    table.add_column("MAC Address", style="green")
    table.add_column("Operating System", style="yellow")

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
    )

    if not no_header:
        layout["header"].update("[bold green]Scanning IP ranges[/bold green]")
    
    layout["body"].update(table)

    with Live(layout, console=console, refresh_per_second=1):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for ip_range in ip_ranges:
                network = ipaddress.ip_network(ip_range)
                console.print(f"Scanning IP range: {ip_range}", style="bold green")
                for ip in network.hosts():
                    futures.append(executor.submit(get_device_info, str(ip), passive, filter_expr))
                    
            for future in as_completed(futures):
                info = future.result()
                if info:
                    table.add_row(info["IP"], info["Hostname"], info["MAC"], info["OS"])
                    layout["body"].update(table)
                    if print_results:
                        print(f"{info['IP']}\t{info['Hostname']}\t{info['MAC']}\t{info['OS']}")

            if listen:
                while True:
                    for future in as_completed(futures):
                        info = future.result()
                        if info:
                            table.add_row(info["IP"], info["Hostname"], info["MAC"], info["OS"])
                            layout["body"].update(table)
                            if print_results:
                                print(f"{info['IP']}\t{info['Hostname']}\t{info['MAC']}\t{info['OS']}")

def main():
    parser = argparse.ArgumentParser(description="DrNetScanner - Network Scanning Tool")
    parser.add_argument("-i", "--device", help="Your network device")
    parser.add_argument("-r", "--range", help="Scan a given range instead of auto scan. 192.168.6.0/24,/16,/8")
    parser.add_argument("-l", "--list", help="Scan the list of ranges contained into the given file")
    parser.add_argument("-p", "--passive", action="store_true", help="Do not send anything, only sniff")
    parser.add_argument("-m", "--macfile", help="Scan a list of known MACs and host names")
    parser.add_argument("-F", "--filter", default="arp", help="Customize pcap filter expression (default: 'arp')")
    parser.add_argument("-s", "--sleep", type=int, default=0, help="Time to sleep between each ARP request (milliseconds)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of times to send each ARP request (for nets with packet loss)")
    parser.add_argument("-n", "--node", type=int, help="Last source IP octet used for scanning (from 2 to 253)")
    parser.add_argument("-d", "--ignore_home", action="store_true", help="Ignore home config files for autoscan and fast mode")
    parser.add_argument("-f", "--fastmode", action="store_true", help="Enable fastmode scan, saves a lot of time, recommended for auto")
    parser.add_argument("-P", "--print_results", action="store_true", help="Print results in a format suitable for parsing by another program and stop after active scan")
    parser.add_argument("-L", "--listen", action="store_true", help="Similar to -P but continue listening after the active scan is completed")
    parser.add_argument("-N", "--no_header", action="store_true", help="Do not print header. Only valid when -P or -L is enabled")
    parser.add_argument("-S", "--hardcore", action="store_true", help="Enable sleep time suppression between each request (hardcore mode)")
    parser.add_argument("--workers", type=int, default=100, help="Number of worker threads to use for scanning (default: 100)")

    args = parser.parse_args()

    if args.range:
        ip_ranges = [args.range]
    elif args.list:
        with open(args.list, 'r') as file:
            ip_ranges = [line.strip() for line in file.readlines()]
    else:
        ip_ranges = get_local_network_ranges()
        if not ip_ranges:
            console.print("Unable to determine local network ranges.", style="bold red")
            return

    scan_network(ip_ranges, args.workers, args.sleep, args.count, args.hardcore, args.passive, args.filter, args.print_results, args.listen, args.no_header)

if __name__ == "__main__":
    main()
