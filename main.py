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

console = Console()
nm = nmap.PortScanner()

def clear_screen():
    command = 'cls' if platform.system().lower() == 'windows' else 'clear'
    subprocess.call(command, shell=True)

def get_device_info(ip):
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

def scan_network(ip_ranges, max_workers=100):
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

    layout["header"].update("[bold green]Scanning IP ranges[/bold green]")
    layout["body"].update(table)

    with Live(layout, console=console, refresh_per_second=1):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for ip_range in ip_ranges:
                network = ipaddress.ip_network(ip_range)
                console.print(f"Scanning IP range: {ip_range}", style="bold green")
                for ip in network.hosts():
                    futures.append(executor.submit(get_device_info, str(ip)))
                    
            for future in as_completed(futures):
                info = future.result()
                if info:
                    table.add_row(info["IP"], info["Hostname"], info["MAC"], info["OS"])
                    layout["body"].update(table)

def main():
    parser = argparse.ArgumentParser(description="DrNetScanner - Network Scanning Tool")
    parser.add_argument("ip_range", nargs="*", help="IP ranges to scan (e.g., 192.168.0.0/24). If not provided, all local network ranges will be scanned.")
    parser.add_argument("--workers", type=int, default=100, help="Number of worker threads to use for scanning (default: 100)")

    args = parser.parse_args()

    if args.ip_range:
        ip_ranges = args.ip_range
    else:
        ip_ranges = get_local_network_ranges()
        if not ip_ranges:
            console.print("Unable to determine local network ranges.", style="bold red")
            return

    scan_network(ip_ranges, args.workers)

if __name__ == "__main__":
    main()
# Hi