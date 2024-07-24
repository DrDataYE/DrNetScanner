import argparse
import subprocess
import socket
import platform
import ipaddress
import netifaces
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()

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

        # Get the MAC address
        mac = None
        if platform.system().lower() == "windows":
            arp_output = subprocess.run(f"arp -a {ip}", shell=True, stdout=subprocess.PIPE).stdout.decode()
            for line in arp_output.splitlines():
                if ip in line:
                    mac = line.split()[1]
                    break
        else:
            arp_output = subprocess.run(f"arp -n {ip}", shell=True, stdout=subprocess.PIPE).stdout.decode()
            for line in arp_output.splitlines():
                if ip in line:
                    mac = line.split()[2]
                    break

        # Dummy data for OS (since getting OS remotely is complex)
        os_type = "Unknown OS"

        return {
            "IP": ip,
            "Hostname": hostname,
            "MAC": mac if mac else "Unknown",
            "OS": os_type
        }
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

def scan_network(ip_range, max_workers=100):
    table = Table(title="Connected Devices on Network")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="magenta")
    table.add_column("MAC Address", style="green")
    table.add_column("Operating System", style="yellow")

    network = ipaddress.ip_network(ip_range)

    with Live(table, console=console, refresh_per_second=1):
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(get_device_info, str(ip)): ip for ip in network.hosts()}
            for future in as_completed(futures):
                info = future.result()
                if info:
                    table.add_row(info["IP"], info["Hostname"], info["MAC"], info["OS"])

def main():
    parser = argparse.ArgumentParser(description="DrNetScanner - Network Scanning Tool")
    parser.add_argument("ip_range", nargs="?", help="IP range to scan (e.g., 192.168.0.0/24). If not provided, all local network ranges will be scanned.")
    parser.add_argument("--workers", type=int, default=100, help="Number of worker threads to use for scanning (default: 100)")

    args = parser.parse_args()

    if args.ip_range:
        ip_ranges = [args.ip_range]
    else:
        ip_ranges = get_local_network_ranges()
        if not ip_ranges:
            console.print("Unable to determine local network ranges.", style="bold red")
            return

    for ip_range in ip_ranges:
        console.print(f"Scanning IP range: {ip_range}", style="bold green")
        scan_network(ip_range, args.workers)

if __name__ == "__main__":
    main()
