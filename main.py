#!/usr/bin/python3
import getmac
import nmap
import socket
import argparse
import platform
import time
from requests import get
from rich import box
from rich.live import Live
from rich.table import Table
from rich.console import Console
from threading import Thread

console = Console()

class networkInfo:
    def __init__(self, subnet=None):
        self.subnet = subnet or self.get_default_subnet()
        self.Nmap = nmap.PortScanner()

    def get_default_subnet(self):
        hosts = self.internal_ip.split('.')
        return '.'.join(hosts[:-1]) + '.0/24'

    @property
    def internal_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    @property
    def external_ip(self):
        return get('http://ipinfo.io/json').json()

    def get_os_info(self, ip):
        if 'osmatch' in self.Nmap[ip] and len(self.Nmap[ip]['osmatch']) > 0:
            return self.Nmap[ip]['osmatch'][0]['name']
        return 'Unknown'

    def IpInfo(self):
        table = Table(expand=True, title='IP INFO', box=box.SQUARE_DOUBLE_HEAD)
        table.add_column("Option", style='yellow')
        table.add_column("Value", style='green')

        with Live(table, refresh_per_second=1):
            table.add_row("Internal", f"{self.internal_ip}")
            for key, val in self.external_ip.items():
                if key not in ['hostname', 'readme']:
                    key = key.replace('ip', 'external')
                    table.add_row(key, val)
            time.sleep(1)  # Small delay to ensure table updates

    def scan_ip(self, ip, table, include_os_info):
        device_name = socket.getfqdn(ip)
        device_name = '[red]Unknown' if device_name == ip else device_name
        mac = getmac.get_mac_address(ip=ip)
        row = [f"{device_name}", f"{ip}", f"{mac if mac else '[red]Unknown'}"]
        if include_os_info:
            os_name = self.get_os_info(ip)
            row.append(os_name)
        table.add_row(*row)
        time.sleep(0.1)  # Small delay to ensure table updates

    def wifiUsers(self, include_os_info=False):
        table = Table(expand=True, title='WIFI USERS', box=box.SQUARE_DOUBLE_HEAD, show_lines=True)
        table.add_column("Device", style='cyan')
        table.add_column("IP Address", style='green')
        table.add_column("MAC Address", style='green')
        if include_os_info:
            table.add_column("OS Name", style='magenta')

        with Live(table, refresh_per_second=1):
            if include_os_info:
                self.Nmap.scan(hosts=self.subnet, arguments='-O -T4 -F')  # Fast scan
            else:
                self.Nmap.scan(hosts=self.subnet, arguments='-T4 -F')  # Fast scan 
            
            threads = []
            for ip in self.Nmap.all_hosts():
                if ip.endswith('.1') or ip.endswith('.255'):
                    continue
                t = Thread(target=self.scan_ip, args=(ip, table, include_os_info))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()

    

def result(subnet=None):
    return networkInfo(subnet=subnet)

def main():
    parser = argparse.ArgumentParser(description='Network Information Tool')
    parser.add_argument('subnet', nargs='?', default=None, help='Specify the subnet to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-i', '--info', action='store_true', help='Display IP information')
    parser.add_argument('-w', '--wifi', action='store_true', help='Display WiFi users')
    parser.add_argument('-a', '--all', action='store_true', help='Display All Options')
    parser.add_argument('-o', '--os', action='store_true', help='Display OS information in WiFi users table')
    
    args = parser.parse_args()
    
    console.print("""

 ___      _  _     _   ___                            
|   \ _ _| \| |___| |_/ __| __ __ _ _ _  _ _  ___ _ _ 
| |) | '_| .` / -_)  _\__ \/ _/ _` | ' \| ' \/ -_) '_|
|___/|_| |_|\_\___|\__|___/\__\__,_|_||_|_||_\___|_|                 
""")
    
    console.print("""
[[green]+[/]] Note: The Script Created by [link=https://github.com/DrDataYE]@DrDataYE[/link] from Telegram Channel [link=https://t.me/LinuxArabe]LinuxArabe[/link].
[[green]+[/]] Tool version 1.0.
""")

    

    if not (args.info or args.wifi or args.os):
        args.info, args.wifi, args.os = False, True, False

    obj = result(subnet=args.subnet)

    if args.all:
        args.info = True
        args.wifi = False
        args.os = True
        
    
    if args.info:
        obj.IpInfo()
    
    if args.wifi or args.os:
        obj.wifiUsers(include_os_info=args.os)
    
if __name__ == '__main__':
    main()
