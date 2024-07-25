import argparse
import os
import sys
import threading
import time
from scapy.all import ARP, Ether, srp, sniff, conf, get_if_addr, get_if_list
from rich.console import Console
from datetime import datetime

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(description="DrNetScanner - Network Scanning Tool")
    parser.add_argument("targets", nargs='*', help="IP addresses or ranges to scan. If not provided, scans all networks on the device.")
    parser.add_argument("-p", "--passive", action="store_true", help="Do not send anything, only sniff")
    parser.add_argument("-F", "--filter", default="arp", help="Customize pcap filter expression (default: 'arp')")
    parser.add_argument("-s", "--sleep", type=int, default=0, help="Time to sleep between each ARP request (milliseconds)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of times to send each ARP request (for nets with packet loss)")
    parser.add_argument("-S", "--hardcore", action="store_true", help="Enable sleep time suppression between each request (hardcore mode)")
    parser.add_argument("--workers", type=int, default=100, help="Number of worker threads to use for scanning (default: 100)")
    return parser.parse_args()

def get_local_networks():
    networks = []
    for iface in get_if_list():
        ip = get_if_addr(iface)
        if ip != '0.0.0.0':
            networks.append(f"{ip}/24")
    return networks

def scan_network(target_ip, count, sleep_time, hardcore):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def display_results_live(network, devices, start_time):
    captured_packets = 0
    unique_devices = set()

    while True:
        new_devices = scan_network(network, 1, 0, False)
        for device in new_devices:
            if device['mac'] not in unique_devices:
                unique_devices.add(device['mac'])
                devices.append(device)
                console.print(f"IP Address: {device['ip']}, MAC Address: {device['mac']}, Count: 1, Len: 60, MAC Vendor / Hostname: Unknown")
                captured_packets += 1

        # elapsed_time = datetime.now() - start_time
        # console.print(f"\n{captured_packets} Captured ARP Req/Rep packets, from {len(devices)} hosts.   Total size: {len(devices) * 60} bytes")
        # console.print(f"Time elapsed: {elapsed_time}", end="\r")
        # break

def passive_sniff(filter_expr):
    sniff(filter=filter_expr, prn=process_packet, store=0)

def process_packet(packet):
    if packet.haslayer(ARP):
        arp = packet[ARP]
        console.print(f"[green]ARP Probe from {arp.psrc} ({arp.hwsrc})[/green]")

def main():
    args = parse_args()

    if args.passive:
        console.print("[yellow]Starting passive sniffing...[/yellow]")
        passive_sniff(args.filter)
    else:
        target_ranges = args.targets if args.targets else get_local_networks()

        for target_range in target_ranges:
            devices = []
            console.print(f"[blue]Scanning {target_range}...[/blue]")
            start_time = datetime.now()
            try:
                display_results_live(target_range, devices, start_time)
            except KeyboardInterrupt:
                elapsed_time = datetime.now() - start_time
                console.print(f"\n[yellow]Scan stopped. Total time elapsed: {elapsed_time}[/yellow]")
                break

if __name__ == "__main__":
    main()
