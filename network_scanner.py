#! /bin/python
import scapy.all as scapy
import subprocess
import argparse
import re

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="Desired Interface")
    args = parser.parse_args()
    interface = args.interface
    if not args.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    else:
        return(interface)

def get_ip(interface):
    ifconfig_result = subprocess.check_output(["ifconfig",interface]).decode("utf-8")
    ip_address = str(re.search(r"inet ()\d*[.]\d*[.]\d*[.]",ifconfig_result).group(0)[5:]+"1/24")
    return(ip_address)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,verbose=False,timeout=5)[0]
    return(answered_list)

def print_scan_results(answered_list):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------")
    for element in answered_list:
        print(element[1].psrc+"\t\t"+element[1].hwsrc)

def main():
    interface = get_interface()
    ip = get_ip(interface)
    answered_list = scan(ip)
    print_scan_results(answered_list)

main()
