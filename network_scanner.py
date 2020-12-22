#! /bin/python
import scapy.all as scapy
import subprocess
import re

def get_ip():
    ifconfig_result = subprocess.check_output(["ifconfig","wlan0"]).decode("utf-8")
    ip_address = str(re.search(r"inet ()\d*[.]\d*[.]\d*[.]",ifconfig_result).group(0)[5:]+"1/24")
    return(ip_address)

def scan():
    ip = get_ip()
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast,timeout=5)[0]
    print("IP\t\t\tMAC Address")
    print("-------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc+"\t\t"+element[1].hwsrc)

scan()
