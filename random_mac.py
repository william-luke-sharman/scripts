#! /bin/python
import subprocess
import random
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

def generate_new_mac_address():
    new_mac = ""
    for counter in range(6):
        if counter == 0:
            new_mac += str(random.randint(0,49)*2).zfill(2)
        else: 
            new_mac += (":"+str(random.randint(0,99)).zfill(2))
    return(new_mac)

def update_mac_address(interface,new_mac):
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig",interface,"up"])
    print("[+] Changing MAC address for " + interface  + " to: " + new_mac+".")

def validate_mac_address(interface,new_mac):
    ifconfig_result = subprocess.check_output(["ifconfig",interface]).decode("utf-8")
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_result)
    if mac_address_search_result and mac_address_search_result.group(0) == new_mac:
        print("[+] mac address for "+interface+" successfully changed to: "+mac_address_search_result.group(0)+".")
    elif mac_address_search_result and mac_address_search_result.group(0) != new_mac:
        print("[-] mac address for "+interface+" was not updated successfully.")
    else:
        print("[-] could not read mac address.")

def main():
    interface = get_interface()
    new_mac = generate_new_mac_address()
    update_mac_address(interface,new_mac)
    validate_mac_address(interface,new_mac)

main()
