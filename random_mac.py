#! /bin/python
import subprocess
import random
import argparse

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="Desired Interface")
    args = parser.parse_args()
    interface = args.interface
    return(interface)

def generate_new_mac_address():
    new_mac = ""
    for counter in range(6):
        if counter == 0:
            new_mac += str(random.randint(0,49)*2).zfill(2)
        else: 
            new_mac += (":"+str(random.randint(0,99)).zfill(2))
    return(new_mac)

def update_mac_address():
    interface = get_interface()
    new_mac = generate_new_mac_address()
    subprocess.call(["ifconfig",interface,"down"])
    subprocess.call(["ifconfig",interface,"hw","ether",new_mac])
    subprocess.call(["ifconfig",interface,"up"])
    print("[+] MAC address for " + interface  + " has been changed to: " + new_mac)

update_mac_address()

