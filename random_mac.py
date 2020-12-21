#! /bin/python
import subprocess
import random

interface = input("Interface: ")
new_mac = ""

for counter in range(6):
    if counter == 0:
        new_mac += str(random.randint(0,49)*2).zfill(2)
    else: 
        new_mac += (":"+str(random.randint(0,99)).zfill(2))

subprocess.call("ifconfig " + interface + " down", shell=True)
subprocess.call("ifconfig " + interface + " hw ether " + new_mac, shell=True)
subprocess.call("ifconfig " + interface + " up", shell=True)
print("[+] MAC address for " + interface  + " has been changed to: " + new_mac)
