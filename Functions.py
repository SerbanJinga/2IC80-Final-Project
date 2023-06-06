from scapy.all import *

class Functions():

	def __init__(self):
		pass

	def retrieveMACAdress(self, networkID, ipConfig):
		arp = ARP(pdst=ipConfig)
		ether = Ether(dst="ff:ff:ff:ff:ff:ff")
		pkt = ether / arp

		result_srp = srp(pkt, iface=networkID, timeout=10, inter=0.1)[0]
		print(result_srp)        
		outputResult = None

		for sentPackage, receivedPackage in result_srp:
			print("Requested ip is:" + receivedPackage.psrc + " with MAC address:" + receivedPackage.hwsrc)
			outputResult = receivedPackage.hwsrc


		return outputResult
