import threading
import dns_spoofing
import arp_spoofing
import time

def run_arp():
    arp_spoofing.main()

def run_dns():
    dns_spoofing.main()

if __name__ == "__main__":
    arpThread = threading.Thread(target=run_arp)
    dnsThread = threading.Thread(target=run_dns)

    arpThread.start()
    time.sleep(10)
    dnsThread.start()

    arpThread.join()
    dnsThread.join()
