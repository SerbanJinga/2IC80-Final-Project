import threading
import dns_test
import arp_test
import time

def run_arp():
    arp_test.main()

def run_dns():
    dns_test.main()

if __name__ == "__main__":
    arpThread = threading.Thread(target=run_arp)
    dnsThread = threading.Thread(target=run_dns)

    arpThread.start()
    time.sleep(10)
    dnsThread.start()

    arpThread.join()
    dnsThread.join()
