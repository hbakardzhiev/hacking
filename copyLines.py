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


print("start handshake")
sport = random.randint(1024, 65535)
ip = IP(src ="10.0.2.5", dst = GOOGLE_IP) #google ip  
tcpSYN = TCP(sport = sport, dport = 443, flags ="S", seq = 1000) 
pktSYNACK = sr1(ip/tcpSYN)

#os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.0.2.5 -j DROP")

#send ACK after receiving SYNACK
ACK = TCP(sport = sport, dport = 443, flags ="A", seq = 1001, ack = pktSYNACK.seq + 1)
send(ip/ACK)

#http
# pkts = sniff(count = 5)

#os.system("sudo iptables --flush")