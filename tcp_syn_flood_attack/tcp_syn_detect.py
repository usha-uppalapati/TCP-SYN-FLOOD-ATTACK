#!/bin/env python3
from scapy.all import *
from collections import Counter
from time import localtime, strftime

syn_count = Counter()
threshold = 50


def syn_detect(pkt):
 if IP in pkt:
  ipsrc = str(pkt[IP].src)                     # source IP
  ipdst = str(pkt[IP].dst)                     # destination IP
  try:
   sport = str(pkt[IP].sport)               # source port
   dport = str(pkt[IP].dport)               # destination port
  except:
   sport = ""
   dport = ""
  prtcl = pkt.getlayer(2).name                 # protocol
  #flow = '{:<4} | {:<16} | {:<6} | {:<16} | {:<6} | '.format(prtcl, ipsrc, sport, ipdst, dport)
  # print(flow)
  # TCP SYN packet
 if TCP in pkt and pkt[TCP].flags & 2:
  src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')
  syn_count[src] += 1
  if syn_count.most_common(1)[0][1] > threshold and pkt.ack == 0:
   cur_time = strftime("%a, %d %b %Y %X", localtime())
   ip=syn_count.most_common(1)[0][0]
   print(cur_time + " SYN attack detected! IP: " + str(syn_count.most_common(1)[0][0]) + " No. of attempts: " +str(syn_count.most_common(1)[0][1]))
   del syn_count[ip]
   
   
#Sniffing the packets
sniff(prn=syn_detect, store=0)

#prevention module commands
#iptables -A INPUT -s 10.9.0.105 -j REJECT
#iptables -F  flush new entries
#iptables -L list all entries

