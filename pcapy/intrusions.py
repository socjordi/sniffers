#!/usr/bin/env python

import pcapy
import dpkt
import socket
import json
import sys
from datetime import datetime

cap=pcapy.open_live('enp2s0f0',100000,1,0)

cap.setfilter('tcp')

while True:

  try:
    (header,payload)=cap.next()
    eth = dpkt.ethernet.Ethernet(str(payload))
    ip = eth.data
    ip_src=socket.inet_ntoa(ip.src)
    ip_dst=socket.inet_ntoa(ip.dst)
    tcp = ip.data
    srcport=tcp.sport
    dstport=tcp.dport
    length=len(tcp.data)
  except:
    continue

  ack=tcp.flags&16
  syn=tcp.flags&2

  if ack==0 and syn==2:
    print(ack,ip_src,srcport,ip_dst,dstport)
