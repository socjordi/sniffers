#!/usr/bin/env python

import pcapy
import dpkt
import socket
import json
import sys
from datetime import datetime
from dnslib import DNSRecord
import re
import pymysql.cursors
import pymysql
import time
import ipaddress

#################################################################################

def islocal(ip):

  if (ip>=167772160) and (ip<=184549375):	# 10.0.0.0 - 10.255.255.255
    return True

  if (ip>=2886729728) and (ip<=2887778303):	# 172.16.0.0 - 172.31.255.255
    return True

  if (ip>=3232235520) and (ip<=3232301055):	# 192.168.0.0 - 192.168.255.255
    return True

  return False

#################################################################################

def process(ip_src,scrport,ip_dst,dstport):

  global stats

  ip_src=socket.inet_ntoa(ip_src)
  ip_dst=socket.inet_ntoa(ip_dst)
  #print "ip_src=%s:%s ip_dst=%s:%s" % (ip_src,srcport,ip_dst,dstport)

  if ip_src in stats:
    if not ip_dst in stats[ip_src]:
      #print("ip_src=%s ip_dst=%s" % (ip_src,ip_dst))
      stats[ip_src].append(ip_dst)
  else:
    stats[ip_src]=[ip_dst]

#################################################################################

def process2(ip_src,ip_dst,length):

  global stats,totaltotal

  ip_src=socket.inet_ntoa(ip_src)
  ip_dst=socket.inet_ntoa(ip_dst)

  print "ip_src=%s:%s ip_dst=%s:%s %d" % (ip_src,srcport,ip_dst,dstport,length)

  if ip_src in stats:
    if ip_dst in stats[ip_src]:
      #print("ip_src=%s ip_dst=%s" % (ip_src,ip_dst))
      stats[ip_src][ip_dst]=stats[ip_src][ip_dst]+length
    else:
      stats[ip_src][ip_dst]=length
  else:
    stats[ip_src]={}
    stats[ip_src][ip_dst]=length

#################################################################################

cap=pcapy.open_live('enp2s0f0',100000,1,0)

cap.setfilter('tcp dst port 5060 and not src port 5061')

start = time.time()

while True:

  #try:

    (header,payload)=cap.next()

    eth = dpkt.ethernet.Ethernet(str(payload))
    ip = eth.data
    tcp = ip.data
    srcport=tcp.sport
    dstport=tcp.dport

    length=len(ip.data)

    ipsrc=int(ipaddress.IPv4Address(ip.src))
    ipdst=int(ipaddress.IPv4Address(ip.dst))

    print srcport,dstport,tcp.data[0:7]
    #if tcp.data[0:3]=="SIP":
    print(tcp.data)

    #process2(ip.src,ip.dst,length)

  #except KeyboardInterrupt:
  #  break

  #except:
  #  continue

end = time.time()

#################################################################################
