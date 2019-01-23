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

#################################################################################

def ip2bin(ip):

  ListA = ip.split(".")
  ListA = list(map(int, ListA))
  ListA = ListA[0]*(256**3) + ListA[1]*(256**2) + ListA[2]*(256**1) + ListA[3]

  return ListA

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

def process(ip_src,ip_dst,d):

  global connection

  try:

    for linia in str(d).splitlines():

      #matchObj = re.match(r'(\S+)\s+(\d+)\s+IN\s+A\s+(10\.\d+\.\d+\.\d+)$', linia, re.M|re.I)
      matchObj = re.match(r'(\S+)\s+(\d+)\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)$', linia, re.M|re.I)
      if matchObj:

   	nom=matchObj.group(1).lower()
   	#ttl=matchObj.group(2)
   	ip=matchObj.group(3)
        ipbin=ip2bin(ip)

        if islocal(ipbin):

          #print("nom=%s\tip=%s %d" % (nom,ip, ipbin))

          with connection.cursor() as cursor:

            cursor.execute('SELECT * FROM DGP_dns_fw WHERE ip=%s AND nom=%s', (ipbin, nom))
            row = cursor.fetchone()
            if row:
              iddnsfw=row['iddnsfw']
              sql="UPDATE DGP_dns_fw SET num=num+1,lastseen=%s WHERE iddnsfw=%s"
              cursor.execute(sql, (time.time(), iddnsfw))
            else:
              sql = "INSERT INTO DGP_dns_fw(ip, nom, created, lastseen, num) VALUES (%s, %s, %s, %s, %s)"
              cursor.execute(sql, (ipbin, nom, time.time(), time.time(), 1))

          connection.commit()

  except:
    return

#################################################################################

connection = pymysql.connect(host='10.1.1.2',
                             user='username',
                             password='password',
                             db='database',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

cap=pcapy.open_live('enp2s0f0',100000,1,0)

cap.setfilter('udp')

while True:

  try:
    (header,payload)=cap.next()
    eth = dpkt.ethernet.Ethernet(str(payload))
    ip = eth.data
    udp = ip.data
    srcport=udp.sport
    dstport=udp.dport
    length=len(udp.data)
  except:
    continue

  if srcport == 53:

    ip_src=socket.inet_ntoa(ip.src)
    ip_dst=socket.inet_ntoa(ip.dst)
    #print "%s:%d %s:%d length=%d" % (ip_src, srcport, ip_dst, dstport, length)

    d=DNSRecord.parse(udp.data)
    process(ip_src,ip_dst,d)

#################################################################################
