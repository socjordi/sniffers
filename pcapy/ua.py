#!/usr/bin/env python

import pcapy
import dpkt
import socket
import json
import sys
from datetime import datetime

#################################################################################

cap=pcapy.open_live('enp2s0f0',100000,1,0)

cap.setfilter('tcp')

num=0

while True:

  try:

    (header,payload)=cap.next()

    eth = dpkt.ethernet.Ethernet(str(payload))
    ip = eth.data
    tcp = ip.data

    if tcp.dport == 80 and len(tcp.data) > 0:

      ip_src=socket.inet_ntoa(ip.src)
      ip_dst=socket.inet_ntoa(ip.dst)
      #syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN )

      user_agent=None
      first_index = tcp.data.find("\r\nUser-Agent:")
      if first_index >= 0:
        first_index = first_index + len("\r\nUser-Agent: ")
        last_index = tcp.data.find("\r\n", first_index)
        if last_index >= 0:
          user_agent = tcp.data[first_index:last_index]

      if not user_agent:

        print("ip_src=%s ip_dst=%sd" % (socket.inet_ntoa(ip_src), socket.inet_ntoa(ip_dst)))
        print(rcp.data)
        print

  except KeyboardInterrupt:
    break

  except:
    continue
