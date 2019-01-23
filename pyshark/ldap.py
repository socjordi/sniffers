#!/usr/bin/env python

import pyshark
import json
from pprint import pprint
import StringIO
import time

#################################################################################

capture = pyshark.LiveCapture(interface='enp2s0f0', bpf_filter='tcp port 389', output_file='/tmp/ldap.pcap')

packet_iterator=capture.sniff_continuously

while True:

  for packet in packet_iterator(packet_count=1000):

    #pprint(vars(packet.ldap))

    try:
      op=packet.ldap.protocolOp # bindRequest
    except:
      continue

    if op!="0": # bindRequest
      continue

    try:
      auth=packet.ldap.authentication
    except:
      auth=""

    if auth=="3":	# sasl
      continue

    try:
      mechanism=packet.ldap.mechanism
    except:
      mechanism=""

    try:
      simple=packet.ldap.simple
    except:
      simple=""

    if simple=="simple: <MISSING>":
      continue

    try:
      hostname=packet.ntlmssp.auth.hostname
    except:
      hostname=""

    try:
      username=packet.ntlmssp.auth.username
    except:
      username=""


    #print("LDAP authentication=%s mechanism=%s hostname=%s username=%s" % (auth,mechanism,hostname,username))

    with open('/home/monitor/ldap/ldap.log','at') as f:

      f.write(time.strftime("%Y-%m-%d %H:%M"))
      f.write("\n")
      s = StringIO.StringIO()
      pprint(vars(packet), s)
      pprint(vars(packet.ldap), s)
      f.write(s.getvalue())
      f.write("\n\n")

#################################################################################
