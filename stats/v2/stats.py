#!/usr/bin/python

import glob
import sys
import re
import os
import fnmatch

##############################################################

def processa(nom):

  global stats

  with open(nom, "r") as f:

    for line in f:

      a=line.strip().split('\t')

      ipsrc=a[0]
      ipdst=a[1]
      numpackets=a[2]
      numbytes=a[3]

      key=ipsrc+"/"+ipdst

      if key in stats:
        stats[key]=stats[key]+int(numbytes)
      else:
        stats[key]=int(numbytes)

##############################################################

stats={}

path=sys.argv[1]

matches = []
for root, dirnames, filenames in os.walk(path):
  for filename in fnmatch.filter(filenames, '*.log'):
    processa(root+"/"+filename)

for key in stats:
  
  matchObj = re.match(r'(.*)/(.*)', key, re.M|re.I)

  ipsrc=matchObj.group(1)
  ipdst=matchObj.group(2)

  print "%015d\t%s\t%s" % (stats[key], ipsrc, ipdst)
