#!/usr/bin/python

import glob
import sys

##############################################################

def processa(nom):

  global stats

  with open(nom, "r") as f:

    for line in f:

      a=line.strip().split('\t')

      ip=a[0]
      numpackets=a[1]
      numbytes=a[2]

      if ip in stats:
        stats[ip]=stats[ip]+int(numbytes)
      else:
        stats[ip]=int(numbytes)

##############################################################

stats={}

files=glob.glob(sys.argv[1])

for file in files:
  processa(file)

for ip in stats:
  print "%09d\t%s" % (stats[ip], ip)
