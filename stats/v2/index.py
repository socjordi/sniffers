#!/usr/bin/python

from datetime import datetime
from dateutil import parser,tz
from elasticsearch import Elasticsearch,helpers
import os
import time
import fnmatch

##############################################################

def processa(path):

  global es,actions

  print(path)

  nom=os.path.basename(path)

  timestamp=datetime.strptime(nom[0:8]+nom[9:15], '%Y%m%d%H%M%S')
  zone=tz.gettz('Europe/Madrid')
  timestamp=timestamp.replace(tzinfo=zone)

  index="xarxa-%04d.%02d.%02d" % (timestamp.year, timestamp.month, timestamp.day)

  with open(path, "r") as f:

    for line in f:

      a=line.strip().split('\t')

      ipsrc=a[0]
      ipdst=a[1]
      numpackets=int(a[2])
      numbytes=int(a[3])

      #print("%s %s %d %d" % (ipsrc,ipdst,numpackets,numbytes))

      xarxa = {
      'timestamp': timestamp,
      'IPSrc': ipsrc,
      'IPDst': ipdst,
      'numpackets': numpackets,
      'numbytes': numbytes
      }

      action={
        "_index": index,
        "_type": "xarxa",
        "_source": xarxa
      }
      actions.append(action)

      if len(actions)>=250:
        helpers.bulk(es, actions)
        actions=[]

##############################################################

es=Elasticsearch(["10.1.1.1", "10.1.1.2"],max_retries=10,retry_on_timeout=True)

actions=[]

#path=sys.argv[1]
path="/stats/20171023"

num=0

matches = []
for root, dirnames, filenames in os.walk(path):
  for filename in fnmatch.filter(filenames, '*.log'):
    processa(root+"/"+filename)
    num=num+1
    if num>1:
      break

helpers.bulk(es, actions)
