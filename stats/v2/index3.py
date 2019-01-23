#!/usr/bin/python

from datetime import datetime,timedelta
from dateutil import parser,tz
from elasticsearch import Elasticsearch,helpers
import os
import time
import fnmatch
import re

##############################################################

def indexa(timestamp):

  global stats,es,actions

  index="xarxa-%04d.%02d.%02d" % (timestamp.year, timestamp.month, timestamp.day)

  zone=tz.gettz('Europe/Madrid')
  timestamp=timestamp.replace(tzinfo=zone)

  for key in stats:

   matchObj = re.match(r'(.*)/(.*)', key, re.M|re.I)

   (numbytes,numpackets)=stats[key]
   ipsrc=matchObj.group(1)
   ipdst=matchObj.group(2)

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

def processa(path):

  global stats

  print(path)

  #mtime=os.path.getmtime(path)
  #print(time.time()-mtime)

  nom=os.path.basename(path)

  #timestamp=datetime.strptime(nom[0:8]+nom[9:15], '%Y%m%d%H%M%S')
  #zone=tz.gettz('Europe/Madrid')
  #timestamp=timestamp.replace(tzinfo=zone)

  with open(path, "r") as f:

    for line in f:

      a=line.strip().split('\t')

      ipsrc=a[0]
      ipdst=a[1]
      numpackets=int(a[2])
      numbytes=int(a[3])

      key=ipsrc+"/"+ipdst

      if (key,0) in stats:
        (nbytes,npackets)=stats[key]
        stats[key]=(numbytes+nbytes,numpackets+npackets)
      else:
        stats[key]=(numbytes,numpackets)

##############################################################

ts = datetime.now() - timedelta(seconds=30)
#path="/stats/"+ts.strftime("%Y%m%d")
path="/stats"

stats={}
actions=[]
fitxers=[]

es=Elasticsearch(["10.1.1.1", "10.1.1.2"],max_retries=10,retry_on_timeout=True)

matches = []
for root, dirnames, filenames in os.walk(path):
  #for filename in fnmatch.filter(filenames, ts.strftime("%Y%m%dT%H%M*.log")):
  for filename in filenames:

    matchObj = re.match(r'\d\d\d\d\d\d\d\dT\d\d\d\d\d\d.log', filename, re.M|re.I)
    if matchObj:

      path=root+"/"+filename
      mtime=os.path.getmtime(path)
      elapsed=time.time()-mtime
      if elapsed>10:
        try:
          processa(path)
        except:
          print("ERROR %s" % (path))
        fitxers.append(path)
      #else:
      #  print "%s massa nou (%f)" % (path,elapsed)

ts = datetime(ts.year, ts.month, ts.day, ts.hour, ts.minute, 0)

indexa(ts)

helpers.bulk(es, actions)

for f in fitxers:
  try:
    os.remove(f)
  except:
    print("ERROR remove %s" % (f))

##############################################################
