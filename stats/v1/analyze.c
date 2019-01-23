#include <pcap.h>
#include <stdio.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "uthash.h"

#define KEYSIZE 16

typedef struct {
	char key[KEYSIZE];
	long numpackets;
	long ipbytes;
	UT_hash_handle hh; /* makes this structure hashable */
} ipflow_t;

typedef struct {
	char key[KEYSIZE];
} ipflow_lookup_key_t;

ipflow_t *IPFlowSrc = NULL;
ipflow_t *IPFlowDst = NULL;

long numpackets,total;
float seconds;

/**********************************************************************************/

void AddIPFlow(char index, char *key, long v) {

	ipflow_t *p;
	ipflow_lookup_key_t lookup_key;

	memset(&lookup_key.key, 0, KEYSIZE);
        for (int i=0; (i<strlen(key)); i++) lookup_key.key[i]=key[i];

        //for (int i=0; (i<KEYSIZE); i++) printf("%02x ", lookup_key.key[i]);
        //printf("\n");

        if (index=='S')
	  HASH_FIND(hh, IPFlowSrc, &lookup_key, KEYSIZE, p);
        else
	  HASH_FIND(hh, IPFlowDst, &lookup_key, KEYSIZE, p);

	if (p) {	// La clau ja existeix

		//printf("%c key=/%s/ EXISTEIX\n", index, lookup_key.key);

		p->numpackets = p->numpackets + 1;
		p->ipbytes += v;
	}
	else {		// La clau no existeix


		p = malloc(sizeof(ipflow_t));
		memset(p, 0, sizeof(ipflow_t));
		memset(p->key, 0, KEYSIZE);
        	for (int i=0; (i<strlen(key)); i++) p->key[i]=key[i];
		p->numpackets = 1;
		p->ipbytes = v;

        	//for (int i=0; (i<KEYSIZE); i++) printf("%02x ", key[i]);
        	//printf("\n");
		//printf("%c ADD key=/%s/\n", index, key);

                if (index=='S')
	  	  HASH_ADD(hh, IPFlowSrc, key, KEYSIZE, p);
                else
	  	  HASH_ADD(hh, IPFlowDst, key, KEYSIZE, p);
	}
}

/**********************************************************************************/

long ListIPFlow(char *log, char index) {

	ipflow_t *i, *j;
	long num;
	FILE * fp;

	num=0;

	fp = fopen(log, "wt");

        if (index=='S')
	HASH_ITER(hh, IPFlowSrc, i, j) {
		fprintf(fp, "%s\t%li\t%li\n", i->key, i->numpackets, i->ipbytes);
		HASH_DEL(IPFlowSrc, i);
		free(i);
		num++;
	}
        else
	HASH_ITER(hh, IPFlowDst, i, j) {
		fprintf(fp, "%s\t%li\t%li\n", i->key, i->numpackets, i->ipbytes);
		HASH_DEL(IPFlowDst, i);
		free(i);
		num++;
	}

        fclose(fp);

	return num;
}

/**********************************************************************************/

int capture(pcap_t *handle, int numseconds) {

	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
        const u_char *ip_header;
        int total_length;
	struct timeval t0, t1;
        unsigned short protocol;
	char src[INET_ADDRSTRLEN+1], dst[INET_ADDRSTRLEN+1];

	gettimeofday(&t0, 0);

        total=0;
        numpackets=0;
	IPFlowSrc = NULL;
	IPFlowDst = NULL;

        while (1) {

	  packet = pcap_next(handle, &header);

	  //for (int i=0; (i<30); i++) printf(" %02x", packet[i]);
          //printf("\n"); 
	
	  //total_length = (packet[20] << 8) | packet[21];
	  protocol = packet[27];

	  inet_ntop(AF_INET, ((void *)(packet + 30)), src, INET_ADDRSTRLEN);
	  inet_ntop(AF_INET, ((void *)(packet + 34)), dst, INET_ADDRSTRLEN);

	  //printf("src=%s dst=%s proto=%d header.len=%d\n", src, dst, protocol, header.len);

          total=total+header.len;

	  AddIPFlow('S', src, header.len);
	  AddIPFlow('D', dst, header.len);

          numpackets++;

	  gettimeofday(&t1, 0);
	  seconds= (t1.tv_sec - t0.tv_sec) + (t1.tv_usec - t0.tv_usec) / 1000000.0f;
          if (seconds>numseconds) break;
        }


	return(seconds);
}

/**********************************************************************************/

int main(int argc, char *argv[]) {

  char *dev="enp2s0f0";
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  long numsrc, numdst;
  struct timeval t0, t1;
  //struct bpf_program fp;		/* The compiled filter */
  //char filter_exp[] = "";		/* The filter expression */
  time_t nowtime;
  struct tm *nowtm;
  char s0[64], s1[64], tmbuf[64];
  FILE *fp;

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	return(2);
  }

  /* Compile and apply the filter
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	return(2);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
  	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
  	return(2);
  }
  */

  while (1) {

	gettimeofday(&t0, 0);
	capture(handle, 5);
	gettimeofday(&t1, 0);

	nowtime = t0.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(s0, sizeof tmbuf, "%Y%m%dT%H%M%SS.log", nowtm);

	nowtime = t1.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(s1, sizeof tmbuf, "%Y%m%dT%H%M%SD.log", nowtm);

	numsrc=ListIPFlow(s0, 'S');
	numdst=ListIPFlow(s1, 'D');

	//printf("%s %s numsrc=%ld numdst=%ld\n", s0, s1, numsrc, numdst);

	fp = fopen("analyze.log", "at");
        fprintf(fp, "%s\t%s\tnumsrc=%ld\tnumdst=%ld\tpackets=%ld\tbytes=%ld (%0.2f MB)\tseconds=%f\t%0.2f Mbps\n",
		s0, s1, numsrc, numdst, numpackets, total, (float)total/1048576, seconds, total/seconds/131072);
        fclose(fp);

  }

  pcap_close(handle);
}
/**********************************************************************************/
