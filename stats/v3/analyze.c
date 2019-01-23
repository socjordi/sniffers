#include <pcap.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "uthash.h"

#include "SPCDNS/src/dns.h"
#include "SPCDNS/src/mappings.h"
#include "SPCDNS/src/netsimple.h"
#include "SPCDNS/src/output.h"

#define KEYSIZE 8

typedef struct {
	u_char key[KEYSIZE];
	long numpackets;
	long ipbytes;
	UT_hash_handle hh; /* makes this structure hashable */
} ipflow_t;

typedef struct {
	u_char key[KEYSIZE];
} ipflow_lookup_key_t;

ipflow_t *IPFlow = NULL;

long numpackets,total;
long dns, dnserror;
float seconds;

/**********************************************************************************/

void AddIPFlow(u_char *key, long v) {

	ipflow_t *p;
	ipflow_lookup_key_t lookup_key;

	memset(&lookup_key.key, 0, KEYSIZE);
        for (int i=0; (i<8); i++) lookup_key.key[i]=key[i];

        //for (int i=0; (i<KEYSIZE); i++) printf("%02x ", lookup_key.key[i]);
        //printf("\n");

	HASH_FIND(hh, IPFlow, &lookup_key, KEYSIZE, p);

	if (p) {	// La clau ja existeix

		//printf("%c key=/%s/ EXISTEIX\n", index, lookup_key.key);

		p->numpackets = p->numpackets + 1;
		p->ipbytes += v;
	}
	else {		// La clau no existeix

		p = malloc(sizeof(ipflow_t));
		memset(p, 0, sizeof(ipflow_t));
		memset(p->key, 0, KEYSIZE);
        	for (int i=0; (i<8); i++) p->key[i]=key[i];
		p->numpackets = 1;
		p->ipbytes = v;

        	//for (int i=0; (i<KEYSIZE); i++) printf("%02x ", key[i]);
        	//printf("\n");
		//printf("%c ADD key=/%s/\n", index, key);

	  	HASH_ADD(hh, IPFlow, key, KEYSIZE, p);
	}
}

/**********************************************************************************/

long ListIPFlow(char *log) {

	ipflow_t *i, *j;
	long num;
	FILE * fp;
	char src[INET_ADDRSTRLEN+1], dst[INET_ADDRSTRLEN+1];

	num=0;

	fp = fopen(log, "wt");

	HASH_ITER(hh, IPFlow, i, j) {

	  	inet_ntop(AF_INET, ((void *)(i->key)), src, INET_ADDRSTRLEN);
	  	inet_ntop(AF_INET, ((void *)(i->key + 4)), dst, INET_ADDRSTRLEN);

		fprintf(fp, "%s\t%s\t%li\t%li\n", src, dst, i->numpackets, i->ipbytes);
		HASH_DEL(IPFlow, i);
		free(i);
		num++;
	}

        fclose(fp);

	return num;
}

/**********************************************************************************/

#define DNS_DECODEBUF_64K	(65536uL / sizeof(dns_decoded_t))

int capture(pcap_t *handle, int numseconds) {

	struct pcap_pkthdr header;
	const u_char *packet;
        u_char *ip_header;
	struct timeval t0, t1;
        unsigned short protocol, srcport, dstport, length, total_length, iplen, tcplen;
	char src[INET_ADDRSTRLEN+1], dst[INET_ADDRSTRLEN+1];
	dns_decoded_t bufresult[DNS_DECODEBUF_64K];
	size_t bufsize;
	int rc;

	gettimeofday(&t0, 0);

        total=0;
        numpackets=0;
	IPFlow = NULL;

        while (1) {

	  packet = pcap_next(handle, &header);

	  //for (int i=0; (i<30); i++) printf(" %02x", packet[i]);
          //printf("\n"); 
	
	  total_length = (packet[20] << 8) | packet[21];
          iplen=(packet[18]&0x0f)<<2;
	  protocol = packet[27];

          total=total+header.len;

	  AddIPFlow((void *)(packet+30), header.len);

	  if (protocol==6) { // TCP

		srcport = (packet[38] << 8) | packet[39];
		dstport = (packet[40] << 8) | packet[41];
		tcplen = (packet[50]>>4)<<2;

		if ((srcport == 0x35)||(dstport == 0x35)) { // DNS (TCP)

		  dns++;

		  inet_ntop(AF_INET, ((void *)(packet + 30)), src, INET_ADDRSTRLEN);
		  inet_ntop(AF_INET, ((void *)(packet + 34)), dst, INET_ADDRSTRLEN);

		  length = total_length - tcplen - iplen;

		  printf("TCP dns=%ld dnserror=%ld iplen=%d tcplen=%d (%02x) length=%d\n", dns, dnserror, iplen, tcplen, packet[50], length);

		  if (length>0) {

		    bufsize = sizeof(bufresult);
		    rc = dns_decode(bufresult,&bufsize,(dns_packet_t *)(packet+40+tcplen),length);
		    if (rc != RCODE_OKAY) {

		      dnserror++;

		      fprintf(stderr,"TCP dns_decode() = (%d) %s\n",rc,dns_rcode_text(rc));
	  	      fprintf(stderr, "src=%s dst=%s proto=%d header.len=%d srcport=%d dstport=%d length=%d\n", src, dst, protocol, header.len, srcport, dstport, length);

          	      for (int i=0; (i<tcplen); i++) printf("%02x ", packet[i+38]);
	              printf("\n"); 

		      return EXIT_FAILURE;
		    }
                    else dns_print_result((dns_query_t *)bufresult);
		  }
		}
	  }
	  else if (protocol==17) { // UDP

		srcport = (packet[38] << 8) | packet[39];
		dstport = (packet[40] << 8) | packet[41];
		length  = (packet[42] << 8) | packet[43];

		if (((srcport == 0x35)||(dstport == 0x35))&&(length>=8)) { // DNS (UDP)

		  dns++;

		  //printf("UDP dns=%ld dnserror=%ld\n", dns, dnserror);

		  inet_ntop(AF_INET, ((void *)(packet + 30)), src, INET_ADDRSTRLEN);
		  inet_ntop(AF_INET, ((void *)(packet + 34)), dst, INET_ADDRSTRLEN);

		  printf("UDP dns=%ld dnserror=%ld iplen=%d length=%d\n", dns, dnserror, iplen, length);

                  //fprintf(stderr,"\n");

		  bufsize = sizeof(bufresult);
		  rc = dns_decode(bufresult,&bufsize,(dns_packet_t *)(packet+46),length-8);
		  if (rc != RCODE_OKAY) {

		    dnserror++;

		    fprintf(stderr,"UDP dns_decode() = (%d) %s\n",rc,dns_rcode_text(rc));
	  	    fprintf(stderr, "src=%s dst=%s proto=%d header.len=%d srcport=%d dstport=%d length=%d\n", src, dst, protocol, header.len, srcport, dstport, length);

		    //dns_dump_memory(stderr, packet+46, length-8, 0);

		    for (int i = 0; (i < length - 8); i++) fprintf(stderr,"%02x ", packet[i+46]);
                    fprintf(stderr,"\n");

		    return EXIT_FAILURE;
	 	  }

		  /*
	 	  dns_query_t   *result;
		  result = (dns_query_t *)bufresult;

		  printf("qdcount=%d\n", result->qdcount);
		  printf("ancount=%d\n", result->ancount);
		  printf("nscount=%d\n", result->nscount);
		  printf("arcount=%d\n", result->arcount);

                  for (int i=0; (i<result->qdcount); i++)
		    printf("\tQUESTION %d name=%s\n", i, result->questions[i].name);

                  for (int i=0; (i<result->ancount); i++)
		    printf("\tANSWER %d A name=%s address=%d\n", i, result->answers[i].a.name, result->answers[i].a.address);
		  */

		  //dns_print_result((dns_query_t *)bufresult);

		  //printf("---------------------------------------------\n");
		}

	  }

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
  long num;
  struct timeval t0, t1;
  //struct bpf_program fp;		/* The compiled filter */
  //char filter_exp[] = "";		/* The filter expression */
  time_t nowtime;
  struct tm *nowtm;
  char namelogfolder[1024], logfolder[1024], logfilename[1024];
  FILE *fp;

  dns=0;
  dnserror=0;

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
	strftime(namelogfolder, sizeof logfolder, "%Y%m%d/", nowtm);
	strftime(logfilename, sizeof logfilename, "%Y%m%dT%H%M%S.log", nowtm);

        sprintf(logfolder,"/data/stats/%s", namelogfolder);

        mkdir(logfolder, 0755);

        strcat(logfolder, logfilename);
        printf("logfolder=<%s>\n", logfolder);
	num=ListIPFlow(logfolder);

	printf("%s num=%ld\n", logfilename, num);

//	fp = fopen("/data/stats/analyze.log", "at");
//	fprintf(fp, "%s\tnum=%ld\tpackets=%ld\tbytes=%ld (%0.2f MB)\tseconds=%f\t%0.2f Mbps\n",
//		logfilename, num, numpackets, total, (float)total/1048576, seconds, total/seconds/131072);
//	fclose(fp);

  }

  pcap_close(handle);
}
/**********************************************************************************/
