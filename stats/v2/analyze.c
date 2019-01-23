#include <pcap.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#include "uthash.h"

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

int capture(pcap_t *handle, int numseconds) {

	//bpf_u_int32 mask;
	//bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;
        u_char *ip_header;
        int total_length;
	struct timeval t0, t1;
        unsigned short protocol;
	//char src[INET_ADDRSTRLEN+1], dst[INET_ADDRSTRLEN+1];

	gettimeofday(&t0, 0);

        total=0;
        numpackets=0;
	IPFlow = NULL;

        while (1) {

	  packet = pcap_next(handle, &header);

          //printf("len=%d\n", header.len);

	  //for (int i=0; (i<30); i++) printf(" %02x", packet[i]);
          //printf("\n"); 
	
	  //total_length = (packet[20] << 8) | packet[21];
	  protocol = packet[27];

	  //inet_ntop(AF_INET, ((void *)(packet + 30)), src, INET_ADDRSTRLEN);
	  //inet_ntop(AF_INET, ((void *)(packet + 34)), dst, INET_ADDRSTRLEN);

	  //printf("src=%s dst=%s proto=%d header.len=%d\n", src, dst, protocol, header.len);

          total=total+header.len;

	  AddIPFlow((void *)(packet+30), header.len);

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
  //char namelogfolder[1024];
  char logfolder[1024], logfilename[1024];
  FILE *fp;

  printf("pcap_open_live %s\n", dev);
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

  printf("Enter loop\n");

  while (1) {

	printf("capture\n");
	gettimeofday(&t0, 0);
	capture(handle, 5);
	gettimeofday(&t1, 0);
	printf("capture done\n");

	nowtime = t0.tv_sec;
	nowtm = localtime(&nowtime);
	//strftime(namelogfolder, sizeof logfolder, "%Y%m%d/", nowtm);
	strftime(logfilename, sizeof logfilename, "%Y%m%dT%H%M%S.log", nowtm);

        //sprintf(logfolder,"/stats/%s", namelogfolder);
        strcpy(logfolder, "/stats/");

        //mkdir(logfolder, 0755);

        strcat(logfolder, logfilename);
        printf("logfolder=<%s>\n", logfolder);
	num=ListIPFlow(logfolder);

	printf("%s num=%ld\n", logfilename, num);

	fp = fopen("/stats/analyze.log", "at");
        fprintf(fp, "%s\tnum=%ld\tpackets=%ld\tbytes=%ld (%0.2f MB)\tseconds=%f\t%0.2f Mbps\n",
		logfilename, num, numpackets, total, (float)total/1048576, seconds, total/seconds/131072);
        fclose(fp);
  }

  pcap_close(handle);
}
/**********************************************************************************/
