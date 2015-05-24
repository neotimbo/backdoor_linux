/*---------------------------------------------------------------------------------------
--	SOURCE FILE:		pkt_cap2.c -   A simple packet capture program
--
--	FUNCTIONS:		libpcap - packet filtering library based on the BSD packet
--				 filter (BPF)
--
--	DATE:			April 23, 2006
--
--	REVISIONS:		(Date and nic_description)
--			
--				March 29, 2011
--
--				Fixed memory leak - no more malloc
--				Got rid of unused variables
--
--	DESIGNERS:		Based on the code by Martin Casado & Richard Stevens
--				Modified & redesigned: Aman Abdulla: April 23, 2006
--
--	PROGRAMMER:		Aman Abdulla
--
--	NOTES:
--	The program extends the previous example by using a callback function to capture 
-- 	a specified number of packets using the pcap_loop function
--
--	To compile:
--			gcc -Wall -o pkt_cap2 pkt_cap2.c -lpcap
--	Run:
--			./pkt_cap2 5 
-----------------------------------------------------------------------------------------*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 

// Function Prototypes
void pkt_callback (u_char*, const struct pcap_pkthdr*, const u_char*);

int main (int argc, char **argv)
{ 
	char *nic_dev; 
    	char errbuf[PCAP_ERRBUF_SIZE];
   	pcap_t* nic_descr;
    	
    	if(argc != 2)
	{ 
		fprintf(stdout,"Usage: %s numpackets\n",argv[0]);
		return 0;
	}

    	// find the first NIC that is up and sniff packets from it
    	nic_dev = pcap_lookupdev (errbuf);
    	if (nic_dev == NULL)
    	{ 
		printf("%s\n",errbuf); 
		exit(1); 
	}
   
			
	// open device for reading 
    		nic_descr = pcap_open_live (nic_dev, BUFSIZ, 0, -1, errbuf);
    	if (nic_descr == NULL)
    	{ 
			printf("pcap_open_live(): %s\n",errbuf); 
			exit(1); 
	}

    	// Call pcap_loop(..) and pass in the callback function 
       	pcap_loop(nic_descr, atoi(argv[1]), pkt_callback, NULL);

    	fprintf(stdout,"\nCaptured %d packets.\n", atoi(argv[1]));
    	return 0;
}


// This is the callback function that is passed to pcap_loop(..) and called each time 
// a packet is received                                                    */

void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
		static int count = 1;
    	fprintf(stdout,"%d.. ",count);
    	fflush(stdout);
    	count++;
}