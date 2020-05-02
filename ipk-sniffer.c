#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <getopt.h>

bool just_tcp = false;				/* just tcp packets flag */
bool just_udp = false;				/* just udp packets flag */
int num_packets = 1;				/* number of packets -> (it can be changed by argument) */

bool process_tcp_flag = false;
bool process_udp_flag = false;

#define BUFFER_SIZE 1518			/* define buffer_size -> (maximum btes per packet) */
#define ETHERNET_SIZE 14			/* ethernet header size */
#define ETHERNET_ADDR_LEN 6			/* ethernet address size */
#define FAIL -1
#define SUCCESS 0

/* ERROR HANDLE */
#define EXIT_SUCCESS 0				/* EXIT program success */
#define EXIT_ERROR 1				/* EXIT program with error */

/* error flags */
bool error_lookupnet = true;
bool error_compile = true;
bool error_open_live = true;
bool error_set_filter = true;

void define_protocol(u_char* arg, const struct pcap_pkthdr* header, const u_char* packet);

int main(int argc, char** argv) {	
	char* DEVICE = NULL;                         /* initialize DEVICE */
	pcap_if_t* interfaces, * temporary;          /* initialize INTERFACE */
	char error_buffer[PCAP_ERRBUF_SIZE];         /* initialize BUFFER ERROR */
	pcap_t* HANDLE;	                             /* initialize HANDLE */
	char define_port[] = "ip", define_port2[4];	 /* define base port -> (it can be changed by argument) */
	bool port = false;                           /* initialize port flag -> (specific port) */
	
	if (argv[1] == '--help') {
		printf("Packet Sniffer \n");
		printf("Sniffing UDP a TCP paketov");
		printf("Pre spustenie programu napiste ./ipk-sniffer \"+ argumenty\" \n");
		printf("ARGUMENTY: -i [interfaces] -n [number_of_packets (int)] \n");
		printf("ARGUMENTY: -p [port] -u/-t [search only tcp/udp packets]");
		exit(EXIT_SUCCESS);
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-i") == SUCCESS) {
			DEVICE = argv[i+1];
			i++;
		}
		else if (strcmp(argv[i], "-n") == SUCCESS) {
			num_packets = atoi(argv[i+1]);
			i++;
		}
		else if (strcmp(argv[i], "-p") == SUCCESS) {
			strcpy(define_port2, argv[i+1]);
			i++;
			port = true;
		}
		else if (strcmp(argv[i], "-u") == SUCCESS || strcmp(*argv[i], "-udp") == SUCCESS) {
			// -> filter just UDP packets
			just_udp = true;
		}
		else if (strcmp(argv[i], "-t") == SUCCESS || strcmp(*argv[i], "-tcp") == SUCCESS) {
			// -> filter just TCP packets
			just_tcp = true;
		}
		else {
			fprintf(stderr, "Bad arguments");
			exit(EXIT_ERROR);
		}
	}

	char define_port3[10] = "port ";

	/* if port flag is active, set filter on specific port otherwise filter all ports */
	if (port == true) { strcat(define_port3, define_port2); }
	else { strcpy(define_port3, define_port); }

	/* initialize netmask */
	bpf_u_int32 MASK;										
	bpf_u_int32 NET;
	struct bpf_program compiled_filter;		/* initilize struct for compiled version of filter */

	int i;
	/* if interface is not defined, show all available interfaces */
	if (DEVICE == NULL) {
		pcap_findalldevs(&interfaces, error_buffer);
		printf("Dostupne interfaci \n");
		for (temporary = interfaces; temporary; temporary = temporary->next) {
			printf("%d : %s \n", i++, temporary->name);
		}
		exit(EXIT_SUCCESS);
	}
	else {

		/* find the network address and netmask -> ERROR if fail */
		if (pcap_lookupnet(DEVICE, &NET, &MASK, error_buffer) != FAIL)
			error_lookupnet = false;
		/* get handle to device */
		HANDLE = pcap_open_live(DEVICE, BUFFER_SIZE, 1, 0, error_buffer);
		if (HANDLE != NULL)
			error_open_live = false;
		/* the compile the program (expr) */
		if (pcap_compile(HANDLE, &compiled_filter, define_port3, 0, NET) != FAIL)
			error_compile = false;
		/* set specific filter to compiled version */
		if (pcap_setfilter(HANDLE, &compiled_filter) != FAIL)
			error_set_filter = false;

		if (error_set_filter || error_compile || error_open_live || error_lookupnet) {
			if (error_lookupnet)
				fprintf(stderr, "Error: Cannot get netmask for DEVICE \n");
			if (error_open_live)
				fprintf(stderr, "Error: Cannot open device \n");
			if (error_compile)
				fprintf(stderr, "Error: Cannot parse filter \n");
			if (error_set_filter)
				fprintf(stderr, "Error: Cannot install filter \n");
			exit(EXIT_ERROR);
		}

		/* process all packets */
		pcap_loop(HANDLE, -1, define_protocol, NULL);
		pcap_freecode(&compiled_filter);
		pcap_close(HANDLE);
	} 
	exit(EXIT_SUCCESS);
}

void print_time() {
	time_t rawtime;	/* initialize time */
	struct tm* info;/* initialize time structure */
	time(&rawtime);							/* return a time */
	info = localtime(&rawtime);				/* assign time to structure */
	printf("%02d:%02d:%02d ", info->tm_hour, info->tm_min, info->tm_sec);
}

void process_packet(const unsigned char* packet, const struct iphdr* ip_head, int size);

void define_protocol(u_char* arg, const struct pcap_pkthdr* header, const u_char* packet) {
	
	size_t size = header->len;				/* header length */
	struct timeval temp = header->ts;		/* temporary */
	struct iphdr* ip = (struct iphdr*)(packet + ETHERNET_SIZE);

	/* print actual time */
	print_time();

	/* DEFINE PROTOCOL */
	switch (ip->protocol) {
		case IPPROTO_TCP:
			if ((just_tcp == true && just_udp == false) || (just_tcp && just_udp) || (!just_tcp && !just_udp)) {
				num_packets--;
				process_tcp_flag = true;
				process_packet(packet, ip, size);			/* process tcp packet */
				break;
			}
		case IPPROTO_UDP:
			if ((just_udp == true && just_tcp == false) || (just_tcp && just_udp) || (!just_tcp && !just_udp)) {
				num_packets--;
				process_udp_flag = true;
				process_packet(packet, ip, size);			/* process udp packet */
				break;
			}
		default:
			break;
	}

	process_tcp_flag = false;
	process_udp_flag = false;

	if (num_packets == 0) {
		exit(EXIT_SUCCESS);
	}
}

void print_hexadecimal(const u_char* info, int offset, int len) {
	int i;
	int gap;
	const u_char* ch;

	/* HEXADECIMAL OFFSET <0x0000>*/
	printf("0x%04d ", offset);

	//-----------------------------------------------------------------------------------------------------------------//
	/* Pri pisani tejto casti som sa inspiroval autorom */
	/* <(c) 2010-2020 The Tcpdump Group. Designed by Luis <Martin Garcia>; based on a template by Free CSS Templates.> */
	
	/* Informations in hexadecimal */
	ch = info;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	else if (len < 16) {
		gap = 16 - len;
			printf("  ");
	}
	printf(" ");

	/* ascii print printable characters, dots if cant print */
	ch = info;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	printf("\n");
	return;
	//-----------------------------------------------------------------------------------------------------------------//
}

void print_packet(const u_char* info, int len) {
	int line_len;
	int current_line_len = len;
	int offset = 0;
	
	if (len <= 0)
		return;
	else if (len <= 16) {
		print_hexadecimal(info, offset, len);
		return;
	}

	for (;;) {
		line_len = 16 % len;
		print_hexadecimal(info, offset, line_len);
		current_line_len = current_line_len - line_len;
		info = info + line_len;
		offset = offset + 10;

		if (current_line_len <= 16) {
			print_hexadecimal(info, offset, current_line_len);
			break;
		}
	}
}

void process_packet(const unsigned char* packet, const struct iphdr* ip_head, int size) {
	
	struct tcphdr* header1;
	struct udphdr* header2;
	int switcher = 0;

	if (process_udp_flag == true) {
		/* Define TCP header offset */
		header1 = (struct tcphdr*)(packet + ip_head->ihl * 4 + ETHERNET_SIZE);
		switcher = 1;
	}
	else if (process_tcp_flag == true) {
		/* Define UDP header offset */
		header2 = (struct udphdr*)(packet + ip_head->ihl * 4 + ETHERNET_SIZE);
		switcher = 2;
	}
	else {
		fprintf(stderr, "Error: Protocol is not defined");
		exit(EXIT_ERROR);
	}
	
	/* print first line <time src address : port > dst address : port> */
	struct sockaddr_in src;
	src.sin_addr.s_addr = ip_head->saddr;			/* source address */
	struct sockaddr_in dest;
	dest.sin_addr.s_addr = ip_head->daddr;			/* destination address */

	if (switcher == 1) {
		printf("%s : %u > ", inet_ntoa(src.sin_addr), header1->th_sport);
		printf("%s : %u ", inet_ntoa(dest.sin_addr), header1->th_dport);
	}
	else if (switcher == 2) {
		printf("%s : %u > ", inet_ntoa(src.sin_addr), header2->uh_sport);
		printf("%s : %u", inet_ntoa(dest.sin_addr), header2->uh_dport);
	}
	printf("\n\n");
	switcher = 0;

	/* PRINT INFORMATION ABOUT PACKET */
	print_packet(packet, size);
}
