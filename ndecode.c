#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in_systm.h>
#include <pcap.h>
#ifndef NETBSD
#include <net/ethernet.h>
#endif
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <math.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <semaphore.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/udp.h>
#include <net/if.h>
#ifdef NETBSD
#include <net/if_ether.h>
#endif
#include <sys/ioctl.h>
#include <time.h>

#define PACKAGE "ndecode"

#define MAXBYTES2CAPTURE 2048

/* simple usage message */
static void usage()
{
	printf(PACKAGE " [option][arguments]\n"
	       PACKAGE
	       " "
	       "[-i <interface>][-p <number][-u]\n"
	       "Options:\n"
	       " -i <dev>   Specify the interface to watch\n"
	       " -p <int>   Exit after analyzing int polls\n"
	       " -u         Display help\n");
}

/*
 * copy_argv: Copy off an argument vector
 *         except it does a lot of printing.
 * requires: argvector
 */
static char *copy_argv(char **argv)
{
	char **p;
	u_int len = 0;
	char *buf;
	char *src, *dst;

	p = argv;

	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL) {
		fprintf(stdout, "copy_argv: malloc");
		exit(EXIT_FAILURE);
	}

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0') ;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}

/*
 * Call libpcap and decode payload data.
 */
static void payload_print(u_char * arg, const struct pcap_pkthdr *header,
			  const u_char * packet)
{
	int i = 0, *counter = (int *)arg;

	printf("Packet RECV Size: %d Payload:\n", header->len);
	for (i = 0; i < header->len; i++) {
		if (isprint(packet[i]))
			printf("%c ", packet[i]);
		else
			printf(". ");

		if ((i % 16 == 0 && i != 0) || i == header->len - 1)
			printf("\n");
	}

	return;
}

int main(int argc, char *argv[])
{
	struct bpf_program program;
	int i = 0;
	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *filter = NULL;
	char *pcap_dev = NULL;
	int c;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	uint32_t npolls = -1;

	while ((c = getopt(argc, argv, "i:p:u")) != -1) {
		switch (c) {
		case 'i':
			pcap_dev = optarg;
			break;
		case 'p':
			if (optarg != NULL && isdigit(*optarg)) {
				npolls = atol(optarg);
				if (npolls < 0) {
					fprintf(stderr,
						"Packets must be > than 0\n");
					return EXIT_FAILURE;
				}
			} else {
				fprintf(stderr, "Invalid packet number\n");
				return EXIT_FAILURE;
			}
			break;
		case 'u':
			usage();
			return EXIT_SUCCESS;
			break;
		default:
			usage();
			return EXIT_FAILURE;
			break;
		}
	}

	/* Got root? */
	if (getuid()) {
		fprintf(stderr, "Must be root user.\n");
		return EXIT_FAILURE;
	}

	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	/* Strip off any none getopt arguments for pcap filter */
	if (!filter)
		filter = copy_argv(&argv[optind]);

	/* Initialize the interface to listen on */
	if ((!pcap_dev)
	    && ((pcap_dev = pcap_lookupdev(errbuf)) == NULL)) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	if ((descr = pcap_open_live(pcap_dev, 68, 0, 0, errbuf)) == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	pcap_lookupnet(pcap_dev, &net, &mask, errbuf);	/* Get netinfo */
	if (filter) {
		if (pcap_compile(descr, &program, filter, 0, net) == -1) {
			fprintf(stderr, "Error - `pcap_compile()'\n");
			return EXIT_FAILURE;
		}

		if (pcap_setfilter(descr, &program) == -1) {
			fprintf(stderr, "Error - `pcap_setfilter()'\n");
			return EXIT_FAILURE;
		}

		pcap_freecode(&program);
	}

	pcap_loop(descr, npolls, payload_print, NULL);
	/* Exit program */
	printf("Closing capturing engine...\n");
	pcap_close(descr);

	return 0;
}
