#define _BSD_SOURCE 1

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
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
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

#define PACKAGE "ntraf"

/* XXX jrf - a lot of this stuff doesn't need to be global and can be 
             moved into the pcap handler */
/* TCP v4 header */
struct tcphdr4 {
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t res1:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;
	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t res1:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
	uint16_t th_win;
	uint16_t check;
	uint16_t urg_ptr;
};

typedef struct ether_header eth_hdr;	/* Ethernet header */
typedef struct ip ip4ip;	/* IP data       */
typedef struct tcphdr4 tcp_hdr;	/* TCP header      */

char *pcap_dev;			/* Pcap device file descriptor */
short int proto_version;

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
 * usage - Simple usage message 
 */
static void usage()
{
	printf(PACKAGE " [option][arguments]\n"
	       PACKAGE
	       " "
	       "[-i <interface>][-p <number>][-u]\n"
	       "Options:\n"
	       " -i <dev>   Specify the interface to watch\n"
	       " -p <int>   Exit after analyzing int polls\n"
	       " -u         Display help\n");
}

/*
 * pcap_handler4: This is the ipv4 pcap looper. It is like most pcap callbacks
 *         except it does a lot of printing.
 * requires: all of the standard pcap_loop data
 */
static void pcap_handler4(u_char * args, const struct pcap_pkthdr *header,
			  const u_char * packet)
{
	eth_hdr *ethernet;	/* The ethernet header    */
	ip4ip *ip;		/* The IP header          */
	u_int id;		/* Host id                */
	u_int i;		/* Counter                */
	const struct tcphdr4 *tcp;	/* TCP Header             */
	int len;		/* real length            */
	u_int off, version;	/* offset, version        */
	u_int length = header->len;	/* True header len        */
	char *t;		/* Timestamp intermediary */
	time_t result;		/* Time result (as read)  */
	struct udphdr *udp;	/* udp header info */
	struct icmphdr *icmp;	/* icmp hdr info */

	t = "";			/* empty */

	/* Extract ethernet, ip and tcp headers */
	ethernet = (eth_hdr *) (packet);	/* Pointer to ethernet header */
	ip = (ip4ip *) (packet + sizeof(eth_hdr));
	tcp = (struct tcphdr4 *)(packet +
				 sizeof(struct ether_header) +
				 sizeof(struct ip));

	if (ip->ip_v != 4)
		return;		/* don't try to do ipv6 */
	result = time(NULL);	/* Setup the timestamp */
	t = asctime(localtime(&result));
	t[strlen(t) - 1] = ' ';
	t[strlen(t)] = 0;
	len = ntohs(ip->ip_len);
	off = ntohs(ip->ip_off);
	/* XXX jrf Need to arrange this with less duplication */
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		/* this is just real fun - inet_ntoa mixed with fprintf screws up */
		/* so the WAR is to mix up the print types.                       */
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		fprintf(stdout, "%u ", tcp->th_sport);
		printf("-> %s:", inet_ntoa(ip->ip_dst));
		fprintf(stdout, "%u ", tcp->th_dport);
		fprintf(stdout,
			"tcp len %u off %u ttl %u prot %u cksum %u seq %u ack %u win %u\n",
			len, off, ip->ip_ttl, ip->ip_p,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr *)(packet + sizeof(struct ip));
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		printf("%u", udp->uh_sport);
		printf("-> %s:", inet_ntoa(ip->ip_dst));
		printf("%u ", udp->uh_dport);
		fprintf(stdout,
			"udp len %u sum %u off %u ttl %u prot %u cksum %u seq %u ack %u win %u\n",
			udp->uh_ulen, udp->uh_sum, off, ip->ip_ttl, ip->ip_p,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
		break;
	case IPPROTO_ICMP:
		icmp = (struct icmphdr *)(packet + sizeof(struct ip));
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		printf("-> %s", inet_ntoa(ip->ip_dst));
/* XXX jrf: this mess sucks */
#if DARWIN || NETBSD
		fprintf(stdout,
			"icmp len %u off %u ttl %u prot %u cksum %u seq %u ack %u win %u\n",
			len, off, ip->ip_ttl, ip->ip_p,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
#else
		fprintf(stdout,
			"icmp type %u code %u off %u ttl %u prot %u cksum %u seq %u ack %u win %u\n",
#if FREEBSD
			icmp->icmp_type, icmp->icmp_code,
#else
			icmp->type, icmp->code,
#endif				/* NET and FREEBSD */
			off, ip->ip_ttl, ip->ip_p,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
#endif				/* DARWIN */
		break;
	default:
		printf("%s: %s:", t, inet_ntoa(ip->ip_src));
		fprintf(stdout, "%u ", tcp->th_sport);
		printf("-> %s:", inet_ntoa(ip->ip_dst));
		fprintf(stdout, "%u ", tcp->th_dport);
		fprintf(stdout,
			"??? len %u off %u ttl %u prot %u cksum %u seq %u ack %u win %u\n",
			len, off, ip->ip_ttl, ip->ip_p,
			ip->ip_sum, tcp->th_seq, tcp->th_ack, tcp->th_win);
		break;
	}
}

int main(int argc, char *argv[])
{
	struct bpf_program program;	/* BPF filter program   */
	register int c;		/* Temporary variable   */
	char errbuf[PCAP_ERRBUF_SIZE];	/* pcap error buffer    */
	char *filter = NULL;	/* pcap filter          */
	pcap_t *handle;		/* pcap handle          */
	bpf_u_int32 mask;	/* our netmask          */
	bpf_u_int32 net;	/* our IP adx           */
	uint32_t npolls = -1;	/* Number of pcap polls */

	proto_version = 4;	/* Default ipv4 */

	while ((c = getopt(argc, argv, "6i:p:u")) != -1) {
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

	/* Strip off any none getopt arguments for pcap filter */
	if (!filter)
		filter = copy_argv(&argv[optind]);

	/* Initialize the interface to listen on */
	if ((!pcap_dev)
	    && ((pcap_dev = pcap_lookupdev(errbuf)) == NULL)) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	if ((handle = pcap_open_live(pcap_dev, 68, 0, 0, errbuf)) == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}

	pcap_lookupnet(pcap_dev, &net, &mask, errbuf);	/* Get netinfo */

	if (filter) {
		if (pcap_compile(handle, &program, filter, 0, net) == -1) {
			fprintf(stderr, "Error - `pcap_compile()'\n");
			return EXIT_FAILURE;
		}

		if (pcap_setfilter(handle, &program) == -1) {
			fprintf(stderr, "Error - `pcap_setfilter()'\n");
			return EXIT_FAILURE;
		}

		pcap_freecode(&program);
	}

	/* Main loop */
	printf("Starting capturing engine on %s...\n", pcap_dev);
	if (proto_version == 4)
		pcap_loop(handle, npolls, pcap_handler4, NULL);
	else
		printf("IPV6 Only not yet supported\n");

	/* Exit program */
	printf("Closing capturing engine...\n");
	pcap_close(handle);

	return EXIT_SUCCESS;
}
