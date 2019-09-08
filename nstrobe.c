#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* all of these are here so ip4.h can be used by other programs */
#define DEFAULT_START_PORT 1	/* default starting port to scan */
#define DEFAULT_END_PORT 1024	/* default ending port to scan */
#define DEFAULT_INET_TIMEOUT 2	/* default AF_INET connect timeout */
#define PACKAGE "nstrobe"	/* binary exec name */

struct nstrobe_data {
	u_short port_start;	/* Starting port */
	u_short port_end;	/* Last port */
	int subnet_start;	/* Subnet start */
	int subnet_end;		/* Subnet end, equals start if none specified */
	short int cflag;	/* Full TCP Connect for every scan flag */
	short int iflag;	/* Is alive check only flag */
	short int xflag;	/* Do ports beyond 1024 flag (or eXtra) */
	short int inet_timeo;	/* Connect timeout in seconds */
	short int inet_utimeo;	/* Connect timeout useconds value for the anal */
	char *start_vector;	/* the starting subnet address vector pointer */
	char addr[1024];	/* The raw start address from stdin */
	char *portstring;	/* If only portchecking use this */
	char *socktype;		/* The socket type */
} scandata;			/* Our base struct name */

/* we use "sd" with the idea that we will be protocol version agnostic */
struct nstrobe_data *sd = &scandata;	/* the quick way to get at it... */

/* simple helper to initialize pertinent scandata */
static void init_scandata(void)
{
	sd->port_start = DEFAULT_START_PORT;
	sd->port_end = DEFAULT_END_PORT;
	sd->subnet_start = 0;
	sd->subnet_end = 0;
	sd->cflag = 0;
	sd->iflag = 0;
	sd->xflag = 0;
	sd->inet_timeo = DEFAULT_INET_TIMEOUT;	/* Set connect timeout in secs */
	sd->inet_utimeo = 0;	/* default usec for timer */
	sd->socktype = "STREAM";
}

/* print the current time along with a message */
static void printime(char *msg)
{
	char buffer[256];
	time_t curtime;
	struct tm *loctime;

	curtime = time(NULL);
	loctime = localtime(&curtime);
	printf("%s", msg);
	fputs(asctime(loctime), stdout);
}

/* ye olde usage print */
static void usage(void)
{
	printf(PACKAGE " [[option][arguments]][ipadxn-N|host]\n"
	       PACKAGE " [-c][-p n-N][-t n.n][-P][-u][-v][-x]\n"
	       "OPTIONS:\n"
	       " -6        Specify ipv6\n"
	       " -c        Connect for each port(not default, slower)\n"
	       " -d        Set the socket to datagram instead of stream\n"
	       " -P        Is up only check (Pinglike only check)\n"
	       " -p n[-N]  Scan port number n or a range of n-N\n"
	       "           Defaults are: %i-%i\n"
	       " -t n[.n]  Set the default scan timeout to SECONDS.USECONDS\n"
	       "           Defaults are: %i.0\n"
	       " -x        Xtra thorough scan (slower non-strobe scan)\n"
	       " -u        Print help/usage message\n"
	       " -v        Be verbose\n"
	       "EXAMPLES:\n"
	       "  " PACKAGE " -v -p 22-80 192.168.1.10\n"
	       "  " PACKAGE " -t 5 -p 22-80 192.168.1.2-254\n"
	       "  " PACKAGE " -t 2.050 -v -x  somehost.domain.net\n",
	       DEFAULT_START_PORT, DEFAULT_END_PORT, DEFAULT_INET_TIMEOUT);
}

/* capture any strange socket errors here */
static void sockerr(int res)
{
	fprintf(stderr, "Connect error: ");

	switch (res) {
	case EADDRINUSE:
		fprintf(stderr, "EADDRINUSE\n");
		break;
	case EADDRNOTAVAIL:
		fprintf(stderr, "EADDRNOTAVAIL\n");
		break;
	case EALREADY:
		fprintf(stderr, "EALREADY\n");
		break;
	case ECONNREFUSED:
		fprintf(stderr, "ECONNREFUSED\n");
		break;
	case EHOSTUNREACH:
		fprintf(stderr, "EHOSTUNREACH\n");
		break;
	case ENETDOWN:
		fprintf(stderr, "ENETDOWN\n");
		break;
	case ENETUNREACH:
		fprintf(stderr, "ENETUNREACH\n");
		break;
	case ETIMEDOUT:
		fprintf(stderr, "ETIMEDOUT\n");
		break;
	default:
		fprintf(stderr, "Host timed out (exists?)\n");
		break;
	}
}

/* up/down connect test; we do this once/host unless specified otherwise */
static int isalive(struct sockaddr_in scanaddr,
		   short int inet_timeo, short int inet_utimeo)
{
	short int sock;		/* our main socket */
	long arg;		/* for non-block */
	fd_set wset;		/* file handle for bloc mode */
	struct timeval timeout;	/* timeout struct for connect() */

	sock = -1;

	if (sd->socktype == "STREAM")
		sock = socket(AF_INET, SOCK_STREAM, 0);
	else
		sock = socket(AF_INET, SOCK_DGRAM, 0);

	if ((arg = fcntl(sock, F_GETFL, NULL)) < 0) {
		fprintf(stderr,
			"Error fcntl(..., F_GETFL) (%s)\n", strerror(errno));
		return 1;
	}

	arg |= O_NONBLOCK;
	if (fcntl(sock, F_SETFL, arg) < 0) {
		fprintf(stderr,
			"Error fcntl(..., F_SETFL)  (%s)\n", strerror(errno));
		return 1;
	}

	/* 
	 * set result stat then try a select if it can take
	 * awhile. This is dirty but works 
	 */
	int res = connect(sock, (struct sockaddr *)&scanaddr, sizeof(scanaddr));
	if (res < 0) {
		if (errno == EINPROGRESS) {
			timeout.tv_sec = inet_timeo;
			timeout.tv_usec = inet_utimeo;
			FD_ZERO(&wset);
			FD_SET(sock, &wset);
			int rc = select(sock + 1, NULL,
					&wset, NULL, &timeout);

			/* This works great on dead hosts */
			if (rc == 0 && errno != EINTR) {
				sockerr(res);
				close(sock);
				return 1;
			}
		}
	}
	close(sock);
	return 0;
}

/* XXX jrf: Helper function for scanhost, all this does is save 
            nesting space; I'd prefer to have it inline if there 
            is a cleaner way to do so (no that doesn't mean shorter tabs :) */
static void printport(u_short current_port, struct servent *service_info)
{
	if (sd->xflag) {
		service_info = getservbyport(htons
					     (sd->port_start + current_port),
					     "tcp");
		if (!service_info) {
			printf("%-5d unknown\n", sd->port_start + current_port);
		} else {
			printf("%-5d %-30s\n",
			       sd->port_start + current_port,
			       service_info->s_name);
		}
	} else {
		printf("%-5d %-30s\n",
		       ntohs(service_info->s_port), service_info->s_name);
	}
}

/* short circuit the other jive if we are doing ipv6 */
static void quickport6(char *addr, char *portstring)
{
	struct addrinfo *res;
	struct addrinfo hints;
	register short int isalive6;

	isalive6 = 0;

	memset(&hints, '\0', sizeof(hints));
	if (sd->socktype == "STREAM")
		hints.ai_socktype = SOCK_STREAM;
	else
		hints.ai_socktype = SOCK_DGRAM;

#ifndef NETBSD
	hints.ai_flags = AI_ADDRCONFIG;
#endif

	int e = getaddrinfo(addr, portstring, &hints, &res);
	if (e != 0) {
		printf("Error: %s\n", gai_strerror(e));
		exit(EXIT_FAILURE);
	}

	int sock = -1;
	struct addrinfo *r = res;
	for (; r != NULL; r = r->ai_next) {
		sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
		if (sock != -1 && connect(sock, r->ai_addr, r->ai_addrlen) == 0) {
			printf("Port %s open on %s\n", portstring, addr);
			++isalive6;
			break;
		}
	}

	if (sock != -1)
		close(sock);

	freeaddrinfo(res);
	if (sock != -1)
		if (!isalive6) {
			printf
			    ("Was able to resolve %s but could not connect to port %s\n",
			     addr, portstring);
			close(sock);
			exit(EXIT_FAILURE);
		}

	close(sock);
	exit(EXIT_SUCCESS);
}

/* Perform a single host scan: would like this to be a module someday */
static void scanhost(struct sockaddr_in scanaddr)
{
	u_short current_port;	/* the current port being scanned */
	short int sock;		/* our main socket */
	short int hostalive;	/* node is alive - used for skipping */
	register u_int finished;	/* 1 when deep scanning is finished */
	register u_int goodproto;	/* 1 when protocol mapped to service */
	struct servent *service_info;	/* service information structure */

	service_info = getservent();
	current_port = 0;
	finished = 0;
	goodproto = 0;
	hostalive = 0;
	sock = -1;

	if (!sd->xflag)
		setservent(1);	/* not thorough get /etc/services handle */
	while (((sd->port_start + current_port) <= sd->port_end) || !finished) {
		scanaddr.sin_family = AF_INET;
		if (sd->socktype == "STREAM")
			sock = socket(AF_INET, SOCK_STREAM, 0);
		else
			sock = socket(AF_INET, SOCK_DGRAM, 0);

		if (sock == -1) {
			fprintf(stderr, "Error  assigning master socket\n");
			exit(EXIT_FAILURE);
		}

		/* not thorough then strobe using known services */
		if (!sd->xflag) {
			while (!goodproto) {
				service_info = getservent();
				if (!service_info)
					break;
				if (!strcmp(service_info->s_proto, "tcp")
				    && (ntohs(service_info->s_port) <=
					sd->port_end)
				    && (ntohs(service_info->s_port) >=
					sd->port_start)) {
					goodproto = 1;
					break;
				}
			}

			if (!goodproto)
				break;

			if (!service_info) {
				finished = 1;
				break;
			}

			if (goodproto)
				scanaddr.sin_port = service_info->s_port;
			goodproto = 0;
		} else
			scanaddr.sin_port =
			    htons(sd->port_start + current_port);

		/* do a basic connect/select test before the real check */
		if (!finished) {
			/* If we have not checked already see if it is alive */
			if (hostalive == 0)
				if (isalive(scanaddr,
					    sd->inet_timeo,
					    sd->inet_utimeo) > 0)
					return;
			if (!sd->cflag)
				hostalive = 1;

			if (sd->iflag > 0) {
				printf(" is alive\n");
				close(sock);
				break;
			}

			if (connect
			    (sock, (struct sockaddr *)&scanaddr,
			     sizeof(scanaddr)) == 0) {
				printport(current_port, service_info);
			} else if (errno == 113) {	/* Crap */
				fprintf(stderr, "No route to host\n");
				finished = 1;
				break;
			}
		}

		close(sock);
		current_port++;
		if (sd->port_start + current_port >= sd->port_end)
			finished = 1;
	}

	if (!sd->xflag)
		endservent();
}

/* 
 * The next set of functions are all helpers for the main program; it may
 * seem like overkill but the upside is each one reduces the possible size
 * of memory used which is always a plus. It also allows for simple
 * manipulation of the parsers themselves.
 */

/* this is a helper for main() to parse out 
   -p n-N and fill in the scandata structure 
   via the sd-> pointer */
static void portparse(char *argv_port)
{
	char *token;

	token = strtok(argv_port, "-");
	if (!token) {
		fprintf(stderr, "Error! No port specified\n");
		usage();
		exit(EXIT_FAILURE);
	} else {
		sd->port_start = atoi(token);
		token = strtok(NULL, "-");
		if (token)
			sd->port_end = atoi(token);
		else {
			sd->port_end = sd->port_start;
			sd->portstring = argv_port;
		}
	}

	if (sd->port_start <= 0) {
		fprintf(stderr, "Starting port is a negative number\n");
		exit(EXIT_FAILURE);
	} else if (sd->port_start > sd->port_end) {
		fprintf(stderr, "Starting port is greater than end port\n");
		exit(EXIT_FAILURE);
	} else if (sd->port_end >= 65535) {
		fprintf(stderr, "End port is past 65534\n");
		exit(EXIT_FAILURE);
	}

}

/* this is a helper for main() to parse 
   out -t n.n and fill in the scandata structure via the 
   sd-> pointer */
static void timerparse(char *argv_timer)
{
	char *token;

	token = strtok(argv_timer, ".");
	if (!token) {
		fprintf(stderr, "Error! No time specified\n");
		usage();
		exit(EXIT_FAILURE);
	} else {
		sd->inet_timeo = atoi(token);
		token = strtok(NULL, ".'");
		if (token)
			sd->inet_utimeo = atoi(token);
	}

}

/* this is a helper for main() to parse out 
   x.x.x.n-N and fill in the scandata structure 
   via the sd-> pointer */
static int subnetparse(char *argv_cp)
{
	int y;
	char *end_vp;		/* pointer for the ending subnet address */
	char *tokenizer;	/* tmp pointer for tokenizing */
	char start_addr[1023];	/* char array for the address */

	/* XXX-bug: x.x.x.-n-N will cause a segv */
	sd->start_vector = strtok(argv_cp, "-");
	end_vp = strtok(NULL, "-");

	/* If there is not a - then make subnet end same as the start */
	if (end_vp) {
		sd->subnet_end = atoi(end_vp);
		strncpy(start_addr, sd->start_vector, 1023);
		tokenizer = strtok(start_addr, ".");
		for (y = 3; y != 0; y--) {
			tokenizer = strtok(NULL, ".");
			if (!tokenizer) {
				strncpy(sd->addr, argv_cp, 1023);
				return 0;
			}
		}

		sd->subnet_start = atoi(tokenizer);
	} else
		sd->subnet_end = sd->subnet_start;

	strncpy(sd->addr, sd->start_vector, 1023);

	/* XXX do we need a x.x.x.0 case here? Probably */
	if (sd->subnet_start)
		if (sd->subnet_start > 254) {
			fprintf(stderr, "Error: Invalid subnet start value\n");
			exit(EXIT_FAILURE);
		}

	/* XXX-bug: 0 case cannot be caught */
	if (sd->subnet_end) {
		if (sd->subnet_end <= 0) {
			fprintf(stderr,
				"Error: subnet end is equal or less than 0\n");
			exit(EXIT_FAILURE);
		} else if (sd->subnet_end >= 255) {
			fprintf(stderr,
				"Error: subnet end is equal to or greater than 255\n");
			exit(EXIT_FAILURE);
		}
	}

	if (sd->subnet_start)
		if (sd->subnet_start > sd->subnet_end) {
			fprintf(stderr,
				"Error: subnet start is greater than subnet end\n");
			exit(EXIT_FAILURE);
		}

	return 0;
}

/* MAIN */
int main(int argc, char **argv)
{
	register int i;		/* input parsing      */
	int verbose;		/* verboseflag(local) */
	struct hostent *host_info;	/* Hostinfo struct    */
	struct sockaddr_in address, address_end, scanaddr;	/* Address structs */
	struct sockaddr *cur_address;	/* Current address in subnet */
	struct sockaddr *end_address;	/* Ending subnet address */
	short int isv6 = 0;	/* XXX this is temporary til details worked out */

	if (!argv[1]) {
		fprintf(stderr, "Syntax error\n");
		usage();
		return EXIT_FAILURE;
	}

	/* Init defaults */
	init_scandata();	/* call a simple helper to clean up main() */
	verbose = 0;

	/* XXX Thoughts about these:
	   - Be easier with posix getopt?
	 */
	switch (argc) {
	case 2:		/* Trap help print request */
		if ((!strcmp(argv[1], "-?")) || (!strcmp(argv[1], "-u"))) {
			usage();
			return EXIT_SUCCESS;
		} else {
			break;
		}

	default:
		for (i = 1; i < argc - 1; i++) {
			/* verbose flag */
			if (!strcmp(argv[i], "-v")) {
				++verbose;
				/* v6 */
			} else if (!strcmp(argv[i], "-6")) {
				++isv6;
				/* isalive only check */
			} else if (!strcmp(argv[i], "-P")) {
				++verbose;
				++sd->iflag;
				/* force connect on every port flag */
			} else if (!strcmp(argv[i], "-c")) {
				++sd->cflag;
				/* set the socket type to datagram */
			} else if (!strcmp(argv[i], "-d")) {
				sd->socktype = "DGRAM";
				/* port specification */
			} else if (!strcmp(argv[i], "-p")) {
				portparse(argv[i + 1]);
				i++;
				/* timer specification */
			} else if (!strcmp(argv[i], "-t")) {
				timerparse(argv[i + 1]);
				i++;
				/* Don't strobe (e.g do not rely on /etc/services) */
			} else if (!strcmp(argv[i], "-x")) {
				++sd->xflag;
			}
		}
	}

/*	if ((strstr(argv[argc -1], ".") && (strstr(argv[argc-1], "-"))))
*/
		subnetparse(argv[argc - 1]);

	if (isv6)
		quickport6(sd->addr, sd->portstring);

	/* Initialize the address structure - zero out and assign */
	bzero((char *)&address, sizeof(address));
	address.sin_family = AF_INET;
	sd->addr[1023] = 0;	/* set the last element in the array to 0 */

	/* Try to resolve host in either direction */
	if ((host_info = gethostbyname(sd->addr))) {
		bcopy(host_info->h_addr, (char *)&address.sin_addr,
		      host_info->h_length);
	} else if ((address.sin_addr.s_addr = inet_addr(sd->start_vector)) ==
		   INADDR_NONE) {
		fprintf(stderr, "Could not resolve host\n");
		return EXIT_FAILURE;
	} else if (verbose)
		printf(" address valid\n");

	if (verbose)
		printf("Timeout: %i.%i\n", sd->inet_timeo, sd->inet_utimeo);
	if (verbose)
		printime("Scan start: ");

	while (sd->subnet_start <= sd->subnet_end) {
		cur_address = (struct sockaddr *)&address;
		end_address = (struct sockaddr *)&address_end;
		end_address->sa_data[5] = sd->subnet_end;
		printf("Host %d.%d.%d.%d",
		       (u_char) cur_address->sa_data[2],
		       (u_char) cur_address->sa_data[3],
		       (u_char) cur_address->sa_data[4],
		       (u_char) cur_address->sa_data[5]);

		if (! sd->iflag) printf("\n");

		bcopy(cur_address, &scanaddr, sizeof(scanaddr));
		if (verbose)
			if ((sd->port_start != sd->port_end)
			    && (sd->iflag == 0))
				printf("Port range: %d-%d\n", sd->port_start,
				       sd->port_end);

		scanhost(scanaddr);
		cur_address->sa_data[5]++;
		sd->subnet_start++;
	}

	if (verbose)
		printime("Scan end: ");

	return EXIT_SUCCESS;
}
