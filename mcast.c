/*****************************************************************************
 *
 *
 *  mcast.c - UDP uni and multicast traffic generator.
 *
 *  Author: Olof Hagsand. 
 *  Copyright: Olof Hagsand. 
 *
 *  This application should be kept as portable as possible and without 
 *  dependency on external software: it should compile stand-alone. 
 *
 *  On solaris link with -lsocket, -lnsl

 *  On windows use MS vcc:
 *  cl -DWIN32 mcast.c ws2_32.lib user32.lib

  This software is a part of Mcast. A very simple traffic generator
  and analyzer especially tuned for IP multicast, although it is
  useful for unicast too.

  Mcast is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  Mcast is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with Mcast; see the file COPYING.

 *****************************************************************************/
#ifdef WIN32
#define WINSOCK 2 /* We assume winsock2 on windows */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <sys/ioctl.h>

#ifndef WINSOCK
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <net/if.h> 
#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h> /* Dont remove: SIOCGIFADDR will be undefined below */
#elif defined(HAVE_SYS_SOCKIO_H)
#include <sys/sockio.h> /* Dont remove: SIOCGIFADDR will be undefined below */
#endif
#elif  (WINSOCK == 1) 
#include <winsock.h>
#define IN_CLASSD(i)            (((long)(i) & 0xf0000000) == 0xe0000000)
#elif (WINSOCK == 2)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#endif /* WINSOCK */

#ifdef WINSOCK
#define sockerror(s) fprintf(stderr, "Error: %s %d\n", (s), WSAGetLastError());
#else
#define sockerror(s) perror(s)
#endif

#if defined(WIN32) || defined(LINUX)
#define bcopy(a,b,c)                   memcpy((b),(a),(c))
#define bcmp(a,b,c)                    memcmp((a),(b),(c))
#define bzero(a,b)                     memset((a),0,(b))
#endif

#define DEFAULT_TTL            8
#define DEFAULT_DURATION_S    10 
#define DEFAULT_PKT_SIZE    (1500-28)
#define DEFAULT_PACKET_PERIOD_US    (1000*1000) /* Time between packets */
#define DEFAULT_POLL_PERIOD_MS 9 /* timer interrupt (not packet interval) */
#define BUFSIZE           8*1024

#ifndef MAX
#define MAX(x, y) ((x)>(y)?(x):(y))
#endif
#ifndef MIN
#define MIN(x, y) ((x)<(y)?(x):(y))
#endif

extern int errno;

/*
 * traffic generator
 */
static void tg_start(unsigned int);
static int tg_done(long long duration_ms);
static int tg_npackets(long long duration_ms);
static void tg_log (int len);
static void tg_exit(int);
static void tg_stats(int);

/*
 * local variables
 */
static long long  nr_packets = 0; /* global variable to log nr of packets */
static int  nr_nobufs = 0;  /* global variable to log nr of buf overflows */
static int debug = 0;
static int quiet = 0;
static char sendbuf[BUFSIZE];
struct timeval T0; /* start */
static char *payload = NULL;

/*
 * Set a signal handler.
 */
static void 
(*set_signal(int signo, void (*handler)()))()
{
#if defined(HAVE_SIGACTION)
    struct sigaction sold, snew;

    snew.sa_handler = handler;
    sigemptyset(&snew.sa_mask);
    snew.sa_flags = 0;
    if (sigaction (signo, &snew, &sold) < 0)
	sockerror ("sigaction");
    return sold.sa_handler;
#elif defined(HAVE_SIGVEC)
    struct sigvec sold, snew;

    snew.sv_handler = handler;
    snew.sv_mask = 0;
    snew.sv_flags = 0;
    if (sigvec (signo, &snew, &sold) < 0)
	sockerror ("sigvec");
    return sold.sv_handler;
#else /* signal */
    void (*old_handler)();

    old_handler = signal (signo, handler);
    if (old_handler == SIG_ERR)
	sockerror ("signal");
    return old_handler;
#endif
}

static void
timevalfix(struct timeval *t1)
{
    if (t1->tv_usec < 0) {
        t1->tv_sec--;
        t1->tv_usec += 1000000;
    }
    if (t1->tv_usec >= 1000000) {
        t1->tv_sec++;
        t1->tv_usec -= 1000000;
    }
}

/*
 * Sub two timevals and return result.
 */
static struct timeval 
timevalsub(struct timeval t1, struct timeval t2)
{
    struct timeval t = t1;
    t.tv_sec -= t2.tv_sec;
    t.tv_usec -= t2.tv_usec;
    timevalfix(&t);
    return t; 
}

#ifdef WIN32 /* only used in WIN32 */
static struct timeval
timevaladd(struct timeval t1, struct timeval t2)
{
    struct timeval t = t1;
    t.tv_sec += t2.tv_sec;
    t.tv_usec += t2.tv_usec;
    timevalfix(&t);
    return t; 
}
#endif

#ifdef WIN32
#include "windows.h"
#define exp32 4294967296.0 /* (2^32) */

#ifdef WINSOCK
#include <sys/timeb.h>
#endif

/*-------------------------------------------------------------------------
  Real-time clock on PC
  Some statistics:
  On my PentiumPRO, it takes 7 microseconds to make the realtime clock call.
  clocks calendar clocks on unix & my pc differs with 150 secs.
-------------------------------------------------------------------------*/

struct timeval 
gettimestamp()
{
    struct timeval tp;
    static double _usec_res;
    static double _sec_res;
    static int firsttime = TRUE;
    static struct timeval absdiff;
    LARGE_INTEGER Time; /* Clock cykler */
    unsigned long sec;
    unsigned long usec;

    if (firsttime){
	LARGE_INTEGER Frequency; /* cykler / sek */
	QueryPerformanceFrequency (&Frequency); /* XXX: init */
	_usec_res = 1000000.0/Frequency.LowPart; /* 0.9 */
	if (_usec_res > 1)
	    fprintf(stderr, "wise_init: performance frequency factor > 1");
	_sec_res = exp32/Frequency.LowPart; /* 3500 */
    }
    QueryPerformanceCounter (&Time);
    usec = Time.LowPart*_usec_res; /* microsekunder */
    sec = usec/1000000;
    usec = usec%1000000;
    sec += Time.HighPart*_sec_res; 
    tp.tv_sec = sec;
    tp.tv_usec = usec;
    if (firsttime) {
#ifdef WINSOCK
	struct timeb fnow;
	ftime(&fnow);

	absdiff.tv_sec = fnow.time;
	absdiff.tv_usec = 1000*(unsigned long)fnow.millitm;
#else
	gettimeofday(&absdiff, NULL);
#endif
	absdiff = timevalsub(absdiff, tp);
#if 0
	absdiff.tv_usec = 0;
	absdiff.tv_sec |= 0x0000ffff; /* Only on i386 */
#endif
	firsttime = FALSE;
    }
    tp = timevaladd(tp, absdiff); 
    return tp;
}

#else /* WIN32 */
/*
 * return current time.
 */
static struct timeval
gettimestamp()
{  
    struct timeval t;
    gettimeofday(&t, NULL);
    return t;
}
#endif /* WIN32 */


/*
 * Pretty print a timeval in a static string.
 */
static char *
timevalprint(struct timeval t1)
{
    static char s[64];

    if (t1.tv_sec < 0 && t1.tv_usec > 0){
	if (t1.tv_sec == -1)
	    snprintf(s, 64, "-%ld.%06ld", (long)t1.tv_sec+1, 1000000-(long)t1.tv_usec);
	else
	    snprintf(s, 64, "%ld.%06ld", (long)t1.tv_sec+1, 1000000-(long)t1.tv_usec);
    }
    else
	snprintf(s, 64, "%ld.%06ld", (long)t1.tv_sec, (long)t1.tv_usec);
    return s;
}

static void
usage(char *argv0)
{
    fprintf(stderr, "usage:\t%s [options]* <addr>:<port>   Send UDP packets to destination\n"
	    "where options are:\n"
	    "\t-h \t\tHelp text\n" 
	    "\t-D \t\tDebug\n"
	    "\t-b \t\tBacklog (print info from receiver)\n"
/*	    "\t-q \t\tQuiet\n" */
	    "\t-t <ttl>\tOrigin _multicast_ TTL value (default: %u)\n"
	    "\t-i <ifname>\tSending interface name \n"
	    "\t-d <sec>\tDuration of test in seconds (default: %ds)\n"
	    "\t-B <nr>\t\tJust send a burst of <nr> packets. Overrides -d.\n"
	    "\t-s <len>\tPacket length in bytes (default: %d)\n"
	    "\t-S <sec>\tStart time until start of test (default 0)\n"
	    "\t-x <len>\tSet transmit socket buffer\n"
	    "\t-p <us>\t\tInter-packet interval in us (default: %u us)\n"
	    "\t-P <ms>\t\tPoll period in ms (default %u ms). 0 means busy loop\n"
	    "\t-l <port>\tLocal sender UDP port (default random)\n"
	    "\t-T <number>\tTos value in sending traffic (default 0)\n" 
	    "\t-L <string>\tPayload string\n", 
	    argv0,
	    DEFAULT_TTL,
	    DEFAULT_DURATION_S,
	    DEFAULT_PKT_SIZE,
	    DEFAULT_PACKET_PERIOD_US,
	    DEFAULT_POLL_PERIOD_MS
	);
    exit(0);
}


static int
send_one(int s, struct sockaddr *addr, int addrlen, int len)
{
    struct timeval t;
    char          *p;

    p = sendbuf;
    *(int*)p = htonl(nr_packets);

    t = gettimestamp();
    p += sizeof(int);
    memcpy(p, &t, sizeof(t)); /* XXX: not byte-swapped */
    p += sizeof(t);
    if (payload)
	strncpy(p, payload, len-(p-sendbuf));
    if (debug && (nr_packets%10000 == 0))
	tg_log(len);
    if ((sendto(s, sendbuf, len, 0x0, addr, addrlen)) < 0){
#ifndef WINSOCK
	if (errno == ENOBUFS) {/* try again if ifq is empty */
	    nr_nobufs++;
	    if (!quiet)
		sockerror("sendto");
	    return 0;
	}
#endif
	sockerror("sendto");
	return -1;
    }
    nr_packets++; /* global */
    return 0;
}

static int
send_data(int s, struct sockaddr *dst_addr,
	  int addrlen, int len, 
	  long long duration_s)
{
    int i, nr;

    nr = tg_npackets(1000*duration_s);
    if (nr < 0)
	return -1;
    for (i=0; i<nr; i++){
	
	if (send_one(s, dst_addr, addrlen, len) < 0)
	    return -1;
    }
    return 0;
}

/* port in network byte order */  
static int
host2saddr(char *hostname)
{
    struct hostent *hp;
    int saddr;

    saddr = inet_addr(hostname);
    if (saddr == -1) {
	/* symbolic name */
	hp = gethostbyname(hostname);
	if (hp == 0)
	    return -1;
	bcopy((char*)hp->h_addr_list[0], (char*)&saddr, sizeof(saddr));
    }
    return saddr; /* OK */
}


/*
 * translate from ifname, eg "dr0" to inet address.
 */
static int
ifname2addr(const char *ifname, struct in_addr *ifaddr)
{
    int s;
    struct  ifreq  ifr;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
	sockerror("socket");
	return -1;
    }
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    (void) strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFADDR, (void*)&ifr) < 0) {
	perror("ioctl SIOCGIFADDR");
	close(s);
	return -1;
    }
    close(s);
    *ifaddr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    return 0;
}


int
main(int argc, char *argv[])
{
    char              *argv0 = argv[0];
    int                s;
    int                c;
    int                n;
    int                saddr;
    unsigned short     port;
    unsigned char      ttl = DEFAULT_TTL;
    char              *pstr;
    char               hostname[64];
    char               hostname0[64];
    struct sockaddr_in addr;
    struct sockaddr   *addrp;
    int                addrlen;
    char              *ifname = NULL;
    struct in_addr     ifaddr;
    long long          duration_s = DEFAULT_DURATION_S;
    int                pkt_size = DEFAULT_PKT_SIZE;
    int                packet_period_us = DEFAULT_PACKET_PERIOD_US; /* Time between packets */
    unsigned short     lport = 0;
    struct timeval     poll_period_tv;
    fd_set             fdset;
    double             start_s = 0;
    int                len;
    int                backlog = 0;
    int                tos = 0;
    int                poll_period_ms = DEFAULT_POLL_PERIOD_MS;
    int                burst = 0;
    int                sockbuflen = 0;
#ifdef WIN32
    HWND              _hwnd; /* Braindead: need to create windows for events */
    UINT               polltimer = 0;  /*Timer interval for receiving */
#endif

    argv++;argc--;
    if (argc == 0)
	usage(argv0);
    for (;(argc>0)&& *argv; argc--, argv++){
	if (**argv != '-')
	    break;
	(*argv)++;
	if (strlen(*argv)==0)
	    usage(argv0);
	c = **argv;
	switch (c) {
	case 'h' : /* help */
	    usage(argv0);
	    break;
	case 'D' : /* debug */
	    debug++;
	    break;
	case 'b' : /* backlog */
	    backlog++;
	    break;
	case 'q' : /* be (more) quiet */
	    quiet++;
	    break;
	case 't' : /* ttl */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    ttl = atoi(*argv);
	    break;
	case 'i' : /* interface */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    ifname = strdup(*argv);
	    if (ifname2addr(ifname, &ifaddr) < 0)
		exit(0);
	    break;
	case 'd' : /* duration in s*/
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    if (sscanf(*argv, "%llu", &duration_s) != 1){
		fprintf(stderr, "Illegal duration: %s s\n", *argv);
		exit(1);
	    }
	    if (duration_s == 0)
		duration_s = 10000000000LL; /* Hack for long period */
	    break;
	case 'B' : /* Burst */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    burst = atoi(*argv);
	    break;
	case 's' : /* packet size */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    pkt_size = atoi(*argv);
	    break;
	case 'S' : /* start time in seconds */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    start_s = atof(*argv);
	    break;
	case 'x' : /* socket buffer */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    sockbuflen = atoi(*argv);
	    break;
	case 'p' : /* period in us (time between packets) */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    packet_period_us = atoi(*argv);
	    if (packet_period_us <= 0){
		fprintf(stderr, "Illegal period: %d ms\n", packet_period_us);
		exit(1);
	    }
	    break;
	case 'P' : /* Poll period in ms */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    poll_period_ms = atoi(*argv);
	    if (poll_period_ms < 0){
		fprintf(stderr, "Illegal poll period: %d ms\n", poll_period_ms);
		exit(1);
	    }
	    break;
	case 'l': /* local port number */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    lport = atoi(*argv);
	    break;
	case 'T': /* ToS bits */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    if (sscanf(*argv, "%d", &tos) != 1)
		usage(argv0);
	    break;
	case 'L': /* Payload string */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    payload = *argv;
	    break;
	}
    }
    if (argc < 1)
	usage(argv0);
    if ((pstr = (char*)strrchr(*argv, ':')) == NULL){
	fprintf(stderr, "Illegal syntax\n");
	usage(argv0);
    }
#ifdef WINSOCK
    {
	int err;
	WSADATA wsaData; 
	WORD wVersionRequested;
      
#if (WINSOCK == 1)
	wVersionRequested = MAKEWORD( 1, 1 ); 
#elif (WINSOCK == 2)
	wVersionRequested = MAKEWORD( 2, 0 ); 
#endif
	err = WSAStartup( wVersionRequested, &wsaData ); 
	if ( err != 0 ) 
	    fprintf(stderr, "WSAStartup failed");
    }
#endif /* WINSOCK */
    if (gethostname(hostname0, sizeof(hostname0)) < 0) {
	sockerror("gethostname");
	exit(0);
    }

    port = atoi(pstr+1);
    if (port <= 0){
	fprintf(stderr, "Illegal port in: %s\n", *argv);
	exit(0);
    }
    *pstr = '\0';
    strncpy(hostname, *argv, sizeof(hostname));
    if (strlen(hostname)==0) 
	strncpy(hostname, hostname0, sizeof(hostname));
    if ((saddr = host2saddr(hostname)) == -1) {
	fprintf(stderr, "Illegal address: %s\n", hostname);
	exit(0);
    }
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	sockerror("socket");
	exit(0);
    }
    if (ifname){
	if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
		       (char *)&ifaddr, sizeof(ifaddr)) < 0) {
	    sockerror("setsockopt ip_MULTICAST_IF");
	    exit(0);
	}
	
    }
#ifndef WINSOCK
    if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
		   &ttl, sizeof(ttl)) < 0){
	sockerror("setsockopt IP_MULTICAST_TTL");
	exit(0);
    }
#endif
    if (ifname || lport != 0) {      /* Bind local port number */
	struct sockaddr_in myaddr;
	socklen_t myaddrlen = sizeof(myaddr);

	if (ifname){
	    memset(&myaddr, 0, sizeof(myaddr));
#ifdef HAVE_SIN_LEN
	    myaddr.sin_len = sizeof(myaddr);
#endif
	    myaddr.sin_family = AF_INET;
	    memcpy(&myaddr.sin_addr, &ifaddr, sizeof(ifaddr));
	}
	else
	    if (getsockname(s, (struct sockaddr *) &myaddr, &myaddrlen) == -1) {
		sockerror("getsockname");
		exit(1);
	    }
	if (lport)
	    myaddr.sin_port = htons(lport);
	if (-1 == bind(s, (struct sockaddr *) &myaddr, sizeof(myaddr))) {
	    sockerror("bind");
	    exit(1);
	}
    }
#ifdef IP_TOS
    if (tos) {
	socklen_t tos0 = 0, tlen;
	tlen = sizeof(tos);
	if (getsockopt(s, IPPROTO_IP, IP_TOS,
		       (void *) &tos0, &tlen) < 0){
	    sockerror("getsockopt IP_TOS");  
	}
	else {
	    fprintf(stderr, "Setting IP_TOS (%d) to 0x%x from 0x%x\n", IP_TOS, tos, tos0);
	    if (setsockopt(s, IPPROTO_IP, IP_TOS,
			   (char *) &tos, sizeof(tos)) < 0)
		sockerror("setsockopt IP_TOS");  
	}
    }
#endif /* IP_TOS */
    if (sockbuflen){
	int n;
	socklen_t nlen = sizeof(n);

	if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &n, &nlen) == -1) {
	    perror("getsockopt(SNDBUF)");
	    exit(1);
	}
	if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sockbuflen, 
		       sizeof(sockbuflen)) == -1) {
	    perror("setsockopt(SNDBUF)");
	    exit(1);
	}
	fprintf(stderr, "Setting rx sockbuflen:%d -> %d\n", n, sockbuflen);
    }


    argv++;argc--;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = saddr;
    addr.sin_port = htons(port);
    addrp = (struct sockaddr *) &addr;
    addrlen = sizeof(addr);

    poll_period_tv.tv_sec = 0;
    poll_period_tv.tv_usec = poll_period_ms*1000;
    set_signal(SIGINT, tg_exit); 
    set_signal(SIGTERM, tg_exit);

    /*
     * Init sendbuf
     */
#if 0
    for (i=0; i<BUFSIZE/4; i++)
	((int*)sendbuf)[i] = 0x42000000 + i;
#endif

    if (burst) /* Recompute to duration_s */
	duration_s = burst*packet_period_us/1000000.0; /* maybe burst -1 */

    /*
     * Wait till start
     */
    if (start_s){
#if 1
	struct timeval t = {start_s, 0};

	FD_ZERO(&fdset);
	n = select(FD_SETSIZE, &fdset, NULL, NULL, &t); 
	if (n == -1) {
	    sockerror ("select");
	    exit(1);
	}
#else
	struct timespec t;

	t.tv_sec = floor(start_s);
	t.tv_nsec = (start_s - floor(start_s)) * 1E9;
	nanosleep(&t, NULL);
#endif
    }
    fprintf(stdout, "%s: Sending to %s:%d\n", hostname0, inet_ntoa(addr.sin_addr), port);
    fprintf(stdout, "\tpkt_size= %d (total = %d), duration = %lld s, period = %d us\n", 
	    pkt_size, pkt_size + 28,duration_s, packet_period_us);

    tg_start(packet_period_us);
    if (send_data(s, addrp, addrlen, pkt_size, duration_s) < 0)
	exit(0);
#ifdef WINSOCK
    /* Braindead: need to create windows for events */
    _hwnd = CreateWindow("STATIC", "null", 0, 0, 0, 0, 0, 0, 0, 0, 0);
    if (poll_period_ms)
	polltimer = SetTimer(_hwnd, 0, poll_period_ms, NULL); /* ms */
#endif
    while (!tg_done(1000*duration_s)) {
#ifdef WIN32    
	MSG msg;
	if (polltimer == 0){
	    if (send_data(s, addrp, addrlen, pkt_size, duration_s) < 0)
		break;
	    continue;
	}
	if (GetMessage(&msg, NULL, 0, 0) < 0){
	    fprintf(stderr, "GetMessage error\n");
	    exit(1);
	}
	else
	    if (msg.message == WM_TIMER) {
		if (send_data(s, addrp, addrlen, pkt_size, duration_s) < 0)
		    break;
	    }
#else /* WIN32 */
	FD_ZERO(&fdset);
	n = select(FD_SETSIZE, &fdset, NULL, NULL, &poll_period_tv); 
	if (n == -1) {
	    sockerror ("select");
	    exit(1);
	}
	if (n==0){     /* Timeout */
	    if (send_data(s, addrp, addrlen, pkt_size, duration_s) < 0){
		break;
	    }
	}
#endif /* WIN32 */
    }
    tg_stats(nr_packets);
    fprintf(stdout, "mcast done, %lld packets sent from %s ", 
	    nr_packets, hostname0);
    fprintf(stdout, "to %s\n", inet_ntoa(addr.sin_addr));
    if (nr_nobufs)
	fprintf(stdout, "%d buffer overflow\n", nr_nobufs);

    /*
     * Expect a udp packet from the receiver.
     */

    if (backlog) {
	/*
	 * Wait for 10s for backlog message 
	 */
	poll_period_tv.tv_sec = 10;
	FD_ZERO(&fdset);
	FD_SET(s, &fdset);
	n = select(FD_SETSIZE, &fdset, NULL, NULL, &poll_period_tv); 
	if (n == -1) {
	    sockerror ("select");
	    exit(1);
	}
	if (n==0)   /* Timeout */
	    fprintf(stdout, "backlog timeout\n");
	else
	    if (FD_ISSET(s, &fdset)) {
		struct sockaddr_in from;
		socklen_t          fromlen;
		fromlen = sizeof(from);
		len = recvfrom(s, sendbuf, 1500, 0x0, (struct sockaddr *)&from, &fromlen);
		if (len < 0){
		    sockerror("recvfrom");
		    exit(0);
		}
		if (len >= sizeof(int))
		    fprintf(stdout, "Lost_packets: %lld\n", 
			    nr_packets-*(int*)sendbuf);
	    }
    }

    return(0);
}

/*---------------------------------------------------------------------------
    Traffic Generator
 *-------------------------------------------------------------------------*/
static struct timeval tg_t0 = {0,0};
static unsigned int tg_pkt_interval_us;
static long long tg_packet_nr = 0;

/*
 * Called at exit
 */
static void 
tg_exit(int arg)
{
    static int i = 0;
    struct timeval tnow, t;

    if (i++ == 0){
	tnow = gettimestamp();
	t= timevalsub(tnow, tg_t0);
	fprintf(stderr, "mcast terminated, %lld packets sent. in %s secs\n", 
		nr_packets, timevalprint(t));
	if (nr_nobufs)
	    fprintf(stderr, "%d buffer overflow\n", nr_nobufs);
    }
    exit(0);
}


static void
tg_start(unsigned int interval_us)
{
    tg_pkt_interval_us = interval_us;
    tg_t0 = gettimestamp();
}    

/* returns 1 if time duration has passed, 0 if more traffic */
static int
tg_done(long long duration_ms)
{
    struct timeval t = gettimestamp();
    double tnow;

    if (duration_ms == 0) /* run forever */
	return 0;

    /* How long time has passed since start (in s) */
    tnow = (t.tv_sec - tg_t0.tv_sec) + (t.tv_usec - tg_t0.tv_usec)/1000000.0;

    /* Check if the time period has passed */
    return (tnow*1000 > duration_ms); 
}

/* return nr of packets to send */
static int
tg_npackets(long long duration_ms)
{
    struct timeval t = gettimestamp();
    int t1;
    int nr = 0, remaining_ms;
    uint64_t max;
    double tnow;

    /* How long time has passed since start (in s) */
    tnow = (t.tv_sec - tg_t0.tv_sec) + (t.tv_usec - tg_t0.tv_usec)/1000000.0;

    /* 
     * How many packet intervals have passed? 
     * (how many packets should have been sent?) 
     */
    t1 = ((tnow*1000*1000 ) / tg_pkt_interval_us) + 0.5;          
    if (t1 > tg_packet_nr){
	nr = t1 - tg_packet_nr;
	tg_packet_nr = t1;
    }
    if (duration_ms){
	/* With the current rate, how many pkts remain to be sent? */
	remaining_ms = duration_ms - (int)(tnow*1000.0);
	max = remaining_ms * ((double)(MAX(10, tg_packet_nr)))/(tnow*1000.0);
	return MIN(nr, max);
    }
    else
	return nr;
} 

static void
tg_log (int len)
{
    struct timeval t;
    struct tm *tm;

    t = gettimestamp();
    tm=localtime(&t.tv_sec);

    fprintf(stderr, "%llu %d-%02d-%02d %02d:%02d:%02d.%06lu\n", 
	    nr_packets,
	    1900+tm->tm_year,
	    tm->tm_mon+1,
	    tm->tm_mday,
	    tm->tm_hour,
	    tm->tm_min,
	    tm->tm_sec,
	    t.tv_usec
	);
}

static void
tg_stats(int nr)
{
    struct timeval t;
    double tnow;  

    t = timevalsub(gettimestamp(), tg_t0);
    tnow = t.tv_sec + ((double)(t.tv_usec))/1000000.0;
    fprintf(stderr, "%d.%06d s,  %f pps\n", 
	    (int)t.tv_sec, (int)t.tv_usec, 
	    ((double)nr)/tnow);
}


