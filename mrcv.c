/*****************************************************************************
 *
 *
 *  mrcv.c - UDP uni and multicast tester.
 *
 *  Author: Olof Hagsand. 
 *  Copyright: Olof Hagsand. 
 *
 *  This application should be kept as portable as possible and without 
 *  dependency on external software: it should compile stand-alone.

 *  On solaris link with -lsocket, -lnsl
 *
 *  On windows use MS vcc:
 *  cl -DWIN32 mrcv.c ws2_32.lib 

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

#ifndef WINSOCK
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/ioctl.h>
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

#ifdef WIN32
#define bcopy(a,b,c)                   memcpy((b),(a),(c))
#define bcmp(a,b,c)                    memcmp((a),(b),(c))
#define bzero(a,b)                     memset((a),0,(b))
#endif


#define	SEQ_LT(a,b)	((int)((a)-(b)) < 0)
#define	SEQ_LEQ(a,b)	((int)((a)-(b)) <= 0)
#define	SEQ_GT(a,b)	((int)((a)-(b)) > 0)
#define	SEQ_GEQ(a,b)	((int)((a)-(b)) >= 0)

static int debug = 0;
static char hostname0[64];	/* name of this host */
static int pkts = 0;		/* packets received counter */
static void doexit(int);
static int  nr_nobufs = 0;  /* global variable to log nr of buf overflows */

struct timeval firstpkt, lastpkt;

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
	perror ("sigaction");
    return sold.sa_handler;
#elif defined(HAVE_SIGVEC)
    struct sigvec sold, snew;

    snew.sv_handler = handler;
    snew.sv_mask = 0;
    snew.sv_flags = 0;
    if (sigvec (signo, &snew, &sold) < 0)
	perror ("sigvec");
    return sold.sv_handler;
#else /* signal */
    void (*old_handler)();

    old_handler = signal (signo, handler);
    if (old_handler == SIG_ERR)
	perror ("signal");
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


/*---------------------------------------------------------------------------
 *  netw_join
 *  
 *  Join an IP multicast group.
 * addr should be in the range 224.0.0.7 -- ?
 * Open a socket for the new address.
 * Record the addresses we have joined and sockets we have bound
 * by the w0.joined linked list.
 * addr & port in Network byte order 
 *--------------------------------------------------------------------------*/
int 
netw_join(int s, unsigned int addr, unsigned short port, int ifaddr)
{
    struct ip_mreq mreq;
    int size, len;

#if 1
    struct sockaddr_in maddr;
    maddr.sin_family = AF_INET;
#define CAN_BIND_TO_MULTICAST
#if defined(CAN_BIND_TO_MULTICAST)
    maddr.sin_addr.s_addr = /*htonl*/ (addr);
#else
    maddr.sin_addr.s_addr = /*htonl*/ (INADDR_ANY);
#endif /* CAN_BIND_TO_MULTICAST */
    maddr.sin_port = port;
    /* Here I bind to INADDR_ANY, and JOIN to one address ,
       Alternatively, we could BIND to a specific adress.
    */
#if 0
    if (bind(s, (struct sockaddr *) &maddr, sizeof(maddr)) < 0) {
	perror("bind");
	fprintf(stderr, "netw_join: can't bind to UDP multicast port\n");
    }
#endif
#endif
    mreq.imr_multiaddr.s_addr = addr;
    mreq.imr_interface.s_addr = ifaddr; /* addr */
    if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		   (char *)&mreq, sizeof(mreq)) < 0) {
	perror("setsockopt ip_add_membership");
	fprintf(stderr, "Hint: Old multicast kernel?\n");
    }
    len = sizeof(size);
    return 0;
}

/*  Leave an IP multicast group */
int 
netw_leave(int sock, unsigned int addr)
{
    struct ip_mreq mreq;

    bzero(&mreq, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = addr;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		   (char *)&mreq, sizeof(mreq)) < 0) {
	perror("setsockopt ip_drop_membership");
	return -1;
    }
    close(sock);
    return 0;
}

void 
mcast_init(int s)
{
    u_char value = 1;
    int one = 1;

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
		   (void *) &one, sizeof(one)) < 0)
	perror("setsockopt SO_REUSEADDR");
#ifdef SO_REUSEPORT
    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
		   (void *) &one, sizeof(one)) < 0)
	perror("setsockopt SO_REUSEPORT");
#endif /* SO_REUSEPORT */
    if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &value, sizeof(value)) < 0){
	perror("setsockopt IP_MULTICAST_TTL");
	fprintf(stderr, "Hint: Old multicast kernel?\n");
    }
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
	perror("socket");
	return -1;
    }
    bzero(&ifr, sizeof(ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    (void) strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFADDR, (caddr_t)&ifr) < 0) {
	fprintf(stderr, "ioctl SIOCGIFADDR %s\n", ifname);
	return -1;
    }
    *ifaddr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    printf("ifaddr: %s\n", inet_ntoa(*ifaddr));

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


static void
usage(char *argv0)
{
    fprintf(stderr, "usage:\t%s [options]* [<addr>]:<port>   Receive UDP packets on socket\n"
	    "where options are:\n"
	    "\t-h \t\tHelp text\n" 
	    "\t-D \t\tDebug\n"
	    "\t-b \t\tBacklog (send info back to sender)\n"
	    "\t-t <nr> \tTimeout in counts\n" 
	    "\t-f <filename>\tLog to file\n"
	    "\t-i <ifname>\tReceiving interface name \n",
	    argv0);
    exit(0);
}

/*
 * Format of sendbuf:
 * sequence:32
 * timeval:64
 */
static int
send_one(int s, struct sockaddr *addr, int addrlen, char *buf, int len)
{
    struct timeval t;

    t = gettimestamp();
    memcpy(buf+sizeof(int)+sizeof(t), &t, sizeof(t)); /* XXX: not byte-swapped */
    if ((sendto(s, buf, len, 0x0, addr, addrlen)) < 0){
	if (errno == ENOBUFS) {/* try again if ifq is empty */
	    nr_nobufs++;
	    sockerror("sendto");
	    return 0;
	}
	sockerror("sendto");
	return -1;
    }
    return 0;
}


int
main(int argc, char *argv[])
{
    char *argv0 = argv[0];
    int s, c;
    int saddr;
    int caddr;
    int conn = 0;
    struct in_addr ifaddr;
    unsigned short port;
    struct sockaddr_in addr;
    char *pstr, hostname[64];
    char *ifname = NULL;
    struct timeval t0, t;
    int pkts0 = 0;
    fd_set fdset;
    int timeout = 0, count = 0;
    unsigned int i, last;
    int backlog = 0;
    struct sockaddr_in from;
    int fromlen = 0;
    char *filename = NULL;
    FILE *f = NULL;

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
	case 't' : /* timeout */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    timeout = atoi(*argv);
	    break;
	case 'f' : /* filename */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    filename = *argv;
	    break;
	case 'c' : /* connect address */
	    conn++;
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    if ((caddr = inet_addr(*argv)) == -1) {
		fprintf(stderr, "Illegal address: %s\n", *argv);
		exit(0);
	    }
	    break;
	case 'i' : /* interface */
	    argv++;argc--;
	    if (argc == 0)
		usage(argv0);
	    ifname = strdup(*argv);
	    if (ifname2addr(ifname, &ifaddr) < 0)
		exit(0);
	    break;
	}
    }
    if (filename){
	if ((f = fopen(filename, "w")) == NULL){
	    perror("fopen");
	    exit(0);
	}
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
	perror("gethostname");
	exit(0);
    }
    set_signal(SIGINT, doexit);
    set_signal(SIGTERM, doexit);

    if (argc != 1)
	usage(argv0);
    if ((pstr = (char*)strrchr(*argv, ':')) == NULL){
	fprintf(stderr, "Illegal syntax\n");
	usage(argv0);
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
	perror("socket");
	exit(0);
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; 
    addr.sin_port = htons(port);
    {
	int yes = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0){
	perror("setsockopt");
	exit(0);
	}

	if(setsockopt(s, SOL_IP, IP_RECVTTL, &yes, sizeof(int))<0){
	    perror("IP_RECVTTL on rcv");
	    exit(1);
	};
    }
    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0){
	perror("bind");
	exit(0);
    }
    if (conn){
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = caddr; 
    addr.sin_port = 0;
    if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0){
	perror("connect");
	exit(0);
    }
    }
    if (IN_CLASSD(ntohl(saddr))) {
	mcast_init(s);
	netw_join(s, saddr, htons(port), ifname ? ifaddr.s_addr : htonl(INADDR_ANY));
    }
    {
	struct in_addr in;
	in.s_addr = saddr;
	fprintf(stderr, "Listening to %s:%hu", inet_ntoa(in), port);
	if (ifname){
	    in.s_addr = ifaddr.s_addr;
	    fprintf(stderr, " on interface %s\n", inet_ntoa(in));
	}
	else
	    fprintf(stderr, "\n");
    }

    t0 = gettimestamp();
    t.tv_sec = 1;     t.tv_usec = 0;
    last = -1;
    for (;;){
	int len = 0, n;
	char buf[8000];
    
	FD_ZERO(&fdset);
	FD_SET(s, &fdset);
	n = select(FD_SETSIZE, &fdset, NULL, NULL, NULL); 
	if (n == -1) {
	    perror ("select");
	    exit(1);
	}
	if (n==0){     /* Timeout */

	    t.tv_sec = 1;     t.tv_usec = 0;
	    if (pkts != pkts0){
		pkts0 = pkts;
		fprintf(stderr, "%s: Received %d packets\n", hostname0, pkts);
		/*
		 * Send a UDP packet back with reported number of pkts.
		 */
		if (backlog && fromlen != 0)
		    if ((sendto(s, (void*)&pkts, sizeof(pkts), 0x0, 
				(struct sockaddr*)&from, fromlen)) < 0){
			perror("sendto");
			exit(0);
		    }
		count = 0;
	    }
	    else{
		count++;
		if (timeout != 0 && count > timeout)
		    break; /* timeout */
	    }
	}
	if (FD_ISSET(s, &fdset)) {
	    struct msghdr   msg;
	    struct iovec    iov[1];
	    struct cmsghdr *cmsg;
	    struct timeval *ti;
	    char            cbuf[64];
	    int             ttl;

	    memset(&msg, 0, sizeof(msg));
	    memset(iov, 0, sizeof(iov));
	    iov[0].iov_base = buf;
	    iov[0].iov_len  = sizeof(buf);
	    msg.msg_iov     = iov;
	    msg.msg_iovlen  = 1;
	    fromlen = sizeof(from);
	    msg.msg_name = &from;
	    msg.msg_namelen = fromlen;
	    memset(cbuf, 0, 64);
	    cmsg = (struct cmsghdr *)cbuf;
	    msg.msg_control = cmsg;
	    msg.msg_controllen = 64;
	    len = recvmsg(s, &msg, 0x0);
	    if (len < 0){
		perror("recvmsg");
		exit(0);
	    }
	    i = ntohl(*(int*)buf);
	    ti = (struct timeval *)(buf + sizeof(int));
	    ttl = 0;
	    for (cmsg=CMSG_FIRSTHDR(&msg); cmsg!=NULL; cmsg=CMSG_NXTHDR(&msg,cmsg)) {
		if (cmsg->cmsg_type==IP_TTL) {
		    if (CMSG_DATA(cmsg) !=  NULL){
			ttl = *(int*)CMSG_DATA(cmsg);
			break;
		    }
		}
	    }
#if 0
	    if (SEQ_LEQ(i,last))
		fprintf(stderr, "Duplicated or reordered packet %d\n", i);
	    else
		last = i;
#endif
	    pkts++;
	    if (pkts == 1) {
		firstpkt = gettimestamp();
	    }
	    lastpkt = gettimestamp();
	    t = gettimestamp();
	    send_one(s, msg.msg_name, msg.msg_namelen, buf, len);
//	    t = timevalsub(gettimestamp(), t0);
	    struct timeval t2 = timevalsub(t, *ti);
	    struct tm *tm;
	    tm=localtime(&t.tv_sec);
	    fprintf(stderr, "%u %lu.%06lu\n", i, t2.tv_sec, t2.tv_usec);
/*
	    fprintf(stdout, "%u %d %d-%02d-%02d %02d:%02d:%02d.%06lu\n", 
		    i,
		    ttl,
		    1900+tm->tm_year,
		    tm->tm_mon+1,
		    tm->tm_mday,
		    tm->tm_hour,
		    tm->tm_min,
		    tm->tm_sec,
		    t.tv_usec
		);
*/
	    if (f){
		if (fwrite(buf, 1, len, f) != len)
		    fprintf(stderr, "Error when writing to %s\n", filename);
	    }
	}
    }

    return(0);
}



static void doexit(int arg)
{
    struct timeval dur;

    dur = timevalsub(lastpkt, firstpkt);
    fprintf(stderr, "%s: Received %d packets (term) during %ld.%03ld secs\n", 
	    hostname0, pkts, dur.tv_sec, dur.tv_usec/1000);
    exit(0);
}
