/***********************************************************************
*
* pppoe-server.c
*
* Implementation of a user-space PPPoE server
*
* Copyright (C) 2000 Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* $Id$
*
* LIC: GPL
*
***********************************************************************/
#define CONFIG_FEATURE_PPP_BRIDGE
/* #undef  CONFIG_FEATURE_PPP_BRIDGE */

static char const RCSID[] =
"$Id$";

#include "config.h"

#if defined(HAVE_NETPACKET_PACKET_H) || defined(HAVE_LINUX_IF_PACKET_H)
#define _POSIX_SOURCE 1 /* For sigaction defines */
#endif

#define _BSD_SOURCE 1 /* for gethostname */

#include "pppoe-server.h"
#include "md5.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <stdio.h>
#include <time.h>

#include <signal.h>
#include <dirent.h>

#include <sys/ioctl.h>	//YDChao, 2011, July 4th, for adding route default gw ppp0

#ifdef HAVE_LICENSE
#include "license.h"
#include "licensed-only/servfuncs.h"
static struct License const *ServerLicense;
static struct License const *ClusterLicense;
#else
#define control_session_started(x) (void) 0
#define control_session_terminated(x) (void) 0
#define control_exit() (void) 0
#define realpeerip peerip
#endif

#ifdef HAVE_L2TP
extern PppoeSessionFunctionTable L2TPSessionFunctionTable;
extern void pppoe_to_l2tp_add_interface(EventSelector *es,
					Interface *interface);
#endif

static void InterfaceHandler(EventSelector *es,
			int fd, unsigned int flags, void *data);
static void startPPPD(ClientSession *sess);
static void sendErrorPADS(int sock, unsigned char *source, unsigned char *dest,
			  int errorTag, char *errorMsg);

pid_t* FindPidByName(char* pcPidName);
pid_t *pid_GPRSpppd = NULL;  
pid_t startGPRSPPPD(void);
int wait_gprs_pppd_established(ClientSession *session);

#define CHECK_ROOM(cursor, start, len) \
do {\
    if (((cursor)-(start))+(len) > MAX_PPPOE_PAYLOAD) { \
	syslog(LOG_INFO, "Would create too-long packet"); \
	return; \
    } \
} while(0)

static void PppoeStopSession(ClientSession *ses, char const *reason);
static int PppoeSessionIsActive(ClientSession *ses);

/* Service-Names we advertise */
#define MAX_SERVICE_NAMES 64
static int NumServiceNames = 0;
static char const *ServiceNames[MAX_SERVICE_NAMES];

static unsigned char cGetPADT=0; //add by mhho

PppoeSessionFunctionTable DefaultSessionFunctionTable = {
    PppoeStopSession,
    PppoeSessionIsActive,
    NULL
};

/* An array of client sessions */
ClientSession *Sessions = NULL;
ClientSession *FreeSessions = NULL;
ClientSession *LastFreeSession = NULL;
ClientSession *BusySessions = NULL;

/* Interfaces we're listening on */
Interface interfaces[MAX_INTERFACES];
int NumInterfaces = 0;

/* The number of session slots */
size_t NumSessionSlots;

/* Maximum number of sessions per MAC address */
int MaxSessionsPerMac;

/* Number of active sessions */
size_t NumActiveSessions = 0;

/* Offset of first session */
size_t SessOffset = 0;

/* Event Selector */
EventSelector *event_selector;

/* Use Linux kernel-mode PPPoE? */
static int UseLinuxKernelModePPPoE = 0;
//static int UseLinuxKernelModePPPoE = 1;

/* File with PPPD options */
static char *pppoptfile = NULL;

static int Debug = 0;
static int CheckPoolSyntax = 0;

/* Synchronous mode */
static int Synchronous = 0;

/* Random seed for cookie generation */
#define SEED_LEN 16
#define MD5_LEN 16
#define COOKIE_LEN (MD5_LEN + sizeof(pid_t)) /* Cookie is 16-byte MD5 + PID of server */

static unsigned char CookieSeed[SEED_LEN];

#define MAXLINE 512

/* Default interface if no -I option given */
//#define DEFAULT_IF "eth0"
#define DEFAULT_IF "br0"	//YDChao

/* Access concentrator name */
char *ACName = NULL;

/* Options to pass to pppoe process */
char PppoeOptions[SMALLBUF] = "";

/* Our local IP address */
unsigned char LocalIP[IPV4ALEN] = {10, 0, 0, 1}; /* Counter optionally STARTS here */
unsigned char RemoteIP[IPV4ALEN] = {10, 67, 15, 1}; /* Counter STARTS here */

/* Do we increment local IP for each connection? */
int IncrLocalIP = 0;

/* Do we randomize session numbers? */
int RandomizeSessionNumbers = 0;

/* Do we pass the "unit" option to pppd?  (2.4 or greater) */
int PassUnitOptionToPPPD = 0;

static PPPoETag hostUniq;
static PPPoETag relayId;
static PPPoETag receivedCookie;
static PPPoETag requestedService;

#define HOSTNAMELEN 256

static int
count_sessions_from_mac(unsigned char *eth)
{
    int n=0;
    ClientSession *s = BusySessions;
    while(s) {
	if (!memcmp(eth, s->eth, ETH_ALEN)) n++;
	s = s->next;
    }
    return n;
}

/**********************************************************************
*%FUNCTION: childHandler
*%ARGUMENTS:
* pid -- pid of child
* status -- exit status
* ses -- which session terminated
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called synchronously when a child dies.  Remove from busy list.
***********************************************************************/
static void
childHandler(pid_t pid, int status, void *s)
{
    ClientSession *session = s;
	
    printf("childHandler::interface[0].socket=%d \n\r",interfaces[0].sock);

    /* Temporary structure for sending PADT's. */
    PPPoEConnection conn;
		printf("session->pid:%d Get SIGCHID from :%d\n",session->pid,pid);
		
/*		if(pid==session->pid)
		{
			if(cGetPADT)  return;

			printf("3G pppd section kill :%d \n",session->gpid);
    			
    			//system("killall pppd");	//YDChao
    			if( pid_GPRSpppd )
    			{
    				printf("(B)kill pid_GPRSpppd: %d\n", pid_GPRSpppd[0]);
    				kill( pid_GPRSpppd[0], SIGTERM );
    				free( pid_GPRSpppd );
    				pid_GPRSpppd = NULL;
    			}
			//if(session->gpid)
			//	kill(session->gpid, SIGTERM);
			
    			if (session->gpid) {
		    	session->funcs->stop(session, "Received PADT");				
   	  		}
			////return;
		}								*/
		
#ifdef HAVE_L2TP
    /* We're acting as LAC, so when child exits, become a PPPoE <-> L2TP
       relay */
    if (session->flags & FLAG_ACT_AS_LAC) {
	syslog(LOG_INFO, "Session %u for client "
	       "%02x:%02x:%02x:%02x:%02x:%02x handed off to LNS %s",
	       (unsigned int) ntohs(session->sess),
	       session->eth[0], session->eth[1], session->eth[2],
	       session->eth[3], session->eth[4], session->eth[5],
	       inet_ntoa(session->tunnel_endpoint.sin_addr));
	session->pid = 0;
	session->funcs = &L2TPSessionFunctionTable;
	return;
    }
#endif

    memset(&conn, 0, sizeof(conn));
    conn.useHostUniq = 0;

    syslog(LOG_INFO,
	   "Session %u closed for client "
	   "%02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s",
	   (unsigned int) ntohs(session->sess),
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   (int) session->realpeerip[0], (int) session->realpeerip[1],
	   (int) session->realpeerip[2], (int) session->realpeerip[3],
	   session->ethif->name);
    memcpy(conn.myEth, session->ethif->mac, ETH_ALEN);
    conn.discoverySocket = session->ethif->sock;
    conn.session = session->sess;
    memcpy(conn.peerEth, session->eth, ETH_ALEN);
    if (!(session->flags & FLAG_SENT_PADT)) {
	if (session->flags & FLAG_RECVD_PADT) {
	    sendPADT(&conn, "RP-PPPoE: Received PADT from peer");
	} else {
	    sendPADT(&conn, "RP-PPPoE: Child pppd process terminated");
	}
	session->flags |= FLAG_SENT_PADT;
    }

    session->serviceName = "";
    control_session_terminated(session);
    printf("childHandler1::interface[0].socket=%d \n\r",interfaces[0].sock);	
    if (pppoe_free_session(session) < 0) {
    printf("childHandler2::interface[0].socket=%d \n\r",interfaces[0].sock);		
	return;
    }
    printf("childHandler3::interface[0].socket=%d \n\r",interfaces[0].sock);	

}

/**********************************************************************
*%FUNCTION: incrementIPAddress (static)
*%ARGUMENTS:
* addr -- a 4-byte array representing IP address
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Increments addr in-place
***********************************************************************/
static void
incrementIPAddress(unsigned char ip[IPV4ALEN])
{
    ip[3]++;
    if (!ip[3]) {
	ip[2]++;
	if (!ip[2]) {
	    ip[1]++;
	    if (!ip[1]) {
		ip[0]++;
	    }
	}
    }
}

/**********************************************************************
*%FUNCTION: killAllSessions
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills all pppd processes (and hence all PPPoE sessions)
***********************************************************************/
void
killAllSessions(void)
{
    ClientSession *sess = BusySessions;
    while(sess) {
	sess->funcs->stop(sess, "Shutting Down");
	sess = sess->next;
    }
#ifdef HAVE_L2TP
    pppoe_close_l2tp_tunnels();
#endif
}

/**********************************************************************
*%FUNCTION: parseAddressPool
*%ARGUMENTS:
* fname -- name of file containing IP address pool.
* install -- if true, install IP addresses in sessions.
*%RETURNS:
* Number of valid IP addresses found.
*%DESCRIPTION:
* Reads a list of IP addresses from a file.
***********************************************************************/
static int
parseAddressPool(char const *fname, int install)
{
    FILE *fp = fopen(fname, "r");
    int numAddrs = 0;
    unsigned int a, b, c, d;
    unsigned int e, f, g, h;
    char line[MAXLINE];

    if (!fp) {
	sysErr("Cannot open address pool file");
	exit(1);
    }

    while (!feof(fp)) {
	if (!fgets(line, MAXLINE, fp)) {
	    break;
	}
	if ((sscanf(line, "%u.%u.%u.%u:%u.%u.%u.%u",
		    &a, &b, &c, &d, &e, &f, &g, &h) == 8) &&
	    a < 256 && b < 256 && c < 256 && d < 256 &&
	    e < 256 && f < 256 && g < 256 && h < 256) {

	    /* Both specified (local:remote) */
	    if (install) {
		Sessions[numAddrs].myip[0] = (unsigned char) a;
		Sessions[numAddrs].myip[1] = (unsigned char) b;
		Sessions[numAddrs].myip[2] = (unsigned char) c;
		Sessions[numAddrs].myip[3] = (unsigned char) d;
		Sessions[numAddrs].peerip[0] = (unsigned char) e;
		Sessions[numAddrs].peerip[1] = (unsigned char) f;
		Sessions[numAddrs].peerip[2] = (unsigned char) g;
		Sessions[numAddrs].peerip[3] = (unsigned char) h;
#ifdef HAVE_LICENSE
		memcpy(Sessions[numAddrs].realpeerip,
		       Sessions[numAddrs].peerip, IPV4ALEN);
#endif
	    }
	    numAddrs++;
	} else if ((sscanf(line, "%u.%u.%u.%u-%u", &a, &b, &c, &d, &e) == 5) &&
		   a < 256 && b < 256 && c < 256 && d < 256 && e < 256) {
	    /* Remote specied as a.b.c.d-e.  Example: 1.2.3.4-8 yields:
	       1.2.3.4, 1.2.3.5, 1.2.3.6, 1.2.3.7, 1.2.3.8 */
	    /* Swap d and e so that e >= d */
	    if (e < d) {
		f = d;
		d = e;
		e = f;
	    }
	    if (install) {
		while (d <= e) {
		    Sessions[numAddrs].peerip[0] = (unsigned char) a;
		    Sessions[numAddrs].peerip[1] = (unsigned char) b;
		    Sessions[numAddrs].peerip[2] = (unsigned char) c;
		    Sessions[numAddrs].peerip[3] = (unsigned char) d;
#ifdef HAVE_LICENSE
		    memcpy(Sessions[numAddrs].realpeerip,
			   Sessions[numAddrs].peerip, IPV4ALEN);
#endif
		d++;
		numAddrs++;
		}
	    } else {
		numAddrs += (e-d) + 1;
	    }
	} else if ((sscanf(line, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) &&
		   a < 256 && b < 256 && c < 256 && d < 256) {
	    /* Only remote specified */
	    if (install) {
		Sessions[numAddrs].peerip[0] = (unsigned char) a;
		Sessions[numAddrs].peerip[1] = (unsigned char) b;
		Sessions[numAddrs].peerip[2] = (unsigned char) c;
		Sessions[numAddrs].peerip[3] = (unsigned char) d;
#ifdef HAVE_LICENSE
		memcpy(Sessions[numAddrs].realpeerip,
		       Sessions[numAddrs].peerip, IPV4ALEN);
#endif
	    }
	    numAddrs++;
	}
    }
    fclose(fp);
    if (!numAddrs) {
	rp_fatal("No valid ip addresses found in pool file");
    }
    return numAddrs;
}

/**********************************************************************
*%FUNCTION: parsePADITags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADI packet
***********************************************************************/
void
parsePADITags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_SERVICE_NAME:
	/* Copy requested service name */
	requestedService.type = htons(type);
	requestedService.length = htons(len);
	memcpy(requestedService.payload, data, len);
	break;
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADRTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADR packet
***********************************************************************/
void
parsePADRTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    case TAG_AC_COOKIE:
	receivedCookie.type = htons(type);
	receivedCookie.length = htons(len);
	memcpy(receivedCookie.payload, data, len);
	break;
    case TAG_SERVICE_NAME:
	requestedService.type = htons(type);
	requestedService.length = htons(len);
	memcpy(requestedService.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    char buf[SMALLBUF];
    snprintf(buf, SMALLBUF, "%s: %s", str, strerror(errno));
    printErr(buf);
    control_exit();
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: sysErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to syslog.
***********************************************************************/
void
sysErr(char const *str)
{
    char buf[1024];
    sprintf(buf, "%.256s: %.256s", str, strerror(errno));
    printErr(buf);
}

/**********************************************************************
*%FUNCTION: rp_fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
rp_fatal(char const *str)
{
    printErr(str);
    control_exit();
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: genCookie
*%ARGUMENTS:
* peerEthAddr -- peer Ethernet address (6 bytes)
* myEthAddr -- my Ethernet address (6 bytes)
* seed -- random cookie seed to make things tasty (16 bytes)
* cookie -- buffer which is filled with server PID and
*           md5 sum of previous items
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Forms the md5 sum of peer MAC address, our MAC address and seed, useful
* in a PPPoE Cookie tag.
***********************************************************************/
void
genCookie(unsigned char const *peerEthAddr,
	  unsigned char const *myEthAddr,
	  unsigned char const *seed,
	  unsigned char *cookie)
{
    struct MD5Context ctx;
    pid_t pid = getpid();

    MD5Init(&ctx);
    MD5Update(&ctx, peerEthAddr, ETH_ALEN);
    MD5Update(&ctx, myEthAddr, ETH_ALEN);
    MD5Update(&ctx, seed, SEED_LEN);
    MD5Final(cookie, &ctx);
    memcpy(cookie+MD5_LEN, &pid, sizeof(pid));
}

/**********************************************************************
*%FUNCTION: processPADI
*%ARGUMENTS:
* ethif -- Interface
* packet -- PPPoE PADI packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADO packet back to client
***********************************************************************/
void
processPADI(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPoEPacket pado;
    PPPoETag acname;
    PPPoETag servname;
    PPPoETag cookie;
    size_t acname_len;
    unsigned char *cursor = pado.payload;
    UINT16_t plen;

    int sock = ethif->sock;
    int i;
    int ok = 0;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	syslog(LOG_INFO, "PADI packet from non-unicast source address");
	return;
    }

    /* If number of sessions per MAC is limited, check here and don't
       send PADO if already max number of sessions. */
    if (MaxSessionsPerMac) {
	if (count_sessions_from_mac(packet->ethHdr.h_source) >= MaxSessionsPerMac) {
	    syslog(LOG_INFO, "PADI: Client %02x:%02x:%02x:%02x:%02x:%02x attempted to create more than %d session(s)",
		   packet->ethHdr.h_source[0],
		   packet->ethHdr.h_source[1],
		   packet->ethHdr.h_source[2],
		   packet->ethHdr.h_source[3],
		   packet->ethHdr.h_source[4],
		   packet->ethHdr.h_source[5],
		   MaxSessionsPerMac);
	    return;
	}
    }

    acname.type = htons(TAG_AC_NAME);
    acname_len = strlen(ACName);
    acname.length = htons(acname_len);
    memcpy(acname.payload, ACName, acname_len);

    relayId.type = 0;
    hostUniq.type = 0;
    requestedService.type = 0;
    parsePacket(packet, parsePADITags, NULL);

    /* If PADI specified non-default service name, and we do not offer
       that service, DO NOT send PADO */
    if (requestedService.type) {
	int slen = ntohs(requestedService.length);
	if (slen) {
	    for (i=0; i<NumServiceNames; i++) {
		if (slen == strlen(ServiceNames[i]) &&
		    !memcmp(ServiceNames[i], &requestedService.payload, slen)) {
		    ok = 1;
		    break;
		}
	    }
	} else {
	    ok = 1;		/* Default service requested */
	}
    } else {
	ok = 1;			/* No Service-Name tag in PADI */
    }
    if (!ok) {
	/* PADI asked for unsupported service */
	return;
    }
    /* Generate a cookie */
    cookie.type = htons(TAG_AC_COOKIE);
    cookie.length = htons(COOKIE_LEN);
    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookie.payload);
    /* Construct a PADO packet */
    memcpy(pado.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pado.ethHdr.h_source, myAddr, ETH_ALEN);
    pado.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pado.ver = 1;
    pado.type = 1;
    pado.code = CODE_PADO;
    pado.session = 0;
    plen = TAG_HDR_SIZE + acname_len;

    CHECK_ROOM(cursor, pado.payload, acname_len+TAG_HDR_SIZE);
    memcpy(cursor, &acname, acname_len + TAG_HDR_SIZE);
    cursor += acname_len + TAG_HDR_SIZE;
    /* If no service-names specified on command-line, just send default
       zero-length name.  Otherwise, add all service-name tags */
    servname.type = htons(TAG_SERVICE_NAME);
    if (!NumServiceNames) {
	servname.length = 0;
	CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE);
	memcpy(cursor, &servname, TAG_HDR_SIZE);
	cursor += TAG_HDR_SIZE;
	plen += TAG_HDR_SIZE;
    } else {
	for (i=0; i<NumServiceNames; i++) {
	    int slen = strlen(ServiceNames[i]);
	    servname.length = htons(slen);
	    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE+slen);
	    memcpy(cursor, &servname, TAG_HDR_SIZE);
	    memcpy(cursor+TAG_HDR_SIZE, ServiceNames[i], slen);
	    cursor += TAG_HDR_SIZE+slen;
	    plen += TAG_HDR_SIZE+slen;
	}
    }

    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE + COOKIE_LEN);
    memcpy(cursor, &cookie, TAG_HDR_SIZE + COOKIE_LEN);
    cursor += TAG_HDR_SIZE + COOKIE_LEN;
    plen += TAG_HDR_SIZE + COOKIE_LEN;

    if (relayId.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(hostUniq.length)+TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pado.length = htons(plen);
    sendPacket(NULL, sock, &pado, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: processPADT
*%ARGUMENTS:
* ethif -- interface
* packet -- PPPoE PADT packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills session whose session-ID is in PADT packet.
***********************************************************************/
void
processPADT(Interface *ethif, PPPoEPacket *packet, int len)
{
    size_t i;
    
    unsigned char *myAddr = ethif->mac;
	//printf("Enter processPADT \n");
    /* Ignore PADT's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    /* Get session's index */
    i = ntohs(packet->session) - 1 - SessOffset;
    if (i >= NumSessionSlots) return;
    if (Sessions[i].sess != packet->session) {
	syslog(LOG_INFO, "Session index %u doesn't match session number %u",
	       (unsigned int) i, (unsigned int) ntohs(packet->session));
	return;
    }


    /* If source MAC does not match, do not kill session */
    if (memcmp(packet->ethHdr.h_source, Sessions[i].eth, ETH_ALEN)) {
	syslog(LOG_WARNING, "PADT for session %u received from "
	       "%02X:%02X:%02X:%02X:%02X:%02X; should be from "
	       "%02X:%02X:%02X:%02X:%02X:%02X",
	       (unsigned int) ntohs(packet->session),
	       packet->ethHdr.h_source[0],
	       packet->ethHdr.h_source[1],
	       packet->ethHdr.h_source[2],
	       packet->ethHdr.h_source[3],
	       packet->ethHdr.h_source[4],
	       packet->ethHdr.h_source[5],
	       Sessions[i].eth[0],
	       Sessions[i].eth[1],
	       Sessions[i].eth[2],
	       Sessions[i].eth[3],
	       Sessions[i].eth[4],
	       Sessions[i].eth[5]);
	return;
    }
    Sessions[i].flags |= FLAG_RECVD_PADT;
    parsePacket(packet, parseLogErrs, NULL);
    
    cGetPADT=1;//add by mhho

    printf("interface[0].socket=%d \n\r",interfaces[0].sock);
    	
    Sessions[i].funcs->stop(&Sessions[i], "Received PADT");
    printf("interface[0].socket=%d \n\r",interfaces[0].sock);	
}


//Add by mhho for BTAP
void restartHSUPA(void)
{
printf("USB power cycle\n");
return;
	system("gpio l 11 4000 0 0 0 0");
	sleep( 3 );
	system("gpio l 11 0 4000 0 0 0");
}

//end of add
/**********************************************************************
*%FUNCTION: processPADR
*%ARGUMENTS:
* ethif -- Ethernet interface
* packet -- PPPoE PADR packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet back to client and starts a PPP session if PADR
* packet is OK.
***********************************************************************/
void
processPADR(Interface *ethif, PPPoEPacket *packet, int len)
{
    cGetPADT=0; //add by mhho
	
    unsigned char cookieBuffer[COOKIE_LEN];
    ClientSession *cliSession;
    pid_t child;
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    UINT16_t plen;
    int i;
    int sock = ethif->sock;
    unsigned char *myAddr = ethif->mac;
    int slen = 0;
    char const *serviceName = NULL;

#ifdef HAVE_LICENSE
    int freemem;
#endif

    /* Initialize some globals */
    relayId.type = 0;
    hostUniq.type = 0;
    receivedCookie.type = 0;
    requestedService.type = 0;


    /* Ignore PADR's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    /* Ignore PADR's from non-unicast addresses */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	syslog(LOG_INFO, "PADR packet from non-unicast source address");
	return;
    }

    /* If number of sessions per MAC is limited, check here and don't
       send PADS if already max number of sessions. */
    if (MaxSessionsPerMac) {
	if (count_sessions_from_mac(packet->ethHdr.h_source) >= MaxSessionsPerMac) {
	    syslog(LOG_INFO, "PADR: Client %02x:%02x:%02x:%02x:%02x:%02x attempted to create more than %d session(s)",
		   packet->ethHdr.h_source[0],
		   packet->ethHdr.h_source[1],
		   packet->ethHdr.h_source[2],
		   packet->ethHdr.h_source[3],
		   packet->ethHdr.h_source[4],
		   packet->ethHdr.h_source[5],
		   MaxSessionsPerMac);
		   
	    return;
	}
    }

    parsePacket(packet, parsePADRTags, NULL);

    /* Check that everything's cool */

    if (!receivedCookie.type) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Is cookie kosher? */
    if (receivedCookie.length != htons(COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookieBuffer);
    if (memcmp(receivedCookie.payload, cookieBuffer, COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Check service name */
    if (!requestedService.type) {
	syslog(LOG_INFO, "Received PADR packet with no SERVICE_NAME tag");
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Server: No service name tag");
	return;
    }

    slen = ntohs(requestedService.length);

    if (slen) {
	/* Check supported services */
	for(i=0; i<NumServiceNames; i++) {
	    if (slen == strlen(ServiceNames[i]) &&
		!memcmp(ServiceNames[i], &requestedService.payload, slen)) {
		serviceName = ServiceNames[i];
		break;
	    }
	}

	if (!serviceName) {
	    syslog(LOG_INFO, "Received PADR packet asking for unsupported service %.*s", (int) ntohs(requestedService.length), requestedService.payload);
	    sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
			  TAG_SERVICE_NAME_ERROR, "RP-PPPoE: Server: Invalid service name tag");
	    return;
	}
    } else {
	serviceName = "";
    }

#ifdef HAVE_LICENSE
    /* Are we licensed for this many sessions? */
    if (License_NumLicenses("PPPOE-SESSIONS") <= NumActiveSessions) {
	syslog(LOG_INFO, "Insufficient session licenses (%02x:%02x:%02x:%02x:%02x:%02x)",
	       (unsigned int) packet->ethHdr.h_source[0],
	       (unsigned int) packet->ethHdr.h_source[1],
	       (unsigned int) packet->ethHdr.h_source[2],
	       (unsigned int) packet->ethHdr.h_source[3],
	       (unsigned int) packet->ethHdr.h_source[4],
	       (unsigned int) packet->ethHdr.h_source[5]);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: No session licenses available");
	return;
    }
#endif
    /* Enough free memory? */
#ifdef HAVE_LICENSE
    freemem = getFreeMem();
    if (freemem < MIN_FREE_MEMORY) {
	syslog(LOG_WARNING,
	       "Insufficient free memory to create session: Want %d, have %d",
	       MIN_FREE_MEMORY, freemem);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Insufficient free RAM");
	return;
    }
#endif

    /* Looks cool... find a slot for the session */
    cliSession = pppoe_alloc_session();
    if (!cliSession) {
	syslog(LOG_INFO, "No client slots available (%02x:%02x:%02x:%02x:%02x:%02x)",
	       (unsigned int) packet->ethHdr.h_source[0],
	       (unsigned int) packet->ethHdr.h_source[1],
	       (unsigned int) packet->ethHdr.h_source[2],
	       (unsigned int) packet->ethHdr.h_source[3],
	       (unsigned int) packet->ethHdr.h_source[4],
	       (unsigned int) packet->ethHdr.h_source[5]);
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: No client slots available");
	return;
    }

    /* Set up client session peer Ethernet address */
    memcpy(cliSession->eth, packet->ethHdr.h_source, ETH_ALEN);
    cliSession->ethif = ethif;
    cliSession->flags = 0;
    cliSession->funcs = &DefaultSessionFunctionTable;
    cliSession->startTime = time(NULL);
    cliSession->serviceName = serviceName;

system("pppd call 3g");
	while( pid_GPRSpppd == NULL )
	{
		pid_GPRSpppd = FindPidByName("pppd");
		usleep( 5000 );
	}	
	printf("pid_GPRSpppd: %d\n\r", pid_GPRSpppd[0]);


    /* Create child process, send PADS packet back */
    child = fork();
////child = vfork(); how is the process of "pppd pty /bin/pppoe" been killed...??? 
    if (child < 0) {
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_AC_SYSTEM_ERROR, "RP-PPPoE: Server: Unable to start session process");
	pppoe_free_session(cliSession);
	return;
    }

    if (child != 0) {
	/* In the parent process.  Mark pid in session slot */
	cliSession->pid = child;
	Event_HandleChildExit(event_selector, child,
			      childHandler, cliSession);
	control_session_started(cliSession);
	return;
    }

    /* In the child process.  */
    /* Close all file descriptors except for socket */
    closelog();

    /* In the usermode, we should not close these fd. ???*/  
    for (i=0; i<CLOSEFD; i++) {
	if (i != sock) {
	    close(i);
	}
    }

    openlog("pppoe-server", LOG_PID, LOG_DAEMON);
    /* pppd has a nasty habit of killing all processes in its process group.
       Start a new session to stop pppd from killing us! */
    setsid();////// how is the process of "pppd pty /bin/pppoe" been killed...??? 
	
    /* Send PADS and Start pppd */
    memcpy(pads.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, myAddr, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.ver = 1;
    pads.type = 1;
    pads.code = CODE_PADS;

    pads.session = cliSession->sess;
    plen = 0;

    /* Copy requested service name tag back in.  If requested-service name
       length is zero, and we have non-zero services, use first service-name
       as default */
    if (!slen && NumServiceNames) {
	slen = strlen(ServiceNames[0]);
	memcpy(&requestedService.payload, ServiceNames[0], slen);
	requestedService.length = htons(slen);
    }
    memcpy(cursor, &requestedService, TAG_HDR_SIZE+slen);
    cursor += TAG_HDR_SIZE+slen;
    plen += TAG_HDR_SIZE+slen;

    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(NULL, sock, &pads, (int) (plen + HDR_SIZE));

    /* Close sock; don't need it any more */
    close(sock);

printf("%s:%d \n",__FILE__,__LINE__); 	

    /* We will start the GPRS PPPD first */
#ifdef CONFIG_FEATURE_PPP_BRIDGE
    // cliSession->gpid = startGPRSPPPD(); 
    //system("autoconn3G.sh connect &");
/*
system("autoconn3G.sh connect &");
	while( pid_GPRSpppd == NULL )
	{
		pid_GPRSpppd = FindPidByName("pppd");
		usleep( 10000 );
	}	
	printf("pid_GPRSpppd: %d\n\r", pid_GPRSpppd[0]);
*/
    if (0 == wait_gprs_pppd_established(cliSession))
     {

//for trying CLARO not able to browse www.uol.com
//	system("route del default gw 0.0.0.0 dev ppp0");	//YDChao
	
    	startPPPD(cliSession);
printf("%s:%d \r\n",__FILE__,__LINE__); 	    	
     }
    else
     {
	printf("gprs pppd established failed.\r\n");
	restartHSUPA();
	sleep(2);
	pppoe_free_session(cliSession);	
	printf("before return procPADR \n");
	return;
     }
#else
printf("%s:%d \r\n",__FILE__,__LINE__); 	

    startPPPD(cliSession);
printf("%s:%d \r\n",__FILE__,__LINE__); 	    
#endif    
}

/**********************************************************************
*%FUNCTION: termHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGTERM or SIGINT.  Causes all sessions to be killed!
***********************************************************************/
static void
termHandler(int sig)
{
    syslog(LOG_INFO,
	   "Terminating on signal %d -- killing all PPPoE sessions",
	   sig);
	  printf("Get SIGTERM... pid: %d\n",getpid());
    killAllSessions();
    control_exit();

if( sig == SIGTERM )	//if SIGINT, do not exit. used by GPRSpppd to notify us that its IPCP is down
    exit(0);	//do not exit, YDChao, but not able to be killed!!!!
}

/**********************************************************************
*%FUNCTION: usage
*%ARGUMENTS:
* argv0 -- argv[0] from main
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints usage instructions
***********************************************************************/
void
usage(char const *argv0)
{
    fprintf(stderr, "Usage: %s [options]\n", argv0);
    fprintf(stderr, "Options:\n");
#ifdef USE_BPF
    fprintf(stderr, "   -I if_name     -- Specify interface (REQUIRED)\n");
#else
    fprintf(stderr, "   -I if_name     -- Specify interface (default %s.)\n",
	    DEFAULT_IF);
#endif
    fprintf(stderr, "   -T timeout     -- Specify inactivity timeout in seconds.\n");
    fprintf(stderr, "   -C name        -- Set access concentrator name.\n");
    fprintf(stderr, "   -m MSS         -- Clamp incoming and outgoing MSS options.\n");
    fprintf(stderr, "   -L ip          -- Set local IP address.\n");
    fprintf(stderr, "   -l             -- Increment local IP address for each session.\n");
    fprintf(stderr, "   -R ip          -- Set start address of remote IP pool.\n");
    fprintf(stderr, "   -S name        -- Advertise specified service-name.\n");
    fprintf(stderr, "   -O fname       -- Use PPPD options from specified file\n");
    fprintf(stderr, "                     (default %s).\n", PPPOE_SERVER_OPTIONS);
    fprintf(stderr, "   -p fname       -- Optain IP address pool from specified file.\n");
    fprintf(stderr, "   -N num         -- Allow 'num' concurrent sessions.\n");
    fprintf(stderr, "   -o offset      -- Assign session numbers starting at offset+1.\n");
    fprintf(stderr, "   -f disc:sess   -- Set Ethernet frame types (hex).\n");
    fprintf(stderr, "   -s             -- Use synchronous PPP mode.\n");
#ifdef HAVE_LINUX_KERNEL_PPPOE
    fprintf(stderr, "   -k             -- Use kernel-mode PPPoE.\n");
#endif
    fprintf(stderr, "   -u             -- Pass 'unit' option to pppd.\n");
    fprintf(stderr, "   -r             -- Randomize session numbers.\n");
    fprintf(stderr, "   -d             -- Debug session creation.\n");
    fprintf(stderr, "   -x n           -- Limit to 'n' sessions/MAC address.\n");
    fprintf(stderr, "   -P             -- Check pool file for correctness and exit.\n");
#ifdef HAVE_LICENSE
    fprintf(stderr, "   -c secret:if:port -- Enable clustering on interface 'if'.\n");
    fprintf(stderr, "   -1             -- Allow only one session per user.\n");
#endif

    fprintf(stderr, "   -h             -- Print usage information.\n\n");
    fprintf(stderr, "PPPoE-Server Version %s, Copyright (C) 2001-2006 Roaring Penguin Software Inc.\n", VERSION);

#ifndef HAVE_LICENSE
    fprintf(stderr, "PPPoE-Server comes with ABSOLUTELY NO WARRANTY.\n");
    fprintf(stderr, "This is free software, and you are welcome to redistribute it\n");
    fprintf(stderr, "under the terms of the GNU General Public License, version 2\n");
    fprintf(stderr, "or (at your option) any later version.\n");
#endif
    fprintf(stderr, "http://www.roaringpenguin.com\n");
}

/**********************************************************************
*%FUNCTION: main
*%ARGUMENTS:
* argc, argv -- usual suspects
*%RETURNS:
* Exit status
*%DESCRIPTION:
* Main program of PPPoE server
***********************************************************************/
int
main(int argc, char **argv)
{
		printf("pppoe_server Main Start at :%p \n ",main);
		printf("pppoe_server processPADT Start at :%p \n ",processPADT);	
		//printf("pppoe_server Main Start at \n\r ");
		//printf("pppoe_server Main Start at \n\r ");

    FILE *fp;
    int i, j;
    int opt;
    int d[IPV4ALEN];
    int beDaemon = 1;
    int found;
    unsigned int discoveryType, sessionType;
    char *addressPoolFname = NULL;
#ifdef HAVE_LICENSE
    int use_clustering = 0;
#endif

#ifndef HAVE_LINUX_KERNEL_PPPOE
    char *options = "x:hI:C:L:R:T:m:FN:f:O:o:sp:lrudPc:S:1";
#else
    char *options = "x:hI:C:L:R:T:m:FN:f:O:o:skp:lrudPc:S:1";
#endif
    //printf("here1\r\n");
    //return;

    if (getuid() != geteuid() ||
	getgid() != getegid()) {
	fprintf(stderr, "SECURITY WARNING: pppoe-server will NOT run suid or sgid.  Fix your installation.\n");
	exit(1);
    }

    memset(interfaces, 0, sizeof(interfaces));

    /* Initialize syslog */
    openlog("pppoe-server", LOG_PID|LOG_NDELAY, LOG_LOCAL2);
    setlogmask(LOG_UPTO(LOG_INFO));
    /* Default number of session slots */
    NumSessionSlots = DEFAULT_MAX_SESSIONS;
    MaxSessionsPerMac = 0; /* No limit */
    NumActiveSessions = 0;

    /* Parse command-line options */
    while((opt = getopt(argc, argv, options)) != -1) {
	switch(opt) {
	case 'x':
	    if (sscanf(optarg, "%d", &MaxSessionsPerMac) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (MaxSessionsPerMac < 0) {
		MaxSessionsPerMac = 0;
	    }
	    break;

#ifdef HAVE_LINUX_KERNEL_PPPOE
	case 'k':
	    UseLinuxKernelModePPPoE = 1;
	    break;
#endif
	case 'S':
	    if (NumServiceNames == MAX_SERVICE_NAMES) {
		fprintf(stderr, "Too many '-S' options (%d max)",
			MAX_SERVICE_NAMES);
		exit(1);
	    }
	    ServiceNames[NumServiceNames] = strdup(optarg);
	    if (!ServiceNames[NumServiceNames]) {
		fprintf(stderr, "Out of memory");
		exit(1);
	    }
	    NumServiceNames++;
	    break;
	case 'c':
#ifndef HAVE_LICENSE
	    fprintf(stderr, "Clustering capability not available.\n");
	    exit(1);
#else
	    cluster_handle_option(optarg);
	    use_clustering = 1;
	    break;
#endif

	case 'd':
	    Debug = 1;
	    break;
	case 'P':
	    CheckPoolSyntax = 1;
	    break;
	case 'u':
	    PassUnitOptionToPPPD = 1;
	    break;

	case 'r':
	    RandomizeSessionNumbers = 1;
	    break;

	case 'l':
	    IncrLocalIP = 1;
	    break;

	case 'p':
	    SET_STRING(addressPoolFname, optarg);
	    break;

	case 's':
	    Synchronous = 1;
	    /* Pass the Synchronous option on to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -s");
	    break;

	case 'f':
	    if (sscanf(optarg, "%x:%x", &discoveryType, &sessionType) != 2) {
		fprintf(stderr, "Illegal argument to -f: Should be disc:sess in hex\n");
		exit(EXIT_FAILURE);
	    }
	    Eth_PPPOE_Discovery = (UINT16_t) discoveryType;
	    Eth_PPPOE_Session   = (UINT16_t) sessionType;
	    /* This option gets passed to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -%c %s", opt, optarg);
	    break;

	case 'F':
	    beDaemon = 0;
	    break;

	case 'N':
	    if (sscanf(optarg, "%d", &opt) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (opt <= 0) {
		fprintf(stderr, "-N: Value must be positive\n");
		exit(EXIT_FAILURE);
	    }
	    NumSessionSlots = opt;
	    break;

	case 'O':
	    SET_STRING(pppoptfile, optarg);
	    break;

	case 'o':
	    if (sscanf(optarg, "%d", &opt) != 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    if (opt < 0) {
		fprintf(stderr, "-o: Value must be non-negative\n");
		exit(EXIT_FAILURE);
	    }
	    SessOffset = (size_t) opt;
	    break;

	case 'I':
	    if (NumInterfaces >= MAX_INTERFACES) {
		fprintf(stderr, "Too many -I options (max %d)\n",
			MAX_INTERFACES);
		exit(EXIT_FAILURE);
	    }
	    found = 0;
	    for (i=0; i<NumInterfaces; i++) {
		if (!strncmp(interfaces[i].name, optarg, IFNAMSIZ)) {
		    found = 1;
		    break;
		}
	    }
	    if (!found) {
		strncpy(interfaces[NumInterfaces].name, optarg, IFNAMSIZ);
		NumInterfaces++;
	    }
	    break;

	case 'C':
	    SET_STRING(ACName, optarg);
	    break;

	case 'L':
	case 'R':
	    /* Get local/remote IP address */
	    if (sscanf(optarg, "%d.%d.%d.%d", &d[0], &d[1], &d[2], &d[3]) != 4) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    for (i=0; i<IPV4ALEN; i++) {
		if (d[i] < 0 || d[i] > 255) {
		    usage(argv[0]);
		    exit(EXIT_FAILURE);
		}
		if (opt == 'L') {
		    LocalIP[i] = (unsigned char) d[i];
		} else {
		    RemoteIP[i] = (unsigned char) d[i];
		}
	    }
	    break;

	case 'T':
	case 'm':
	    /* These just get passed to pppoe */
	    snprintf(PppoeOptions + strlen(PppoeOptions),
		     SMALLBUF-strlen(PppoeOptions),
		     " -%c %s", opt, optarg);
	    break;

	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	case '1':
#ifdef HAVE_LICENSE
	    MaxSessionsPerUser = 1;
#else
	    fprintf(stderr, "-1 option not valid.\n");
	    exit(1);
#endif
	    break;
	}
    }

    if (!pppoptfile) {
	pppoptfile = PPPOE_SERVER_OPTIONS;
    }

#ifdef HAVE_LICENSE
    License_SetVersion(SERVPOET_VERSION);
    License_ReadBundleFile("/etc/rp/bundle.txt");
    License_ReadFile("/etc/rp/license.txt");
    ServerLicense = License_GetFeature("PPPOE-SERVER");
    if (!ServerLicense) {
	fprintf(stderr, "License: GetFeature failed: %s\n",
		License_ErrorMessage());
	exit(1);
    }
#endif

#ifdef USE_LINUX_PACKET
#ifndef HAVE_STRUCT_SOCKADDR_LL
    fprintf(stderr, "The PPPoE server does not work on Linux 2.0 kernels.\n");
    exit(EXIT_FAILURE);
#endif
#endif

    if (!NumInterfaces) {
	strcpy(interfaces[0].name, DEFAULT_IF);
	NumInterfaces = 1;
    }

    if (!ACName) {
	ACName = malloc(HOSTNAMELEN);
	if (gethostname(ACName, HOSTNAMELEN) < 0) {
	    fatalSys("gethostname");
	}
    }

    /* If address pool filename given, count number of addresses */
    if (addressPoolFname) {
	NumSessionSlots = parseAddressPool(addressPoolFname, 0);
	if (CheckPoolSyntax) {
	    printf("%lu\n", (unsigned long) NumSessionSlots);
	    exit(0);
	}
    }

    /* Max 65534 - SessOffset sessions */
    if (NumSessionSlots + SessOffset > 65534) {
	fprintf(stderr, "-N and -o options must add up to at most 65534\n");
	exit(EXIT_FAILURE);
    }

    /* Allocate memory for sessions */
    Sessions = calloc(NumSessionSlots, sizeof(ClientSession));
    if (!Sessions) {
	rp_fatal("Cannot allocate memory for session slots");
    }

    /* Fill in local addresses first (let pool file override later */
    for (i=0; i<NumSessionSlots; i++) {
	memcpy(Sessions[i].myip, LocalIP, sizeof(LocalIP));
	if (IncrLocalIP) {
	    incrementIPAddress(LocalIP);
	}
    }

    /* Fill in remote IP addresses from pool (may also overwrite local ips) */
    if (addressPoolFname) {
	(void) parseAddressPool(addressPoolFname, 1);
    }

    /* For testing -- generate sequential remote IP addresses */
    for (i=0; i<NumSessionSlots; i++) {
	Sessions[i].pid = 0;
	Sessions[i].funcs = &DefaultSessionFunctionTable;
	Sessions[i].sess = htons(i+1+SessOffset);

	if (!addressPoolFname) {
	    memcpy(Sessions[i].peerip, RemoteIP, sizeof(RemoteIP));
#ifdef HAVE_LICENSE
	    memcpy(Sessions[i].realpeerip, RemoteIP, sizeof(RemoteIP));
#endif
	    incrementIPAddress(RemoteIP);
	}
    }

    /* Initialize our random cookie.  Try /dev/urandom; if that fails,
       use PID and rand() */
    fp = fopen("/dev/urandom", "r");
    if (fp) {
	unsigned int x;
	fread(&x, 1, sizeof(x), fp);
	srand(x);
	fread(&CookieSeed, 1, SEED_LEN, fp);
	fclose(fp);
    } else {
	srand((unsigned int) getpid() * (unsigned int) time(NULL));
	CookieSeed[0] = getpid() & 0xFF;
	CookieSeed[1] = (getpid() >> 8) & 0xFF;
	for (i=2; i<SEED_LEN; i++) {
	    CookieSeed[i] = (rand() >> (i % 9)) & 0xFF;
	}
    }

    if (RandomizeSessionNumbers) {
	int *permutation;
	int tmp;
	permutation = malloc(sizeof(int) * NumSessionSlots);
	if (!permutation) {
	    fprintf(stderr, "Could not allocate memory to randomize session numbers\n");
	    exit(EXIT_FAILURE);
	}
	for (i=0; i<NumSessionSlots; i++) {
	    permutation[i] = i;
	}
	for (i=0; i<NumSessionSlots-1; i++) {
	    j = i + rand() % (NumSessionSlots - i);
	    if (j != i) {
		tmp = permutation[j];
		permutation[j] = permutation[i];
		permutation[i] = tmp;
	    }
	}
	/* Link sessions together */
	FreeSessions = &Sessions[permutation[0]];
	LastFreeSession = &Sessions[permutation[NumSessionSlots-1]];
	for (i=0; i<NumSessionSlots-1; i++) {
	    Sessions[permutation[i]].next = &Sessions[permutation[i+1]];
	}
	Sessions[permutation[NumSessionSlots-1]].next = NULL;
	free(permutation);
    } else {
	/* Link sessions together */
	FreeSessions = &Sessions[0];
	LastFreeSession = &Sessions[NumSessionSlots - 1];
	for (i=0; i<NumSessionSlots-1; i++) {
	    Sessions[i].next = &Sessions[i+1];
	}
	Sessions[NumSessionSlots-1].next = NULL;
    }

    if (Debug) {
	/* Dump session array and exit */
	ClientSession *ses = FreeSessions;
	while(ses) {
	    printf("Session %u local %d.%d.%d.%d remote %d.%d.%d.%d\n",
		   (unsigned int) (ntohs(ses->sess)),
		   ses->myip[0], ses->myip[1],
		   ses->myip[2], ses->myip[3],
		   ses->peerip[0], ses->peerip[1],
		   ses->peerip[2], ses->peerip[3]);
	    ses = ses->next;
	}
	exit(0);
    }

    /* Open all the interfaces */
    for (i=0; i<NumInterfaces; i++) {
  printf("%s:%d:open pppoe interface :%s \n",__FILE__,__LINE__,interfaces[i].name);
	interfaces[i].sock = openInterface(interfaces[i].name, Eth_PPPOE_Discovery, interfaces[i].mac);
    }

    printf("interfce name = %s, number_interface= %d\r\n", interfaces[0].name, NumInterfaces);

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);

    /* Create event selector */
    event_selector = Event_CreateSelector();
    if (!event_selector) {
	rp_fatal("Could not create EventSelector -- probably out of memory");
    }
    printf("here1\r\n");

    /* Set signal handlers for SIGTERM and SIGINT */
    if (Event_HandleSignal(event_selector, SIGTERM, termHandler) < 0 ||
	Event_HandleSignal(event_selector, SIGINT, termHandler) < 0) {
	fatalSys("Event_HandleSignal");
    }

    printf("here2\r\n");

    /* Control channel */
#ifdef HAVE_LICENSE
    if (control_init(argc, argv, event_selector)) {
	rp_fatal("control_init failed");
    }
#endif

    /* Create event handler for each interface */
    for (i = 0; i<NumInterfaces; i++) {
	interfaces[i].eh = Event_AddHandler(event_selector,
					    interfaces[i].sock,
					    EVENT_FLAG_READABLE,
					    InterfaceHandler,
					    &interfaces[i]);
	printf("interfaces[%d]:%p  Socket:%d\n\r",i,&interfaces[i],interfaces[i].sock);
#ifdef HAVE_L2TP
	interfaces[i].session_sock = -1;
#endif
	if (!interfaces[i].eh) {
	    rp_fatal("Event_AddHandler failed");
	}
    }

    printf("here3\r\n");

#ifdef HAVE_LICENSE
    if (use_clustering) {
	ClusterLicense = License_GetFeature("PPPOE-CLUSTER");
	if (!ClusterLicense) {
	    fprintf(stderr, "License: GetFeature failed: %s\n",
		    License_ErrorMessage());
	    exit(1);
	}
	if (!License_Expired(ClusterLicense)) {
	    if (cluster_init(event_selector) < 0) {
		rp_fatal("cluster_init failed");
	    }
	}
    }
#endif

#ifdef HAVE_L2TP
    for (i=0; i<NumInterfaces; i++) {
	pppoe_to_l2tp_add_interface(event_selector,
				    &interfaces[i]);
    }
#endif

    printf("here4\r\n");

    /* Daemonize -- UNIX Network Programming, Vol. 1, Stevens */
    if (beDaemon) {
	i = vfork();
	if (i < 0) {
	    fatalSys("fork");
	} else if (i != 0) {
	    /* parent */
	    exit(EXIT_SUCCESS);
	}
	setsid();
	signal(SIGHUP, SIG_IGN);
	i = vfork();
	if (i < 0) {
	    fatalSys("fork");
	} else if (i != 0) {
	    exit(EXIT_SUCCESS);
	}

	chdir("/");

	/* Point stdin/stdout/stderr to /dev/null */
	for (i=0; i<3; i++) {
	    close(i);
	}
	i = open("/dev/null", O_RDWR);
	if (i >= 0) {
	    dup2(i, 0);
	    dup2(i, 1);
	    dup2(i, 2);
	    if (i > 2) close(i);
	}
    }

    printf("here5\r\n");

    for(;;) {
	i = Event_HandleEvent(event_selector);
	if (i < 0) {
			printf("Event_HandleEvent :return error\n");
	    fatalSys("Event_HandleEvent");
	}

#ifdef HAVE_LICENSE
	if (License_Expired(ServerLicense)) {
	    syslog(LOG_INFO, "Server license has expired -- killing all PPPoE sessions");
	    killAllSessions();
	    control_exit();
	    exit(0);
	}
#endif
    }
    printf("here6\r\n");

    return 0;
}

void
serverProcessPacket(Interface *i)
{
    int len;
    PPPoEPacket packet;
    int sock = i->sock;

    printf("Receive the packet out\r\n");
    printf("Received Interface :%p\r\n",i);	
	
    if (receivePacket(sock, &packet, &len) < 0) {
    	printf("socket No error:%d\n",sock);
	printf("Can't receive packet\r\n");
	return;
    }

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	/*syslog(LOG_INFO, "Bogus PPPoE length field (%u)",
	       (unsigned int) ntohs(packet.length));*/
	printf("Packet length error: packet.length=%d, HDR_SIZE=%d, len=%d",ntohs(packet.length),HDR_SIZE,len);
	return;
    }

    printf("serverProcessPacket received the packet\r\n");
    /* Sanity check on packet */
    if (packet.ver != 1 || packet.type != 1) {
	/* Syslog an error */
	return;
    }

    printf("serverProcessPacket parse the packet\r\n");
    switch(packet.code) {
    case CODE_PADI:
	printf("Received PADI packet\r\n");
	processPADI(i, &packet, len);
	break;
    case CODE_PADR:
	printf("Received PADR packet:socket:%d\r\n",sock);
	processPADR(i, &packet, len);
	printf("Process PADR Return\r\n");
	break;
    case CODE_PADT:
	/* Kill the child */
	printf("Received PADT packet\r\n");
	processPADT(i, &packet, len);
	break;
    case CODE_SESS:
	/* Ignore SESS -- children will handle them */
	printf("Received SESS packet\r\n");
	break;
    case CODE_PADO:
    case CODE_PADS:
	/* Ignore PADO and PADS totally */
	printf("Received PADO-PADS packet\r\n");
	break;
    default:
	/* Syslog an error */
	printf("Received UNKNOWN packet\r\n");
	break;
    }
}

/**********************************************************************
*%FUNCTION: sendErrorPADS
*%ARGUMENTS:
* sock -- socket to write to
* source -- source Ethernet address
* dest -- destination Ethernet address
* errorTag -- error tag
* errorMsg -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet with an error message
***********************************************************************/
void
sendErrorPADS(int sock,
	      unsigned char *source,
	      unsigned char *dest,
	      int errorTag,
	      char *errorMsg)
{
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    UINT16_t plen;
    PPPoETag err;
    int elen = strlen(errorMsg);

    memcpy(pads.ethHdr.h_dest, dest, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, source, ETH_ALEN);
    pads.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    pads.ver = 1;
    pads.type = 1;
    pads.code = CODE_PADS;

    pads.session = htons(0);
    plen = 0;

    err.type = htons(errorTag);
    err.length = htons(elen);

    memcpy(err.payload, errorMsg, elen);
    memcpy(cursor, &err, TAG_HDR_SIZE+elen);
    cursor += TAG_HDR_SIZE + elen;
    plen += TAG_HDR_SIZE + elen;

    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(NULL, sock, &pads, (int) (plen + HDR_SIZE));
}

/**********************************************************************
*%FUNCTION: startGPRSPPPD
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD for user-mode PPPoE
***********************************************************************/
#ifdef CONFIG_FEATURE_PPP_BRIDGE
pid_t startGPRSPPPD(void)
{
pid_t child=0;
char *argv[32];   	
int c = 0;

	printf("startGPRSPPPD been called.\n");
	//system("autoconn3G.sh connect &");

    	/* in child thread */
	if(setsid()<0) /* avoid pppd to kill us */
		perror("Setsid:");

        printf("startGPRSPPPD child thread success.\n"); 
	argv[c++] = "/sbin/autoconn3G.sh";
	argv[c++] = "connect";
	argv[c++] = "&";

	execv( argv[0], argv );
	printf("error open pppd\n"); 	
	exit(EXIT_FAILURE);

    	/* in parent thread */
    	return child;
}

#if 0
pid_t
startGPRSPPPD(void)
{
    pid_t child=0;

	//YDChao, July 13
	system("/bin/route del default gw 0.0.0.0 dev eth0");

    printf("startGPRSPPPD been called.\n"); 
    /*
    child = vfork();
    if (child < 0) {
    	return 0;
    }
    
    if (child == 0) */{
char *argv[32];   	
int c = 0;
const char *user = nvram_bufget(RT2860_NVRAM, "wan_3g_user");
const char *passwd = nvram_bufget(RT2860_NVRAM, "wan_3g_pass");

    	/* in child thread */
	if(setsid()<0) /* avoid pppd to kill us */
		perror("Setsid:");

       printf("startGPRSPPPD child thread success.\n"); 
	argv[c++] = "pppd";
	
	//modify by mhho
	argv[c++] = "/dev/ttyUSB2"; //if system use U6100, low cost 3G Modem .
	///<----------------------------------------------------------
	//argv[c++] = "/dev/ttyUSB3"; //if system use U6100 .
	///argv[c++] = "/dev/ttyS1"; //if system use SIM900 Modem .
	//end of modify
	
	//argv[c++] = "38400";
	argv[c++] = "921600";	//<--------------------------------
	///argv[c++] = "115200";//if system use SIM900 Modem 
	//argv[c++] = "sync";	
	argv[c++] = NULL;

	argv[c++] = "name";
	argv[c++] = "MyName";	


	argv[c++] = "debug"; 
	//argv[c++] = "lock";
	argv[c++] = "modem";
	//argv[c++] = "nocrtscts";
	//argv[c++] = "asyncmap";
	//argv[c++] = "20A0000";
	//argv[c++] = "escape";
	//argv[c++] = "FF";
	/*argv[c++] = "kdebug";
	argv[c++] = "1";*/
	//argv[c++] = "0.0.0.0:0.0.0.0";
	//argv[c++] = "noipdefault";
	argv[c++] = "usepeerdns";
	argv[c++] = "persist";
	//argv[c++] = "netmask";
	//argv[c++] = "255.255.255.0";
	argv[c++] = "defaultroute";

	argv[c++] = "nodetach";
	argv[c++] = "noauth"; 
	argv[c++] = "novj";
	argv[c++] = "noccp";
	argv[c++] = "novjccomp";
	argv[c++] = "nopcomp";
	argv[c++] = "noaccomp";
	
	argv[c++] = "connect";
	argv[c++] = "/bin/chat -v -s -f /etc/ppp/chat_script";
	//argv[c++] = "/etc/ppp/ppp-on-gprs-dialer";
	//argv[c++] = "disconnect";
	//argv[c++] = "/etc/ppp/ppp-off-gprs";
	//argv[c++] = "unit";
	//argv[c++] = "0";
	argv[c++] = NULL;
	
	/* begin to establish the GRPS connection */
  printf("eec GPRS pppd \n"); 
	execv(PPPD_PATH, argv);
	//system("pppd /dev/ttyUSB3 name MyName nodetach modem debug noauth persist novj noccp novjccomp nopcomp noaccomp connect \"/bin/chat -v -s -f /etc/ppp/chat_script\"");
	printf("erroe open  GPRS pppd \n"); 	
	//_exit(EXIT_FAILURE);
	exit(EXIT_FAILURE);
    }

    /* in parent thread */
    return child;
    //return getpid();
}

typedef struct server_config_message_t {
	unsigned short magic_number;	/* magic number to identify this message, here set to 0xAbCd */
	unsigned short message_type;	/* config message type, to extend, now define only one message DHCPD_POOL_UPDATE */
	unsigned long  host_address;	/* host address, 0 means invalid, in big-endian */
	unsigned long  gw_address;	/* gateway address, 0 means invalid, in big-endian */
	unsigned long  dns1_address;	/* dns-1 address */
	unsigned long  dns2_address;	/* dns-2 address */
	unsigned long  wins1_address;	/* wins-1 address */
	unsigned long  wins2_address;	/* wins-2 address */
} server_cfg_msg;
#else

#define DHCPD_CFG_MAGIC		0xAbCd

#define DHCPD_POOL_UPDATE		0x0001
#define DHCPD_ETH_UPDATE		0x0002
#define DHCPD_STATE_EVENT		0x0003
#define DHCPD_CONTROL_MSG		0x0004
#define DHCPD_PPP_DISCONNCET	0x0005
#define DHCPD_PPP_CONNECT_FAIL	0x0006

#define SERVER_CTL_PORT 	6700

typedef enum eControlType
{
	CTRL_MSG_PPPOE_LOCK,
	CTRL_MSG_PPPOE_UNLOCK
}CONTROL_TYPE;

typedef enum eFSM_EVENT 
{
	FSM_EVENT_TIMEOUT = 0,
	FSM_EVENT_ROUTER_IDENTIFY,
	FSM_EVENT_DHCP_LINK_DOWN_OR_LEASE_EXPIRE,
	FSM_EVENT_PPP_CONNECTED,
	FSM_EVENT_PPP_DISCONNECT,
	FSM_EVENT_PPP_CONNECT_FAIL
}FSM_EVENT;

typedef 	union u_msg_data {
	struct s_eth_data {
		unsigned long eth_peer_ipaddr;
		unsigned char eth_peer_mac[6];
		unsigned char expire;	/* the address expired ? */
		unsigned char link_down; /* the ethernet link down ? */
	}eth;
	
	struct s_ppp_data {
		unsigned long peer_ipaddr;
		unsigned long local_ipaddr;
		unsigned char reason[32];
	}ppp;
}__attribute__ ((packed))STATE_MSG_DATA;

typedef struct server_config_message_t {
	unsigned short magic_number;	/* magic number to identify this message, here set to 0xAbCd */
	unsigned short message_type;	/* config message type, to extend, now define only one message DHCPD_POOL_UPDATE */

	union {
		struct s_ppp {
			unsigned long  host_address;	/* host address, 0 means invalid, in big-endian */
			unsigned long  gw_address;	/* gateway address, 0 means invalid, in big-endian */
			unsigned long  dns1_address;	/* dns-1 address */
			unsigned long  dns2_address;	/* dns-2 address */
			unsigned long  wins1_address;	/* wins-1 address */
			unsigned long  wins2_address;	/* wins-2 address */
		}ppp_if_info;

		struct s_msg {
			FSM_EVENT event;
			STATE_MSG_DATA data;
		}msg;
		
		struct s_ctrl {
			CONTROL_TYPE ctrl_type;
		}ctrl;

		unsigned char disconnect_reason[32];
	}data;
#define state_event	data.msg.	event
#define state_data	data.msg.data
#define ctrl_type		data.ctrl.ctrl_type
}__attribute__ ((packed)) server_cfg_msg;
#endif

int server_ctl_socket = -1;

int control_socket(unsigned int ip, int port)
{
	int fd;
	struct sockaddr_in addr;
	int n = 1;

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		return -1;
	}
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ip;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &n, sizeof(n)) == -1) {
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1) {
		close(fd);
		return -1;
	}
	
	return fd;
}

int raise_state_event( FSM_EVENT event, void *data )
{
	server_cfg_msg cfg_msg;
	struct sockaddr_in dst_addr;		
	static int udhcpd_ctrl_socket;

	if ((FSM_EVENT_PPP_CONNECTED != event) && (FSM_EVENT_PPP_DISCONNECT != event))
		return -1;
	
	if ((udhcpd_ctrl_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		return -1;
	}

	/* fill the message */			
	memset(&cfg_msg, 0x0, sizeof(cfg_msg));
	cfg_msg.magic_number = DHCPD_CFG_MAGIC;
	cfg_msg.message_type = DHCPD_STATE_EVENT;
	cfg_msg.state_event = event;
	memcpy(&cfg_msg.state_data, data, sizeof(STATE_MSG_DATA) );
	
	/* send the message to local-host */
	memset(&dst_addr, 0x0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(SERVER_CTL_PORT);
	dst_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	
	if (sendto(udhcpd_ctrl_socket, (char *)&cfg_msg, sizeof(cfg_msg), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0) {
		close(udhcpd_ctrl_socket);
		return -1;
	}
	
	close(udhcpd_ctrl_socket);

	//YDChao, June 11
	printf("pppoe-server, TX: raise_state_event=%d.\n", event);
	
	return 0;
}
//Add by mhho for btap
int IP2String(unsigned long ulIP, char *pcStringOut)
{
	int iRt;
	if (pcStringOut == NULL) return -1;

	bzero(pcStringOut, 16);

	iRt = sprintf(pcStringOut, "%u.%u.%u.%u",
		(unsigned int)(ulIP & 0x000000FF),
		(unsigned int)((ulIP>>8) & 0x000000FF),
		(unsigned int)((ulIP>>16) & 0x000000FF),
		(unsigned int)((ulIP>>24) & 0x000000FF));
	return iRt;
}

int SetATCommandFromNet(char *CMD,int wait,char *Ret,int *rlen)	
{
        struct sockaddr_in clntaddr;
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if((sockfd)<0) { printf("socket Error\n"); return 0;}
        //set Net Address which contain IP & Port
        memset(&clntaddr, 0, sizeof(clntaddr));
        clntaddr.sin_family = AF_INET;
        clntaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        clntaddr.sin_port =htons(60000);

	 if(sendto(sockfd,CMD,strlen(CMD),0,(struct sockaddr *) &clntaddr,sizeof(struct sockaddr))<0)
	 {
	 	perror("SetATCommandFromNet:sendto:");	
		*rlen=0;
		close(sockfd);		
		return -1;
	 }

	struct sockaddr_in stFrom;	
       fd_set readSocket;
	struct timeval tv;	   	
	tv.tv_sec=wait;
	tv.tv_usec=0;   
	if(wait<0) 
	{
		*rlen=0;
		close(sockfd);				
		return -1;
	}
	
	FD_ZERO(&readSocket);
	FD_SET(sockfd, &readSocket);
	int iRet = select(sockfd+1,&readSocket, NULL,NULL,&tv);  
	if(iRet<0)
	{	  	
	 	perror("SetATCommandFromNet:select:");	
		*rlen=0;
		close(sockfd);				
		return -1;
	 }
	else if(iRet==0)
	{
		*rlen=0;
		close(sockfd);				
		printf("SetATCommandFromNet:select:Time out ..\n");
		return 0;

	}
		

	int iAddrLen=sizeof(struct sockaddr_in);
	
	int iRecvLen=recvfrom(sockfd,Ret,*rlen,0,(struct sockaddr *)&stFrom,(socklen_t*)&iAddrLen);
	if(iRecvLen<0) 
	{
		perror("SetATCommandFromNet:RecvFrom:");	
		*rlen=0;
		close(sockfd);
		return -1;
	}
	*rlen=iRecvLen;
	printf("pppoe-server, Recv AT return Len:%d Data:%s\n", iRecvLen, Ret);
	close(sockfd);
	return iRecvLen;
}

 static int IsIntDigit(char *pcStr)
{
	char *pc;
	for (pc=pcStr; *pc!='\0'; pc++)
	{
		if (*pc > '\40' && (*pc < '0' || *pc > '9')) return 0;
	}
	return 1;
}


#define READ_BUF_SIZE	50
pid_t* FindPidByName(char* pcPidName)
{
	DIR *dir;
	struct dirent *next;
	pid_t* pidList=NULL;
	int i=0;

	dir = opendir("/proc");
	if (!dir)
	{
		fprintf(stderr, "Cannot open /proc");//CXH_MODIFY
		return NULL;
	}

	while ((next = readdir(dir)) != NULL)
	{
		FILE *status;
		char filename[READ_BUF_SIZE];
		char buffer[READ_BUF_SIZE];
		char name[READ_BUF_SIZE];

		/* If it isn't a number, we don't want it */
		//if (!isdigit(*next->d_name)) continue;

		if (!IsIntDigit(next->d_name)) continue;//CXH_MODIFY

		sprintf(filename, "/proc/%s/status", next->d_name);
		if (! (status = fopen(filename, "r")) ) {
			continue;
		}
		if (fgets(buffer, READ_BUF_SIZE-1, status) == NULL) {
			fclose(status);
			continue;
		}
		fclose(status);

		/* Buffer should contain a string like "Name:   binary_name" */
		sscanf(buffer, "%*s %s", name);
		if (strncmp(name, pcPidName,strlen(pcPidName)) == 0) {
			pidList=realloc( pidList, sizeof(pid_t) * (i+2));
			pidList[i++]=strtol(next->d_name, NULL, 0);
		}
	}

	closedir(dir);//CXH_MODIFY

	if (pidList)
		pidList[i]=0;
	return pidList;
}

//End of add


int
wait_gprs_pppd_established(ClientSession *session)
{
	fd_set waitfd;
	server_cfg_msg	cfg_msg;
	struct timeval abs_timeout;
	struct sockaddr saddr;
	STATE_MSG_DATA msg_data;
	
#define PPPOE_CTRL_PORT 6800

	int salen = sizeof(saddr);
	int r = 0;

	/* Avoid compiler warning */
	abs_timeout.tv_sec = 100;
	abs_timeout.tv_usec = 0;

	FD_ZERO(&waitfd);

	/* This socket is used to control the udhcpd behave by other process, such as pppd */
	if ((server_ctl_socket = control_socket(INADDR_ANY, PPPOE_CTRL_PORT)) < 0)
	{
		syslog(LOG_WARNING, "PPPOE_CTRL_PORT control_socket failed!");
		return -1;
	}	
	
	FD_SET(server_ctl_socket, &waitfd);
	
printf("%s:%d, time:%d\n",__FILE__,__LINE__, time(0));    
	r = select(server_ctl_socket+1, &waitfd, NULL, NULL, &abs_timeout);
printf("%s:%d \n",__FILE__,__LINE__);    	
	if (r < 0)
        {
    printf("select error... \n");
    //pppoe_free_session(session);
		close(server_ctl_socket);
		return -1;
        }
printf("%s:%d :select ret:%d\n",__FILE__,__LINE__,r);            
	if(r==0)
	{
		//sleep(5);
    /* stop the gprs pppd thread */
    /*		
    PPPoEConnection conn;
    memset(&conn, 0, sizeof(conn));
    conn.useHostUniq = 0;

    memcpy(conn.myEth, session->ethif->mac, ETH_ALEN);
    conn.discoverySocket = session->ethif->sock;
    conn.session = session->sess;
    memcpy(conn.peerEth, session->eth, ETH_ALEN);
    sendPADT(&conn, "Dial UP 3G timeout");
    session->flags |= FLAG_SENT_PADT;
    */
		printf("3G pppd section kill :%d, time=%d\n",session->gpid, time(0));    
    if (session->gpid) {
			kill(session->gpid, SIGTERM);
			//session->gpid=0;
		}
		/*
		wait(NULL);
		pppoe_free_session(session);
		close(server_ctl_socket);
		*/
 		return -1;
	}
	if (recvfrom (server_ctl_socket, &cfg_msg, sizeof(cfg_msg), 0, &saddr, &salen))
	{
printf("%s:%d, RX:cfg_msg.message_type=%d\n",__FILE__,__LINE__,cfg_msg.message_type);    			
		/* Received something */
		int iTmp;
		switch(cfg_msg.message_type)
		{
			case DHCPD_POOL_UPDATE:
				for (iTmp = 0; iTmp < 4; iTmp ++)
					session->myip[iTmp] = ((unsigned char*)&(cfg_msg.data.ppp_if_info.gw_address))[iTmp];

				for (iTmp = 0; iTmp < 4; iTmp ++)
					session->peerip[iTmp] = ((unsigned char*)&(cfg_msg.data.ppp_if_info.host_address))[iTmp];

				if (cfg_msg.data.ppp_if_info.dns1_address != 0)
				{
					for (iTmp = 0; iTmp < 4; iTmp ++)
						session->dns[iTmp] = ((unsigned char*)&(cfg_msg.data.ppp_if_info.dns1_address))[iTmp];
				}

				if (cfg_msg.data.ppp_if_info.wins1_address != 0)
				{
					for (iTmp = 0; iTmp < 4; iTmp ++)
						session->wins[iTmp] = ((unsigned char*)&(cfg_msg.data.ppp_if_info.wins1_address))[iTmp];
				}

				/* Raise the event */
				memset(&msg_data, 0, sizeof(msg_data));
				msg_data.ppp.peer_ipaddr = cfg_msg.data.ppp_if_info.gw_address;
				msg_data.ppp.local_ipaddr = cfg_msg.data.ppp_if_info.host_address;
				sprintf(msg_data.ppp.reason, "PPP Connection Established");
				
				raise_state_event(FSM_EVENT_PPP_CONNECTED, &msg_data);
				break;

			case DHCPD_PPP_DISCONNCET:
				killAllSessions();
				break;

			#if 0	
			case DHCPD_PPP_DISCONNCET:
			case DHCPD_PPP_CONNECT_FAIL:
				memset(&msg_data, 0, sizeof(msg_data));
				strcpy(msg_data.ppp.reason, cfg_msg.data.disconnect_reason);
				
				raise_state_event((cfg_msg.message_type == DHCPD_PPP_DISCONNCET)?
								FSM_EVENT_PPP_DISCONNECT: FSM_EVENT_PPP_CONNECT_FAIL, 
								&msg_data);
				break;

			case DHCPD_CONTROL_MSG:
				if (cfg_msg.data.ctrl.ctrl_type == CTRL_MSG_PPPOE_UNLOCK)
				{
					/* unlock */
					pppoe_connection_lock = FALSE;
				}
				else
				{
					/* lock */
					pppoe_connection_lock = TRUE;
				}
				break;
			#endif
			default:
				break;
		}
	}
	
	close(server_ctl_socket);
		
/*		pid_t *pidlist;  

		 char cret[64]={0};
		 int iretlen=64;
		 char *pret1;
		 char *pret2;

		 pidlist=FindPidByName("LedConnect");
		int ret=SetATCommandFromNet("AT+PSRAT",5,cret,&iretlen);	
		
		if(ret>0)
		{
			pret1=strstr(cret,"PSRAT:");
			pret2=strstr(pret1,"\r\n");
			*pret2=0;
			if((pret1[7]=='H')||(pret1[7]=='U'))
			{
				printf("PPP_IPCP_3G detected!!\n");	
				if(pidlist[0])
	  		       kill(pidlist[0],SIGUSR2);				
			}
			else
			{
				printf("PPP_IPCP_2G detected!!\n");			
				if(pidlist[0])				
	  		       kill(pidlist[0],SIGUSR1);								
			}
		}
		else
		{
			printf("Get Connect State error..\n");
		}  
*/	
/*	{//pppd defaultroute does not work every time, so we add default gateway.
	struct ifreq ifr;
	int fd;
	unsigned long ulIP;
	char cCMD[96], cbfr[16];

		if( (fd = socket(AF_INET,SOCK_DGRAM,0)) < 0)
			return -1;
	
		strcpy(ifr.ifr_name, "ppp0");
		if( ioctl(fd, SIOCGIFADDR, &ifr) < 0 )
			return -1;
		else
		ulIP = (*(struct sockaddr_in *)&(ifr.ifr_addr)).sin_addr.s_addr;

		sprintf( cbfr, "%s", inet_ntoa(ulIP) );
		sprintf( cCMD, "/bin/route add -net default gw %s dev ppp0", cbfr );
	printf("___> %s\n", cCMD);
		system( cCMD );
	}	
*/	
	return 0;
}
#endif

/**********************************************************************
*%FUNCTION: startPPPDUserMode
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD for user-mode PPPoE
***********************************************************************/
void
startPPPDUserMode(ClientSession *session)
{
    /* Leave some room */
    char *argv[32];

    char buffer[SMALLBUF];

    int c = 0;

    argv[c++] = "pppd";
    argv[c++] = "pty";

    /* Let's hope service-name does not have ' in it... */
    snprintf(buffer, SMALLBUF, "%s -n -I %s -e %u:%02x:%02x:%02x:%02x:%02x:%02x %s -S '%s'",
	     PPPOE_PATH, session->ethif->name,
	     (unsigned int) ntohs(session->sess),
	     session->eth[0], session->eth[1], session->eth[2],
	     session->eth[3], session->eth[4], session->eth[5],
	     PppoeOptions, session->serviceName);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }
/*
    argv[c++] = "file";
    argv[c++] = pppoptfile;
*/
    snprintf(buffer, SMALLBUF, "%d.%d.%d.%d:%d.%d.%d.%d",
	    (int) session->myip[0], (int) session->myip[1],
	    (int) session->myip[2], (int) session->myip[3],
	    (int) session->peerip[0], (int) session->peerip[1],
	    (int) session->peerip[2], (int) session->peerip[3]);
    syslog(LOG_INFO,
	   "Session %u created for client %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s using Service-Name '%s'",
	   (unsigned int) ntohs(session->sess),
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   (int) session->peerip[0], (int) session->peerip[1],
	   (int) session->peerip[2], (int) session->peerip[3],
	   session->ethif->name,
	   session->serviceName);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }

    if (session->dns[0] != 0)
     {
    	    argv[c++] = "ms-dns";
	    snprintf(buffer, SMALLBUF, "%d.%d.%d.%d",
		    (int) session->dns[0], (int) session->dns[1],
		    (int) session->dns[2], (int) session->dns[3]);
    	    argv[c++] = strdup(buffer);
     }
    else
     {
    	    argv[c++] = "ms-dns";
	    snprintf(buffer, SMALLBUF, "202.106.0.20");
    	    argv[c++] = strdup(buffer);
     }


    if (session->wins[0] != 0)
     {
    	    argv[c++] = "ms-wins";
	    snprintf(buffer, SMALLBUF, "%d.%d.%d.%d",
		    (int) session->wins[0], (int) session->wins[1],
		    (int) session->wins[2], (int) session->wins[3]);
    	    argv[c++] = strdup(buffer);
     }

    argv[c++] = "nodetach";
    argv[c++] = "noaccomp";
    argv[c++] = "nobsdcomp";
    argv[c++] = "nodeflate";
    argv[c++] = "nopcomp";
    argv[c++] = "novj";
    argv[c++] = "novjccomp";
    argv[c++] = "default-asyncmap";

    argv[c++] = "lcp-echo-interval";
		argv[c++] = "10";    
    argv[c++] = "lcp-echo-failure";        
		argv[c++] = "4";        
    
    if (Synchronous) {
	argv[c++] = "sync";
    }
    if (PassUnitOptionToPPPD) {
	argv[c++] = "unit";
	sprintf(buffer, "%u", (unsigned int) (ntohs(session->sess) - 1 - SessOffset));
	argv[c++] = buffer;
    }

    argv[c++] = "debug";
    argv[c++] = NULL;

    execv(PPPD_PATH, argv);
    //_exit(EXIT_FAILURE);
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: startPPPDLinuxKernelMode
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD for kernel-mode PPPoE on Linux
***********************************************************************/
void
startPPPDLinuxKernelMode(ClientSession *session)
{
    /* Leave some room */
    char *argv[32];

    int c = 0;

    char buffer[SMALLBUF];

    argv[c++] = "pppd";
    //argv[c++] = "plugin";
    //argv[c++] = PLUGIN_PATH;

    /* Add "nic-" to interface name */
    snprintf(buffer, SMALLBUF, "nic-%s", session->ethif->name);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	exit(EXIT_FAILURE);
    }

    snprintf(buffer, SMALLBUF, "%u:%02x:%02x:%02x:%02x:%02x:%02x",
	     (unsigned int) ntohs(session->sess),
	     session->eth[0], session->eth[1], session->eth[2],
	     session->eth[3], session->eth[4], session->eth[5]);
    argv[c++] = "rp_pppoe_sess";
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }
    argv[c++] = "rp_pppoe_service";
    argv[c++] = (char *) session->serviceName;
    argv[c++] = "file";
    argv[c++] = pppoptfile;

    snprintf(buffer, SMALLBUF, "%d.%d.%d.%d:%d.%d.%d.%d",
	    (int) session->myip[0], (int) session->myip[1],
	    (int) session->myip[2], (int) session->myip[3],
	    (int) session->peerip[0], (int) session->peerip[1],
	    (int) session->peerip[2], (int) session->peerip[3]);
    syslog(LOG_INFO,
	   "Session %u created for client %02x:%02x:%02x:%02x:%02x:%02x (%d.%d.%d.%d) on %s using Service-Name '%s'",
	   (unsigned int) ntohs(session->sess),
	   session->eth[0], session->eth[1], session->eth[2],
	   session->eth[3], session->eth[4], session->eth[5],
	   (int) session->peerip[0], (int) session->peerip[1],
	   (int) session->peerip[2], (int) session->peerip[3],
	   session->ethif->name,
	   session->serviceName);
    argv[c++] = strdup(buffer);
    if (!argv[c-1]) {
	/* TODO: Send a PADT */
	exit(EXIT_FAILURE);
    }
    argv[c++] = "nodetach";
    argv[c++] = "noaccomp";
    argv[c++] = "nobsdcomp";
    argv[c++] = "nodeflate";
    argv[c++] = "nopcomp";
    argv[c++] = "novj";
    argv[c++] = "novjccomp";
    argv[c++] = "default-asyncmap";
    if (PassUnitOptionToPPPD) {
	argv[c++] = "unit";
	sprintf(buffer, "%u", (unsigned int) (ntohs(session->sess) - 1 - SessOffset));
	argv[c++] = buffer;
    }
    argv[c++] = NULL;
    execv(PPPD_PATH, argv);
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: startPPPD
*%ARGUMENTS:
* session -- client session record
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Starts PPPD
***********************************************************************/
void
startPPPD(ClientSession *session)
{
#if 0
//printf("%s:%d:Startpppd",__FILE__,LINE__);
   printf("startPPPD been called. UseLinuxKernelModePPPoE = %d\r\n",UseLinuxKernelModePPPoE); 
   pid_t child;

    printf("startPPPD been called.\n"); 
    child = vfork();
    if (child < 0) {
    	printf("error vfork startPPPD ..\n");
    	return ;
    }
    
    if (child != 0) 
    {
	session->pid = child;
	control_session_started(session);        	
	Event_HandleChildExit(event_selector, child, childHandler, session);
    	return;
    }

	if(setsid()<0) /* avoid pppd to kill us */
		perror("Setsid:");
#endif

//*    no further PPP react,		YDChao try if PC PPPoe client could negotiate with 3G PPP server
//RESULT: PPPoe packet can not go to the dialup PPP interface, need to strip PPPoe header and relay PPP packet 
    //setsid(); 
    if (UseLinuxKernelModePPPoE) startPPPDLinuxKernelMode(session);
    else startPPPDUserMode(session);
    //_exit(-1);
}

/**********************************************************************
* %FUNCTION: InterfaceHandler
* %ARGUMENTS:
*  es -- event selector (ignored)
*  fd -- file descriptor which is readable
*  flags -- ignored
*  data -- Pointer to the Interface structure
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a packet ready at an interface
***********************************************************************/
void
InterfaceHandler(EventSelector *es,
		 int fd,
		 unsigned int flags,
		 void *data)
{
    printf("InterfaceHandler been called.\r\n");
    serverProcessPacket((Interface *) data);
}

/**********************************************************************
* %FUNCTION: PppoeStopSession
* %ARGUMENTS:
*  ses -- the session
*  reason -- reason session is being stopped.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Kills pppd.
***********************************************************************/
extern int * i_Interface_socket;

static void
PppoeStopSession(ClientSession *ses,
		 char const *reason)
{
printf("Enter PppoeStopSession\n");
		
	i_Interface_socket=&(interfaces[0].sock);		
		
    /* Temporary structure for sending PADT's. */
    PPPoEConnection conn;

    memset(&conn, 0, sizeof(conn));
    conn.useHostUniq = 0;

    memcpy(conn.myEth, ses->ethif->mac, ETH_ALEN);
    conn.discoverySocket = ses->ethif->sock;
    conn.session = ses->sess;
	
    memcpy(conn.peerEth, ses->eth, ETH_ALEN);
    sendPADT(&conn, reason);
    ses->flags |= FLAG_SENT_PADT;

	//pppoe_free_session( ses );	//YDChao add


//* this kill will kill pppoe-server itself....???
printf("pppoe stop, section kill :%d \n",ses->pid);
    if (ses->pid) {
	kill(ses->pid, SIGTERM);
	//ses->pid=0;
    }    
//
    // stop the gprs pppd thread 
    
    //system("killall pppd");	//YDChao
        if( pid_GPRSpppd )
    	{
    		printf("(A)kill pid_GPRSpppd: %d\n", pid_GPRSpppd[0]);
    		kill( pid_GPRSpppd[0], SIGTERM );
    		free( pid_GPRSpppd );
    		pid_GPRSpppd = NULL;
    	}
    
///  ses->funcs = &DefaultSessionFunctionTable;	YDCHao delete
}

/**********************************************************************
* %FUNCTION: PppoeSessionIsActive
* %ARGUMENTS:
*  ses -- the session
* %RETURNS:
*  True if session is active, false if not.
***********************************************************************/
static int
PppoeSessionIsActive(ClientSession *ses)
{
    return (ses->pid != 0);
}

#ifdef HAVE_LICENSE
/**********************************************************************
* %FUNCTION: getFreeMem
* %ARGUMENTS:
*  None
* %RETURNS:
*  The amount of free RAM in kilobytes, or -1 if it could not be
*  determined
* %DESCRIPTION:
*  Reads Linux-specific /proc/meminfo file and extracts free RAM
***********************************************************************/
int
getFreeMem(void)
{
    char buf[512];
    int memfree=0, buffers=0, cached=0;
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return -1;

    while (fgets(buf, sizeof(buf), fp)) {
	if (!strncmp(buf, "MemFree:", 8)) {
	    if (sscanf(buf, "MemFree: %d", &memfree) != 1) {
		fclose(fp);
		return -1;
	    }
	} else if (!strncmp(buf, "Buffers:", 8)) {
	    if (sscanf(buf, "Buffers: %d", &buffers) != 1) {
		fclose(fp);
		return -1;
	    }
	} else if (!strncmp(buf, "Cached:", 7)) {
	    if (sscanf(buf, "Cached: %d", &cached) != 1) {
		fclose(fp);
		return -1;
	    }
	}
    }
    fclose(fp);
    /* return memfree + buffers + cached; */
    return memfree;
}
#endif

/**********************************************************************
* %FUNCTION: pppoe_alloc_session
* %ARGUMENTS:
*  None
* %RETURNS:
*  NULL if no session is available, otherwise a ClientSession structure.
* %DESCRIPTION:
*  Allocates a ClientSession structure and removes from free list, puts
*  on busy list
***********************************************************************/
ClientSession *
pppoe_alloc_session(void)
{
    ClientSession *ses = FreeSessions;
    if (!ses) return NULL;

    /* Remove from free sessions list */
    if (ses == LastFreeSession) {
	LastFreeSession = NULL;
    }
    FreeSessions = ses->next;

    /* Put on busy sessions list */
    ses->next = BusySessions;
    BusySessions = ses;

    /* Initialize fields to sane values */
    ses->funcs = &DefaultSessionFunctionTable;
    ses->pid = 0;
    ses->ethif = NULL;
    memset(ses->eth, 0, ETH_ALEN);
    ses->flags = 0;
    ses->startTime = time(NULL);
    ses->serviceName = "";
#ifdef HAVE_LICENSE
    memset(ses->user, 0, MAX_USERNAME_LEN+1);
    memset(ses->realm, 0, MAX_USERNAME_LEN+1);
    memset(ses->realpeerip, 0, IPV4ALEN);
#endif
#ifdef HAVE_L2TP
    ses->l2tp_ses = NULL;
#endif
    NumActiveSessions++;
    return ses;
}

/**********************************************************************
* %FUNCTION: pppoe_free_session
* %ARGUMENTS:
*  ses -- session to free
* %RETURNS:
*  0 if OK, -1 if error
* %DESCRIPTION:
*  Places a ClientSession on the free list.
***********************************************************************/
int
pppoe_free_session(ClientSession *ses)
{
    ClientSession *cur, *prev;

    cur = BusySessions;
    prev = NULL;
    while (cur) {
	if (ses == cur) break;
	prev = cur;
	cur = cur->next;
    }

    if (!cur) {
	syslog(LOG_INFO, "pppoe_free_session: Could not find session %p on busy list", (void *) ses);
	return -1;
    }

    /* Remove from busy sessions list */
    if (prev) {
	prev->next = ses->next;
    } else {
	BusySessions = ses->next;
    }

    /* Add to end of free sessions */
    ses->next = NULL;
    if (LastFreeSession) {
	LastFreeSession->next = ses;
	LastFreeSession = ses;
    } else {
	FreeSessions = ses;
	LastFreeSession = ses;
    }

    /* Initialize fields to sane values */
    ses->funcs = &DefaultSessionFunctionTable;
    ses->pid = 0;
    ses->flags = 0;
#ifdef HAVE_L2TP
    ses->l2tp_ses = NULL;
#endif
    NumActiveSessions--;
    return 0;
}

/**********************************************************************
* %FUNCTION: sendHURLorMOTM
* %ARGUMENTS:
*  conn -- PPPoE connection
*  url -- a URL, which *MUST* begin with "http://" or it won't be sent, or
*         a message.
*  tag -- one of TAG_HURL or TAG_MOTM
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Sends a PADM packet contaning a HURL or MOTM tag to the victim...er, peer.
***********************************************************************/
void
sendHURLorMOTM(PPPoEConnection *conn, char const *url, UINT16_t tag)
{
    PPPoEPacket packet;
    PPPoETag hurl;
    size_t elen;
    unsigned char *cursor = packet.payload;
    UINT16_t plen = 0;

    if (!conn->session) return;
    if (conn->discoverySocket < 0) return;

    if (tag == TAG_HURL) {
	if (strncmp(url, "http://", 7)) {
	    syslog(LOG_WARNING, "sendHURL(%s): URL must begin with http://", url);
	    return;
	}
    } else {
	tag = TAG_MOTM;
    }

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADM;
    packet.session = conn->session;

    elen = strlen(url);
    if (elen > 256) {
	syslog(LOG_WARNING, "MOTM or HURL too long: %d", (int) elen);
	return;
    }

    hurl.type = htons(tag);
    hurl.length = htons(elen);
    strcpy((char *) hurl.payload, url);
    memcpy(cursor, &hurl, elen + TAG_HDR_SIZE);
    cursor += elen + TAG_HDR_SIZE;
    plen += elen + TAG_HDR_SIZE;

    packet.length = htons(plen);

    sendPacket(conn, conn->discoverySocket, &packet, (int) (plen + HDR_SIZE));
#ifdef DEBUGGING_ENABLED
    if (conn->debugFile) {
	dumpPacket(conn->debugFile, &packet, "SENT");
	fprintf(conn->debugFile, "\n");
	fflush(conn->debugFile);
    }
#endif
}
