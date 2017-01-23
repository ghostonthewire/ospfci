/*
 *   OSPFD routing daemon
 *   Copyright (C) 1998 by John T. Moy
 *   
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version 2
 *   of the License, or (at your option) any later version.
 *   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *   
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <tcl.h>
#include <sys/socket.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/version.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include "../src/ospfinc.h"
#include "../src/monitor.h"
#include "../src/system.h"
#include "tcppkt.h"
#include "linux.h"
#include "ospfd_linux.h"
#include <time.h>

LinuxOspfd *ospfd_sys;
char buffer[MAX_IP_PKTSIZE];

// External declarations
bool get_prefix(char *prefix, InAddr &net, InMask &mask);

/* Signal handlers
 */
void timer(int)
{
    signal(SIGALRM, timer);
    ospfd_sys->one_second_timer();
}
void quit(int)
{
    ospf->shutdown(10);
}
void reconfig(int)
{
    signal(SIGUSR1, reconfig);
    ospfd_sys->read_config();
}

/* The main OSPF loop. Loops getting messages (packets, timer
 * ticks, configuration messages, etc.) and never returns
 * until the OSPF process is told to exit.
 */

int main(int, char * [])

{
    int n_fd;
    itimerval itim;
    fd_set fdset;
    fd_set wrset;
    sigset_t sigset, osigset;

    sys = ospfd_sys = new LinuxOspfd();
    syslog(LOG_INFO, "Starting v%d.%d",
	   OSPF::vmajor, OSPF::vminor);
    // Read configuration
    ospfd_sys->read_config();
    if (!ospf) {
	syslog(LOG_ERR, "ospfd initialization failed");
	exit(1);
    }
    // Set up signals
    signal(SIGALRM, timer);
    signal(SIGHUP, quit);
    signal(SIGTERM, quit);
    signal(SIGUSR1, reconfig);
    itim.it_interval.tv_sec = 1;
    itim.it_value.tv_sec = 1;
    itim.it_interval.tv_usec = 0;
    itim.it_value.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &itim, NULL) < 0)
	syslog(LOG_ERR, "setitimer: %m");
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGUSR1);
    // Block signals in OSPF code
    sigprocmask(SIG_BLOCK, &sigset, &osigset);

    while (1) {
	int msec_tmo;
	int err;
	FD_ZERO(&fdset);
	FD_ZERO(&wrset);
	n_fd = ospfd_sys->netfd;
	FD_SET(ospfd_sys->netfd, &fdset);
	ospfd_sys->mon_fd_set(n_fd, &fdset, &wrset);
	if (ospfd_sys->igmpfd != -1) {
	    FD_SET(ospfd_sys->igmpfd, &fdset);
	    n_fd = MAX(n_fd, ospfd_sys->igmpfd);
	}
	// Process any pending timers
	ospf->tick();
	// Time till next timer firing
	msec_tmo = ospf->timeout();
	// Flush any logging messages
	ospf->logflush();
	// Allow signals during select
	sigprocmask(SIG_SETMASK, &osigset, NULL);
	if (msec_tmo != -1) {
	    timeval timeout;
	    timeout.tv_sec = msec_tmo/1000;
	    timeout.tv_usec = (msec_tmo % 1000) * 1000;
	    err = select(n_fd+1, &fdset, &wrset, 0, &timeout);
	}
	else
	    err = select(n_fd+1, &fdset, &wrset, 0, 0);
	// Handle errors in select
	if (err == -1 && errno != EINTR) {
	    syslog(LOG_ERR, "select failed %m");
	    exit(1);
	}
	// Update elapsed time
	ospfd_sys->time_update();
	// Block signals in OSPF code
	sigprocmask(SIG_BLOCK, &sigset, &osigset);
	// Process received data packet, if any
	if (err <= 0)
	    continue;
	if (FD_ISSET(ospfd_sys->netfd, &fdset))
	    ospfd_sys->raw_receive(ospfd_sys->netfd);
	if (ospfd_sys->igmpfd != -1 &&
	    FD_ISSET(ospfd_sys->igmpfd, &fdset))
	    ospfd_sys->raw_receive(ospfd_sys->igmpfd);
	// Process monitor queries and responses
	ospfd_sys->process_mon_io(&fdset, &wrset);
    }
}

/* Process packets received on a raw socket. Could
 * be either the OSPF socket or the IGMP socket.
 */

void LinuxOspfd::raw_receive(int fd)

{
    int plen;
    int rcvint = -1;
#if LINUX_VERSION_CODE < LINUX22
    unsigned int fromlen;
    plen = recvfrom(fd, buffer, sizeof(buffer), 0, 0, &fromlen);
    if (plen < 0) {
        syslog(LOG_ERR, "recvfrom: %m");
	return;
    }
#else
    msghdr msg;
    iovec iov;
    byte cmsgbuf[128];
    msg.msg_name = 0;
    msg.msg_namelen = 0;
    iov.iov_len = sizeof(buffer);
    iov.iov_base = buffer;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    plen = recvmsg(fd, &msg, 0);
    if (plen < 0) {
        syslog(LOG_ERR, "recvmsg: %m");
	return;
    }
    else {
	cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
	    if (cmsg->cmsg_level == SOL_IP &&
		cmsg->cmsg_type == IP_PKTINFO) {
	        in_pktinfo *pktinfo;
		pktinfo = (in_pktinfo *) CMSG_DATA(cmsg);
		rcvint = pktinfo->ipi_ifindex;
		break;
	    }
	}
    }
#endif

    // Dispatch based on IP protocol
    InPkt *pkt = (InPkt *) buffer;
    switch (pkt->i_prot) {
      case PROT_OSPF:
        ospf->rxpkt(rcvint, pkt, plen);
	break;
      case PROT_IGMP:
        ospf->rxigmp(rcvint, pkt, plen);
	break;
      case 0:
	ospf->mclookup(pkt->i_src, pkt->i_dest);
	break;
      default:
	break;
    }
}

/* Update the program's notion of time, which is in milliseconds
 * since program start. Wait until receiving the timer signal
 * to update a full second.
 */

void LinuxOspfd::time_update()

{
    timeval now;	// Current idea of time
    int timediff;

    (void) gettimeofday(&now, NULL);
    timediff = 1000*(now.tv_sec - last_time.tv_sec);
    timediff += (now.tv_usec - last_time.tv_usec)/1000;
    if ((timediff + sys_etime.msec) < 1000)
	sys_etime.msec += timediff;
    last_time = now;
}

/* Signal handler for the one second timer.
 * Up the elapsed time to the next whole second.
 */

void LinuxOspfd::one_second_timer()

{
    timeval now;	// Current idea of time

    (void) gettimeofday(&now, NULL);
    sys_etime.sec++; 
    sys_etime.msec = 0;
    last_time = now;
}

/* Initialize the Linux interface.
 * Open the network interface.
 * Start the random number generator.
 */

char *ospfd_log_file = "/var/log/ospfd.log";

LinuxOspfd::LinuxOspfd() : Linux(OSPFD_MON_PORT)

{
    rlimit rlim;

    next_phyint = 0;
    memset(phys, 0, sizeof(phys));
    (void) gettimeofday(&last_time, NULL);
    // Allow core files
    rlim.rlim_max = RLIM_INFINITY;
    (void) setrlimit(RLIMIT_CORE, &rlim);
    // Open syslog
    openlog("ospfd", LOG_PID, LOG_DAEMON);
    // Open log file
    if (!(logstr = fopen(ospfd_log_file, "w"))) {
	syslog(LOG_ERR, "Logfile open failed: %m");
	exit(1);
    }
    // Open monitoring listen socket
    monitor_listen();
    // Open network
    if ((netfd = socket(AF_INET, SOCK_RAW, PROT_OSPF)) == -1) {
	syslog(LOG_ERR, "Network open failed: %m");
	exit(1);
    }
    // We will supply headers on output
    int hincl = 1;
    setsockopt(netfd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
#if LINUX_VERSION_CODE >= LINUX22
    // Request notification of receiving interface
    int pktinfo = 1;
    setsockopt(netfd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo));
#endif
    // Open ioctl socket
    if ((udpfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
	syslog(LOG_ERR, "Failed to open UDP socket: %m");
	exit(1);
    }
    // Start random number generator
    srand(getpid());
    // Will open multicast fd if requested to later
    igmpfd = -1;
}

/* Destructor not expected to be called during the life
 * of the program.
 */

LinuxOspfd::~LinuxOspfd()

{
}

/* TCL procedures to send configuration data to the ospfd
 * application.
 */

int SetRouterID(ClientData, Tcl_Interp *, int, char *argv[]);
int SendGeneral(ClientData, Tcl_Interp *, int, char *argv[]);
int SendArea(ClientData, Tcl_Interp *, int, char *argv[]);
int SendAggregate(ClientData, Tcl_Interp *, int, char *argv[]);
int SendHost(ClientData, Tcl_Interp *, int, char *argv[]);
int SendInterface(ClientData, Tcl_Interp *, int, char *argv[]);
int SendVL(ClientData, Tcl_Interp *, int, char *argv[]);
int SendNeighbor(ClientData, Tcl_Interp *, int, char *argv[]);
int SendExtRt(ClientData, Tcl_Interp *, int, char *argv[]);
int SendMD5Key(ClientData, Tcl_Interp *, int, char *argv[]);

/* Read the ospfd config out of the file /etc/ospfd.conf
 */

char *ospfd_tcl_src = "/ospfd.tcl";
char *ospfd_config_file = "/etc/ospfd.conf";
rtid_t new_router_id;

void LinuxOspfd::read_config()

{
    Tcl_Interp *interp; // Interpretation of config commands
    char sendcfg[] = "sendcfg";
    int namlen;
    char *filename;

    new_router_id = 0;
    interp = Tcl_CreateInterp();
    // Install C-language TCl commands
    Tcl_CreateCommand(interp, "routerid", SetRouterID, 0, 0);
    Tcl_CreateCommand(interp, "sendgen", SendGeneral, 0, 0);
    Tcl_CreateCommand(interp, "sendarea", SendArea, 0, 0);
    Tcl_CreateCommand(interp, "sendagg", SendAggregate, 0, 0);
    Tcl_CreateCommand(interp, "sendhost", SendHost, 0, 0);
    Tcl_CreateCommand(interp, "sendifc", SendInterface, 0, 0);
    Tcl_CreateCommand(interp, "sendvl", SendVL, 0, 0);
    Tcl_CreateCommand(interp, "sendnbr", SendNeighbor, 0, 0);
    Tcl_CreateCommand(interp, "sendextrt", SendExtRt, 0, 0);
    Tcl_CreateCommand(interp, "sendmd5", SendMD5Key, 0, 0);
    // Read additional TCL commands
    namlen = strlen(INSTALL_DIR) + strlen(ospfd_tcl_src);
    filename = new char[namlen+1];
    strcpy(filename, INSTALL_DIR);
    strcat(filename, ospfd_tcl_src);
    if (Tcl_EvalFile(interp, filename) != TCL_OK)
	syslog(LOG_INFO, "No additional TCL commands");
    delete [] filename;
    // (Re)read kernel interfaces
    read_kernel_interfaces();
    // (Re)read config file
    if (Tcl_EvalFile(interp, ospfd_config_file) != TCL_OK) {
	syslog(LOG_ERR, "Error in config file, line %d", interp->errorLine);
	return;
    }
    // Verify new router ID
    if (!ospf || ospf->my_id() != new_router_id) {
	syslog(LOG_ERR, "Failed to set Router ID");
	return;
    }
    // Reset current config
    ospf->cfgStart();
    // Download new config
    Tcl_Eval(interp, sendcfg);
    Tcl_DeleteInterp(interp);
    // Signal configuration complete
    ospf->cfgDone();
}

/* Find the physical interface to which a given address
 * belongs. Returns -1 if no matching interface
 * can be found.
 */

int LinuxOspfd::get_phyint(InAddr addr)

{
    int i;
    for (i=0; i < MAXIFs; i++) {
	BSDPhyInt *phyp;
	phyp = phys[i];
	if (phyp && (phyp->addr & phyp->mask) == (addr & phyp->mask))
	    return(i);
    }

    return(-1);
}

/* Read the IP interface information out of the Linux
 * kernel.
 */

void LinuxOspfd::read_kernel_interfaces()

{
    ifconf cfgreq;
    ifreq *ifrp;
    ifreq *end;
    size_t size;
    char *ifcbuf;
    int blen;

    blen = MAXIFs*sizeof(ifreq);
    ifcbuf = new char[blen];
    cfgreq.ifc_buf = ifcbuf;
    cfgreq.ifc_len = blen;

    if (ioctl(udpfd, SIOCGIFCONF, (char *)&cfgreq) < 0) {
	syslog(LOG_ERR, "Failed to read interface config: %m");
	exit(1);
    }

    /* Clear current list of interfaces and directly
     * attached subnets, since we're going to reread
     * them.
     */
    interface_map.clear();
    directs.clear();

    ifrp = (ifreq *) ifcbuf;
    end = (ifreq *)(ifcbuf + cfgreq.ifc_len);
    for (; ifrp < end; ifrp = (ifreq *)(((byte *)ifrp) + size)) {
	BSDPhyInt *phyp;
	byte *phystr;
	ifreq ifr;
	sockaddr_in *insock;
	InAddr addr;
	// Find next interface structure in list
	size = sizeof(InAddr) + sizeof(ifrp->ifr_name);
	if (size < sizeof(ifreq))
	    size = sizeof(ifreq);
	// IP interfaces only
	if (ifrp->ifr_addr.sa_family != AF_INET)
	    continue;
	// Ignore loopback interfaces
	// Also ignore "down" interfaces
	// Get interface flags
	memcpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));
	if (ioctl(udpfd, SIOCGIFFLAGS, (char *)&ifr) < 0) {
	    syslog(LOG_ERR, "SIOCGIFFLAGS Failed: %m");
	    exit(1);
	}
	if ((ifr.ifr_flags & IFF_LOOPBACK) != 0)
	    continue;
	if ((ifr.ifr_flags & IFF_UP) == 0)
	    continue;
#if LINUX_VERSION_CODE >= LINUX22
	int ifindex;
	// Get interface index
	memcpy(ifr.ifr_name, ifrp->ifr_name, sizeof(ifr.ifr_name));
	if (ioctl(udpfd, SIOCGIFINDEX, (char *)&ifr) < 0) {
	    syslog(LOG_ERR, "SIOCGIFFLAGS Failed: %m");
	    exit(1);
	}
	ifindex = ifr.ifr_ifindex;
#endif
	/* Found a legitimate interface
	 * Add physical interface and
	 * IP address maps
	 */
	if (!(phyp = (BSDPhyInt *) phyints.find((byte *)ifrp->ifr_name,
						sizeof(ifrp->ifr_name)))){
	    phyp = new BSDPhyInt;
	    phystr = new byte[sizeof(ifrp->ifr_name)];
	    memcpy(phystr, ifrp->ifr_name, sizeof(ifrp->ifr_name));
	    phyp->key = phystr;
	    phyp->keylen = sizeof(ifrp->ifr_name);
#if LINUX_VERSION_CODE < LINUX22
	    phyp->phyint = ++next_phyint;
#else
	    phyp->phyint = ifindex;
#endif
	    phyints.add(phyp);
	    // May have multiple interfaces attached to same physical
	    // net
	    if (!phys[phyp->phyint])
	        phys[phyp->phyint] = phyp;
	}
	phyp->flags = ifr.ifr_flags;
	insock = (sockaddr_in *) &ifrp->ifr_addr;
	addr = phyp->addr = ntoh32(insock->sin_addr.s_addr);
	// Get subnet mask
	if (ioctl(udpfd, SIOCGIFNETMASK, (char *)&ifr) < 0) {
	    syslog(LOG_ERR, "SIOCGIFNETMASK Failed: %m");
	    exit(1);
	}
	insock = (sockaddr_in *) &ifr.ifr_addr;
	phyp->mask = ntoh32(insock->sin_addr.s_addr);
	add_direct(addr, phyp->mask);
	add_direct(addr, 0xffffffffL);
	// Get interface MTU
	phyp->mtu = ((phyp->flags & IFF_BROADCAST) != 0) ? 1500 : 576;
	if (ioctl(udpfd, SIOCGIFMTU, (char *)&ifr) >= 0)
	    phyp->mtu = ifr.ifr_mtu;
	// For point-to-point links, get other end's address
	phyp->dstaddr = 0;
	if ((phyp->flags & IFF_POINTOPOINT) != 0 &&
	    (ioctl(udpfd, SIOCGIFDSTADDR, (char *)&ifr) >= 0)) {
	    addr = phyp->dstaddr = ntoh32(insock->sin_addr.s_addr);
	    add_direct(addr, 0xffffffffL);
	}
	// Install map from IP address to physical interface
	if (!interface_map.find(addr, 0)) {
	    BSDIfMap *map;
	    map = new BSDIfMap(addr, phyp);
	    interface_map.add(map);
	}
    }

    delete [] ifcbuf;
}

/* Add to the list of directly attached prefixes. These
 * we will let the kernel manage directly.
 */

void LinuxOspfd::add_direct(InAddr addr, InMask mask)

{
    addr = addr & mask;
    if (!directs.find(addr, mask)) {
	AVLitem *item;
	item = new AVLitem(addr, mask);
	directs.add(item);
    }
}

/* Parse an interface identifier, which can either be an address
 * or a name like "eth0".
 */

bool LinuxOspfd::parse_interface(char *arg, in_addr &addr, BSDPhyInt *&phyp)

{
    phyp = 0;

    if (inet_aton(arg, &addr) == 1) {
	BSDIfMap *map;
	InAddr ifaddr;
	ifaddr = ntoh32(addr.s_addr);
	map = (BSDIfMap *) interface_map.find(ifaddr, 0);
	if (map != 0)
	    phyp = map->phyp;
    }
    else {
	byte ifname[IFNAMSIZ];
	memset(ifname, 0, IFNAMSIZ);
	memcpy(ifname, arg, IFNAMSIZ);
	phyp = (BSDPhyInt *) phyints.find(ifname, IFNAMSIZ);
    }

    if (!phyp) {
	syslog(LOG_ERR, "Bad interface identifier %s", arg);
	return(false);
    }

    return(true);
}

/* Set the Router ID of the OSPF Process.
 * Refuse to reset the OSPF Router ID if it has already
 * been set.
 */

int SetRouterID(ClientData, Tcl_Interp *, int, char *argv[])

{
    new_router_id = ntoh32(inet_addr(argv[1]));
    if (!ospf)
	ospf = new OSPF(new_router_id);
    return(TCL_OK);
}

/* Download the global configuration values into the ospfd
 * software. If try to change Router ID, refuse reconfig.
 * If first time, create OSPF protocol instance.
 */

int SendGeneral(ClientData, Tcl_Interp *, int, char *argv[])

{
    CfgGen m;

    m.lsdb_limit = atoi(argv[1]);
    m.mospf_enabled = atoi(argv[2]);
    m.inter_area_mc = atoi(argv[3]);
    m.ovfl_int = atoi(argv[4]);
    m.new_flood_rate = atoi(argv[5]);
    m.max_rxmt_window = atoi(argv[6]);
    m.max_dds = atoi(argv[7]);
    m.host_mode = atoi(argv[9]);
    m.log_priority = atoi(argv[8]);
    m.refresh_rate = atoi(argv[10]);
    ospf->cfgOspf(&m);

    return(TCL_OK);
}

/* Dowload configuration of a single area
 */

int SendArea(ClientData, Tcl_Interp *, int, char *argv[])

{
    CfgArea m;

    m.area_id = ntoh32(inet_addr(argv[1]));
    m.stub = atoi(argv[2]);
    m.dflt_cost = atoi(argv[3]);
    m.import_summs = atoi(argv[4]);
    ospf->cfgArea(&m, ADD_ITEM);

    return(TCL_OK);
}

int SendAggregate(ClientData, Tcl_Interp *, int, char *argv[])
{
    CfgRnge m;
    InAddr net;
    InAddr mask;

    if (get_prefix(argv[1], net, mask)) {
	m.net = net;
	m.mask = mask;
	m.area_id = ntoh32(inet_addr(argv[2]));
	m.no_adv = atoi(argv[3]);
	ospf->cfgRnge(&m, ADD_ITEM);
    }

    return(TCL_OK);
}

int SendHost(ClientData, Tcl_Interp *, int, char *argv[])
{
    CfgHost m;
    InAddr net;
    InAddr mask;

    if (get_prefix(argv[1], net, mask)) {
	m.net = net;
	m.mask = mask;
	m.area_id = ntoh32(inet_addr(argv[2]));
	m.cost = atoi(argv[3]);
	ospf->cfgHost(&m, ADD_ITEM);
    }

    return(TCL_OK);
}

/* Download an interface's configuration.
 * Interface can by identified by its address, name, or
 * for point-to-point addresses, the other end of the link.
 */

int SendInterface(ClientData, Tcl_Interp *, int, char *argv[])

{
    CfgIfc m;
    in_addr addr;
    BSDPhyInt *phyp;
    int intval;

    if (!ospfd_sys->parse_interface(argv[1], addr, phyp))
	return(TCL_OK);

    if (inet_aton(argv[1], &addr) == 1) {
	BSDIfMap *map;
	InAddr ifaddr;
	ifaddr = ntoh32(addr.s_addr);
	map = (BSDIfMap *)ospfd_sys->interface_map.find(ifaddr, 0);
	if (map != 0)
	    phyp = map->phyp;
    }
    else {
	byte ifname[IFNAMSIZ];
	memset(ifname, 0, IFNAMSIZ);
	memcpy(ifname, argv[1], IFNAMSIZ);
	phyp = (BSDPhyInt *) ospfd_sys->phyints.find(ifname, IFNAMSIZ);
    }

    if (!phyp) {
	syslog(LOG_ERR, "Bad interface identifier %s", argv[1]);
	return(TCL_OK);
    }

    m.address = phyp->addr;
    m.phyint = phyp->phyint;
    m.mask = phyp->mask;
    intval = atoi(argv[2]);
    m.mtu = (intval ? intval : phyp->mtu);
    m.IfIndex = atoi(argv[3]);
    m.area_id = ntoh32(inet_addr(argv[4]));
    intval = atoi(argv[5]);
    if (intval)
	m.IfType = intval;
    else if ((phyp->flags & IFF_BROADCAST) != 0)
	m.IfType = IFT_BROADCAST;
    else if ((phyp->flags & IFF_POINTOPOINT) != 0)
	m.IfType = IFT_PP;
    else
	m.IfType = IFT_NBMA;
    m.dr_pri = atoi(argv[6]);
    m.xmt_dly = atoi(argv[7]);
    m.rxmt_int = atoi(argv[8]);
    m.hello_int = atoi(argv[9]);
    m.if_cost = atoi(argv[10]);
    m.dead_int = atoi(argv[11]);
    m.poll_int = atoi(argv[12]);
    m.auth_type = atoi(argv[13]);
    memset(m.auth_key, 0, 8);
    strncpy((char *) m.auth_key, argv[14], (size_t) 8);
    m.mc_fwd = atoi(argv[15]);
    m.demand = atoi(argv[16]);
    m.passive = atoi(argv[17]);
    ospf->cfgIfc(&m, ADD_ITEM);

    return(TCL_OK);
}

int SendVL(ClientData, Tcl_Interp *, int, char *argv[])
{
    CfgVL m;

    m.nbr_id = ntoh32(inet_addr(argv[1]));
    m.transit_area = ntoh32(inet_addr(argv[2]));
    m.xmt_dly = atoi(argv[3]);
    m.rxmt_int = atoi(argv[4]);
    m.hello_int = atoi(argv[5]);
    m.dead_int = atoi(argv[6]);
    m.auth_type = atoi(argv[7]);
    strncpy((char *) m.auth_key, argv[8], (size_t) 8);
    ospf->cfgVL(&m, ADD_ITEM);

    return(TCL_OK);
}

int SendNeighbor(ClientData, Tcl_Interp *, int, char *argv[])
{
    CfgNbr m;

    m.nbr_addr = ntoh32(inet_addr(argv[1]));
    m.dr_eligible = atoi(argv[2]);
    ospf->cfgNbr(&m, ADD_ITEM);

    return(TCL_OK);
}

int SendExtRt(ClientData, Tcl_Interp *, int, char *argv[])
{
    CfgExRt m;
    InAddr net;
    InMask mask;

    if (get_prefix(argv[1], net, mask)) {
	m.net = net;
	m.mask = mask;
	m.type2 = (atoi(argv[3]) == 2);
	m.mc = (atoi(argv[5]) != 0);
	m.direct = 0;
	m.noadv = 0;
	m.cost = atoi(argv[4]);
	m.gw = ntoh32(inet_addr(argv[2]));
	m.phyint = ospfd_sys->get_phyint(m.gw);
	m.tag = atoi(argv[6]);
	ospf->cfgExRt(&m, ADD_ITEM);
    }
    return(TCL_OK);
}

int SendMD5Key(ClientData, Tcl_Interp *, int, char *argv[])
{
    CfgAuKey m;
    in_addr addr;
    BSDPhyInt *phyp;
    timeval now;
    tm tmstr;

    if (!ospfd_sys->parse_interface(argv[1], addr, phyp))
	return(TCL_OK);

    gettimeofday(&now, 0);
    m.address = phyp->addr;
    m.phyint = phyp->phyint;
    m.key_id = atoi(argv[2]);
    memset(m.auth_key, 0, 16);
    strncpy((char *) m.auth_key, argv[3], (size_t) 16);
    m.start_accept = 0;
    m.start_generate = 0;
    m.stop_generate = 0;
    m.stop_accept = 0;
    if (strptime(argv[4], "%D@%T", &tmstr))
	m.start_accept = mktime(&tmstr) - now.tv_sec;
    if (strptime(argv[5], "%D@%T", &tmstr))
	m.start_generate = mktime(&tmstr) - now.tv_sec;
    if (strptime(argv[6], "%D@%T", &tmstr))
	m.stop_generate = mktime(&tmstr) - now.tv_sec;
    if (strptime(argv[7], "%D@%T", &tmstr))
	m.stop_accept = mktime(&tmstr) - now.tv_sec;
    ospf->cfgAuKey(&m, ADD_ITEM);

    return(TCL_OK);
}
