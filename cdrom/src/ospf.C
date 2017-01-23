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

#include "ospfinc.h"
#include "monitor.h"
#include "system.h"
#include "ifcfsm.h"
#include "phyint.h"

// Globals
OSPF *ospf;
PriQ timerq;		// Global timer queue
OspfSysCalls *sys;	// System call interface
INtbl *inrttbl;	// IP routing table
FWDtbl *fa_tbl;        // Forwarding address table
INrte *default_route; // The default routing entry (0/0)
ConfigItem *cfglist;	// List of configurable classes
PatTree MPath::nhdb;	// Next hop(s) database
SPFtime sys_etime;	// Time since program start

/* This file contains the entry points into OSPF:
 *
 *	OSPF();		Creates an OSPF protocol instance
 *	~OSPF();	Destroys an OSPF protocol instance
 *	config();	Configuration command received
 *	rxpkt();	Receives an OSPF packet
 *	tick();		Timer update
 *	mcfwd();	Request to forward IP multicast datagram
 *      phy_up();	Physical interface up indication
 *      phy_down();	Physical interface down indication
 *	join_indication(); Join notification from IGMP
 *	leave_indication(); Leave notification from IGMP
 */

/* Create an instance of the OSPF protocol.
 */

OSPF::OSPF(uns32 rtid) : myid(rtid)

{
    int i;

    ifcs = 0;
    inter_area_mc = true;
    inter_AS_mc = false;
    ExtLsdbLimit = 0;
    ExitOverflowInterval = 300;
    g_mospf_enabled = false;

    new_flood_rate = 1000;
    max_rxmt_window = 8;
    max_dds = 2;		// # simultaneous DB exchanges
    host_mode = 0;		// act as router
    refresh_rate = 0;		// Don't originate DoNotAge LSAs

    myaddr = 0;
    n_extImports = 0;
    ase_xsum = 0;
    ASBRs = 0;
    n_exlsas = 0;
    wo_donotage = 0;
    dna_change = false;
    g_adj_head = 0;
    g_adj_tail = 0;
    build_area = 0;
    build_size = 0;
    orig_buff = 0;
    orig_size = 0;
    mon_buff = 0;
    mon_size = 0;
    shutdown_phase = 0;
    countdown = 0;
    delete_neighbors = false;
    n_local_flooded = 0;
    ases_pending = 0;
    ases_end = 0;
    total_lsas = 0;

    OverflowState = false;
    clear_mospf = false;
    areas = 0;
    summary_area = 0;
    first_area = 0;
    n_area = 0;
    n_dbx_nbrs = 0;
    n_lcl_inits = 0;
    n_rmt_inits = 0;
    ospf_mtu = 65535;
    full_sched = false;
    ase_sched = false;

    n_dijkstras = 0;

    // Initialize logging
    logno = 0;
    logptr = &logbuf[0];
    // Leave room to null terminate
    logend = logptr + sizeof(logbuf) - 1;
    base_priority = 4;
    for (i = 0; i <= MAXLOG; i++) {
	disabled_msgno[i] = false;
	enabled_msgno[i] = false;
    }

    // Start database aging timer
    dbtim.start(1*Timer::SECOND);
    // Add default route
    inrttbl = new INtbl;
    default_route = inrttbl->add(0, 0);
    fa_tbl = new FWDtbl;

    spflog(CFG_START, 5);
}

/* Configure global OSPF parameters. Certain parameter
 * changes cause us to take extra actions.
 */

void OSPF::cfgOspf(CfgGen *m)

{
    bool mospf;
    bool ia_mospf;
    AreaIterator iter(this);
    SpfArea *a;
    bool restart_all=false;

    mospf = (m->mospf_enabled != 0);
    ia_mospf = (m->inter_area_mc != 0);

    // MOSPF parameters
    if (mospf != g_mospf_enabled) {
	// Must restart all adjacencies!
	g_mospf_enabled = mospf;
	inter_area_mc = ia_mospf;
	restart_all = true;
	sys->set_multicast_routing(mospf);
    }
    else if (inter_area_mc != ia_mospf) {
	// Must reoriginate summary-LSAs
	inter_area_mc = ia_mospf;
	while ((a = iter.get_next()))
	    a->generate_summaries();
    }

    // Database oveflorw parameters
    if (ExtLsdbLimit != m->lsdb_limit) {
	ExtLsdbLimit = m->lsdb_limit;
	if (ExtLsdbLimit && n_exlsas >= ExtLsdbLimit)
	    EnterOverflowState();
    }
    if (ExitOverflowInterval != m->ovfl_int) {
	ExitOverflowInterval = m->ovfl_int;
	if (OverflowState) {
	    oflwtim.stop();
	    if (ExitOverflowInterval)
		oflwtim.start(ExitOverflowInterval*Timer::SECOND);
	}
    }

    new_flood_rate = m->new_flood_rate;
    max_rxmt_window = m->max_rxmt_window;
    max_dds = m->max_dds;
    if (host_mode != m->host_mode) {
        host_mode = m->host_mode;
        restart_all = true;
    }
    base_priority = m->log_priority;
    refresh_rate = m->refresh_rate;
    sys->ip_forward(host_mode == 0);

    updated = true;
    if (restart_all) {
	while ((a = iter.get_next()))
	    a->reinitialize();
    }
}

/* Set the defaults for the global OSPF configuration
 * parameters.
 */

void CfgGen::set_defaults()

{
    lsdb_limit = 0; 	// Maximum number of AS-external-LSAs
    mospf_enabled = 0;	// Running MOSPF?
    inter_area_mc = 1;	// Inter-area multicast forwarder?
    ovfl_int = 300; 	// Time to exit overflow state
    new_flood_rate = 1000;	// # self-orig LSAs per second
    max_rxmt_window = 8;	// # back-to-back retransmissions
    max_dds = 2;		// # simultaneous DB exchanges
    host_mode = 0;	// act as router
    log_priority = 4;	// Base logging priority
    refresh_rate = 0;	// Don't originate DoNotAge LSAs
    sys->ip_forward(true);
}

/* On a reconfig, OSPF global parameters have not been
 * specified. Install a set of default parameters instead.
 */

void OSPF::clear_config()

{
    CfgGen msg;

    msg.set_defaults();
    cfgOspf(&msg);
}

/* Calculate the "default IP address" which is
 * used as a source address when sending protocol
 * packets out an unnumbered interface.
 * First go through the host addresses with cost 0.
 * Next, if no hosts found, look at the interfaces.
 */

void OSPF::calc_my_addr()

{
    SpfArea *ap;
    AreaIterator a_iter(this);
    HostAddr *hp;
    SpfIfc *ip;
    IfcIterator iter(this);

    myaddr = 0;
    while ((ap = a_iter.get_next())) {
	AVLsearch h_iter(&ap->hosts);	
	while ((hp = (HostAddr *)h_iter.next())) {
	    if (hp->r_cost == 0 && hp->r_rte->mask() == 0xffffffffL) {
	        myaddr = hp->r_rte->net();
		return;
	    }
	}
    }
    while ((ip = iter.get_next())) {
        if (ip->state() != IFS_DOWN && ip->if_addr != 0) {
	    myaddr = ip->if_addr;
	    return;
	}
    }
}

/* An OSPF protocol packet has been received on a particular
 * physical interface. It is assumed that the IP encapsulation
 * has already been verified: the IP header checksum, and that
 * the IP packet has been received in its entirety.
 *
 * We associate the packet with an OSPF interface, verify that
 * the packet is authentic, and then dispatch to the appropriate
 * routing based on OSPF packet type.
 */

void OSPF::rxpkt(int phyint, InPkt *pkt, int plen)

{
    SpfPkt *spfpkt;
    SpfIfc *ip=0;
    SpfNbr *np=0;
    Pkt pdesc(phyint, pkt);
    int rcv_err;
    int err_level;

    rcv_err = 0;
    err_level = 3;
    spfpkt = pdesc.spfpkt;

    if (ntoh32(spfpkt->srcid) == myid)
	return;

    if (plen < ntoh16(pkt->i_len))
	rcv_err = RCV_SHORT;
    else if (pdesc.bsize < (int) sizeof(SpfPkt))
	rcv_err = RCV_SHORT;
    else if (pdesc.bsize < ntoh16(spfpkt->plen))
	rcv_err = RCV_SHORT;
    else if (spfpkt->vers != OSPFv2)
	rcv_err = RCV_BADV;
    else if (!(ip = find_ifc(&pdesc)))
	rcv_err = RCV_NO_IFC;
    else {
	np = ip->find_nbr(ntoh32(pkt->i_src), ntoh32(spfpkt->srcid));
	if (spfpkt->ptype != SPT_HELLO && !np)
	    rcv_err = RCV_NO_NBR;
	else if (!ip->verify(&pdesc, np)) {
	    rcv_err = RCV_AUTH;
	    err_level = 5;
	}
	else if (ntoh32(pkt->i_dest) == AllDRouters &&
		 ip->state() <= IFS_OTHER)
	    rcv_err = RCV_NOTDR;
    }

    if (rcv_err) {
	if (spflog(rcv_err, err_level))
	    log(&pdesc);
	return;
    }

    if (spflog(LOG_RCVPKT, 1))
	log(&pdesc);
    // Dispatch on OSPF packet type
    switch (spfpkt->ptype) {
      case SPT_HELLO:	// Hello packet
	ip->recv_hello(&pdesc);
	break;
      case SPT_DD:		// Database Description
	np->recv_dd(&pdesc);
	break;
      case SPT_LSREQ:	// Link State Request
	np->recv_req(&pdesc);
	break;
      case SPT_UPD:		// Link State Update
	np->recv_update(&pdesc);
	break;
      case SPT_LSACK:	// Link State Acknowledgment
	np->recv_ack(&pdesc);
	break;
      default:		// Bad packet type
	break;
    }
}

/* Constructor for a host prefix that should be advertised
 * with a given area.
 * A dummy loopback interface class HostAddr::ip is created,
 * but it is not linked onto the global or per-area interface
 * lists, but is used only in multipath structures.
 */

HostAddr::HostAddr(SpfArea *a, uns32 net, uns32 mask) : AVLitem(net, mask)

{
    ap = a;
    r_rte = inrttbl->add(net, mask);
    r_area = ap->id();
    ap->hosts.add(this);
    ip = new LoopIfc(a, net, mask);
}

/* Add or delete a host prefix to be advertised by OSPF.
 */

void OSPF::cfgHost(struct CfgHost *m, int status)

{
    SpfArea *ap;
    HostAddr *hp;

    // Allocate new area, if necessary
    if (!(ap = FindArea(m->area_id)))
	ap = new SpfArea(m->area_id);
    if (!(hp = (HostAddr *) ap->hosts.find(m->net, m->mask)))
	hp = new HostAddr(ap, m->net, m->mask);
    if (status == DELETE_ITEM) {
	ap->hosts.remove(hp);
	delete hp->ip;
	delete hp;
    }
    else {
        hp->r_cost = m->cost;
	hp->updated = true;
    }
    // Reoriginate area's router-LSA
    ap->rl_orig();
    calc_my_addr();
}

/* Host not listed in a reconfig. Delete it.
 */

void HostAddr::clear_config()

{
    ap->hosts.remove(this);
    ap->rl_orig();
    delete this;
    ospf->calc_my_addr();
}

/* Process an incoming monitor request.
 */

void OSPF::monitor(MonMsg *msg, byte type, int, int conn_id)

{
    switch(type) {
      case MonReq_Stat:	// Global statistics
	global_stats(msg, conn_id);
	break;
      case MonReq_Area:	// Area statistics
	area_stats(msg, conn_id);
	break;
      case MonReq_Ifc:	// Interface statistics
	interface_stats(msg, conn_id);
	break;
      case MonReq_VL:	// Virtual link statistics
	vl_stats(msg, conn_id);
	break;
      case MonReq_Nbr:	// Neighbor statistics
	neighbor_stats(msg, conn_id);
	break;
      case MonReq_VLNbr: // Virtual neighbor statistics
	vlnbr_stats(msg, conn_id);
	break;
      case MonReq_LSA:  // Dump LSA contents
	lsa_stats(msg, conn_id);
	break;
      case MonReq_Rte:	// Dump routing table entry
	rte_stats(msg, conn_id);
	break;
      default:
	break;
    }
}

/* We have received an update of the elapsed real time
 * since the program was started. Go through the timer
 * queue and execute those timers which are now due to
 * fire.
 */

void OSPF::tick()

{
    Timer *tqelt;
    uns32 sec;
    uns32 msec;

    sec = sys_etime.sec;
    msec = sys_etime.msec;
    while ((tqelt = (Timer *) timerq.priq_gethead())) {
	if (tqelt->cost0 > sec)
	    break;
	if (tqelt->cost0 == sec && tqelt->cost1 > msec)
	    break;
	// Fire timer
	tqelt = (Timer *) timerq.priq_rmhead();
	tqelt->fire();
    }
}

/* Return the number of milliseconds until the next wakeup.
 * Returns -1 if there is no pending wakeup.
 */

int OSPF::timeout()

{
    Timer *tqelt;
    SPFtime wakeup_time; 

    if (!(tqelt = (Timer *) timerq.priq_gethead()))
	return(-1);

    wakeup_time.sec = tqelt->cost0;
    wakeup_time.msec = tqelt->cost1;
    if (time_less(wakeup_time, sys_etime))
	return(0);
    else
	return(time_diff(wakeup_time, sys_etime));
}

/* An indication that the physical or data link layer
 * has failed. Execute the down event on all associated
 * OSPF interfaces.
 * Redo the external routing calculation in case the
 * physical interface contains non-OSPF subnets which
 * are referenced in imported external routes.
 * Also, turn off IGMP processing.
 */

void OSPF::phy_down(int phyint)

{
    IfcIterator iter(this);
    SpfIfc *ip;
    PhyInt *phyp;

    ase_sched = true;
    while ((ip = iter.get_next())) {
	if (ip->if_phyint == phyint)
	    ip->run_fsm(IFE_DOWN);
    }

    if ((phyp = (PhyInt *)phyints.find((uns32) phyint, 0))) {
        phyp->operational = false;
	phyp->verify_igmp_capabilities();
    }
}

/* An indication that the physical and data link layers
 * are operational. Execute the up event on all associated
 * OSPF interfaces.
 * Redo the external routing calculation in case the
 * physical interface contains non-OSPF subnets which
 * are referenced in imported external routes.
 */


void OSPF::phy_up(int phyint)

{
    IfcIterator iter(this);
    SpfIfc *ip;

    ase_sched = true;
    while ((ip = iter.get_next())) {
	if (ip->if_phyint == phyint)
	    ip->run_fsm(IFE_UP);
    }
}

/* An indication that a group member has appeared
 * on a directly attached interface. If the phyint == -1,
 * the group member is a MOSPF internal group.
 * This routine is usually called by IGMP.
 */

void OSPF::join_indication(InAddr group, int phyint)

{
    GroupMembership *gentry;
    PhyInt *phyp;

    gentry = new GroupMembership(group, phyint);
    local_membership.add(gentry);
    phyp = (PhyInt *) phyints.find((uns32) phyint, 0);
    if (phyp && phyp->mospf_ifp)
        phyp->mospf_ifp->area()->grp_orig(group, 0);
    else if (phyint == -1)
        grp_orig(group, 0);
    if (spflog(LOG_NEWGRP, 4)) {
	log(&group);
	if (phyint != -1) {
	    log(" on ");
	    log(sys->phyname(phyint));
	}
    }
}

/* Leave group processing, similar to the above
 * join, just in reverse.
 */

void OSPF::leave_indication(InAddr group, int phyint)

{
    GroupMembership *gentry;
    PhyInt *phyp;

    gentry = (GroupMembership *) local_membership.find(group, phyint);
    if (!gentry)
	return;
    local_membership.remove(gentry);
    phyp = (PhyInt *)phyints.find(phyint, 0);
    if (phyp && phyp->mospf_ifp)
	phyp->mospf_ifp->area()->grp_orig(group, 0);
    else if (phyint == -1)
        grp_orig(group, 0);
    if (spflog(LOG_GRPEXP, 4)) {
	log(&group);
	if (phyint != -1) {
	    log(" on ");
	    log(sys->phyname(phyint));
	}
    }
    delete gentry;
}

/* Perform a lookup in OSPF's copy of the IP routing
 * table. Used on those platforms that do not maintain
 * a "kernel" copy of the routing table.
 */

MPath *OSPF::ip_lookup(InAddr dest)

{
    INrte *rte;

    if ((rte = inrttbl->best_match(dest)))
	return(rte->r_mpath);

    return(0);
}

/* Find the source address that would be used to send
 * packets to the given destination.
 */

InAddr OSPF::ip_source(InAddr dest)

{
    INrte *rte;
    SpfIfc *ip = 0;

    if ((rte = inrttbl->best_match(dest)) &&
	(ip = rte->r_mpath->NHs[0].o_ifp) &&
	(!ip->unnumbered()))
        return(ip->if_addr);

    return(my_addr());
}

/* Return the IP address associated with a given physical
 * interface.
 */

InAddr OSPF::if_addr(int phyint)

{
    PhyInt *phyp;
    phyp = (PhyInt *)phyints.find(phyint, 0);
    return(phyp ? phyp->my_addr : 0);
}

/* The graceful shutdown procedure. Executed in phases.
 * First flush all locally-originated LSAs, except network-LSAs.
 * Then flush the network-LSAs. Finally, remove OSPF entries
 * from the system routing table, send out empty hellos, and
 * exit.
 *
 * A maximum time limit is placed on the entire procedure.
 */

void OSPF::shutdown(int seconds)

{
    AreaIterator aiter(this);
    SpfArea *a;

    if (shutdown_phase)
	return;

    shutdown_phase++;
    // Set timer
    countdown = seconds;
    // Flush self-originated LSAs
    flush_self_orig(FindLSdb(0, LST_ASL));
    while ((a = aiter.get_next())) {
	flush_self_orig(FindLSdb(a, LST_RTR));
	flush_self_orig(FindLSdb(a, LST_SUMM));
	flush_self_orig(FindLSdb(a, LST_ASBR));
	flush_self_orig(FindLSdb(a, LST_GM));
    }
}

/* Continue the shutdown process.
 */

void OSPF::shutdown_continue()

{
    AreaIterator aiter(this);
    IfcIterator iiter(this);
    SpfArea *a;
    SpfIfc *ip;
    INrte *rte;
    INiterator iter(inrttbl);

    switch(shutdown_phase++) {
      case 1:
	// Reset timer
	countdown = 1;
	// Flush network-LSAs
	while ((a = aiter.get_next()))
	    flush_self_orig(FindLSdb(a, LST_NET));
	break;
      case 2:
	// Send empty Hellos
	while((ip = iiter.get_next()))
	    ip->send_hello(true);
	// Withdraw routing entries
	while ((rte = iter.nextrte())) {
	    switch(rte->type()) {
	      case RT_SPF:
	      case RT_SPFIA:
	      case RT_EXTT1:
	      case RT_EXTT2:
	      case RT_STATIC:
		sys->rtdel(rte->net(), rte->mask(), rte->last_mpath);
		break;
	      default:
		break;
	    }
	}
	// Exit program
	sys->halt(0, "Shutdown complete");
	break;
      default:
	sys->halt(0, "Shutdown complete");
	break;
    }
}
