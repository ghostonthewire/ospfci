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

/* The definitions relating to OSPF interfaces.
 */

/* The Interface timer definitions
 */

class WaitTimer : public Timer {
    class SpfIfc *ip;
  public:
    inline WaitTimer(class SpfIfc *);
    virtual void action();
};

inline WaitTimer::WaitTimer(class SpfIfc *ifc)
{
    ip = ifc;
}

class HelloTimer : public ITimer {
    class SpfIfc *ip;
  public:
    inline HelloTimer(class SpfIfc *);
    virtual void action();
};

inline HelloTimer::HelloTimer(class SpfIfc *ifc)
{
    ip = ifc;
}

class DAckTimer : public Timer {
    class SpfIfc *ip;
  public:
    inline DAckTimer(class SpfIfc *);
    virtual void action();
};

inline DAckTimer::DAckTimer(class SpfIfc *ifc)
{
    ip = ifc;
}

/* Cryptographic keys. Identified by Key ID, and providing
 * a 16-byte string to be used in an MD5 authentication
 * scheme. Also includes the time at which the key should be
 * activated.
 */

class CryptK : public ConfigItem {
    const byte key_id;
    class SpfIfc *ip;
    CryptK *link; 	// Chained in SpfIfc
    byte key[16];
    // key activation timers
    // stop timers are optional
    bool stop_generate_specified;
    bool stop_accept_specified;
    SPFtime start_accept;
    SPFtime start_generate;
    SPFtime stop_generate;
    SPFtime stop_accept;
  public:
    inline CryptK(byte id);
    virtual void clear_config();
    friend class SpfIfc;
    friend class KeyIterator;
    friend class OSPF;
};

inline CryptK::CryptK(byte id) : key_id(id)
{
}

/* The OSPF interface class. Divided into two separate parts.
 * The first part contains the configurable interface parameters
 * (as described in Appendix C.3 of the OSPF specification).
 * Default values for some of these parameters is given in the
 * OSPF MIB, and replicated in the source file "default.h".
 *
 * The interface MTU, which is the size of the largest IP datagram
 * that can be sent out the interface w/o fragmentation, is also
 * considered a configuration parameter.
 *
 * Next come the dynamic interface variables. Many of these are
 * described in Section 9 of the OSPF specification. The finite
 * state machine structure contains the current state, and a pointer
 * to the table that actually drives the FSM.
 */

class SpfIfc : public ConfigItem {
  protected:
    // Configurable parameters
    InMask if_mask;	// Interface address mask
    uns16 mtu;		// Max IP datagram in bytes
    int	if_IfIndex;	// MIB-II IfIndex
    uns16 if_cost;	// Cost
    byte if_rxmt;	// Retransmission interval
    byte if_xdelay;	// Transmission delay, in seconds
    uns16 if_hint;	// Hello interval
    uns32 if_dint;	// Router dead interval
    uns32 if_pint;	// Poll interval (NBMA only)
    byte if_drpri;	// Router priority
    uns32 if_demand:1;	// Demand-based circuit?
    autyp_t if_autype;	// Authentication type
    byte if_passwd[8];	// Simple password
    int passive;	// Don't send or receive control packets?
    int	if_mcfwd;	// Multicast forwardimg
    SpfArea *if_area;	// Associated OSPF area
    CryptK *if_keys;	// Cryptographic keys

    InAddr if_net; 	// Resulting network number
    InAddr if_mcaddr;	// Multicast address to use
    InAddr if_faddr;	// Address to use during flooding

    // Dynamic parameters
    SpfIfc *next; 	// Linked list of interfaces
    SpfIfc  *anext; 	// List by area
    Pkt	if_update;	// Pending update
    Pkt	if_dack;	// Pending delayed acks
    uns32 if_demand_helapse; // Elapsed time between demand hellos

    // Dynamic parameters
    InAddr if_dr; 	// Designated router
    InAddr if_bdr; 	// Backup designated router
    class SpfNbr *if_dr_p; // DR's neighbor structure
    int	if_state;	// Current interface state
    WaitTimer if_wtim;	// Wait timer
    HelloTimer if_htim;	// Hello timer
    DAckTimer if_actim;	// Delayed ack timer
    bool in_recv_update;// in midst of processing received Link State Update?
    bool area_flood;	// Participate in current area flood?
    bool global_flood;	// Ditto for global scope
    // FSM action routines
    virtual void ifa_start() = 0;
    void ifa_nbr_start(int base_priority);
    void ifa_elect();
    void ifa_reset();
    void ifa_allnbrs_event(int event);

  public:
    // Configurable parameters
    InAddr if_addr;	// Interface IP address
    int	if_phyint;	// The physical interface

    class SpfNbr *if_nlst; // List of associated neighbors
    int	if_nnbrs;	// Number of neighbors
    int	if_nfull;	// Number of fully adjacent neighbors

    SpfIfc(InAddr addr, int phyint); // Constructor
    virtual ~SpfIfc(); 	// Destructor
    inline SpfArea *area();
    inline int state();
    inline InAddr net();
    inline InAddr mask();
    inline uns16 cost();
    inline InAddr dr();
    inline InAddr bdr();
    inline byte rxmt_interval();
    bool demand_flooding(byte lstype);
    inline void if_build_dack(LShdr *hdr);
    inline void if_send_dack();
    inline void if_send_update();
    inline int unnumbered();

    void restart();
    void generate_message(Pkt *pdesc);
    int verify(Pkt *pdesc, class SpfNbr *np);
    void md5_generate(Pkt *pdesc);
    int md5_verify(Pkt *pdesc, class SpfNbr *np);
    void run_fsm(int event);// Interface Finite state machine
    void recv_hello(Pkt *pdesc);
    void send_hello(bool empty=false);
    int build_hello(Pkt *, uns16 size);
    bool suppress_this_hello(SpfNbr *np);
    int add_to_update(LShdr *hdr);
    void if_build_ack(LShdr *hdr, Pkt *pkt=0, class SpfNbr *np=0);
    void nl_orig(int forced); // Originate network-LSA
    void finish_pkt(Pkt *pdesc, InAddr addr);
    void nonbroadcast_send(Pkt *pdesc, InAddr addr);
    void nonbroadcast_stop_hellos();
    void nonbroadcast_restart_hellos();
    void dump_stats(struct IfcRsp *irsp);
    bool mospf_enabled();
    void reorig_all_grplsas();

    // Virtual functions
    virtual void clear_config();
    virtual void if_send(Pkt *, InAddr);
    virtual void nbr_send(Pkt *, SpfNbr *); // send OSPF packet to neighbor
    virtual class SpfNbr *find_nbr(InAddr, rtid_t);
    virtual void set_id_or_addr(SpfNbr *, rtid_t, InAddr);
    virtual RtrLink *rl_insert(RTRhdr *, RtrLink *) = 0;
    virtual int rl_size();
    virtual void add_adj_to_cand(class PriQ &cand) = 0;
    virtual int adjacency_wanted(class SpfNbr *np);
    virtual int type() = 0;
    virtual void send_hello_response(SpfNbr *np);
    virtual bool is_virtual();
    virtual bool is_multi_access();
    virtual SpfArea *transit_area();
    virtual rtid_t *vl_endpt();
    virtual void start_hellos();
    virtual void restart_hellos();
    virtual void stop_hellos();
    virtual bool elects_dr();

    friend class PhyInt;
    friend class IfcIterator;
    friend class NbrIterator;
    friend class KeyIterator;
    friend class WaitTimer;
    friend class HelloTimer;
    friend class InactTimer;
    friend class NbrHelloTimer;
    friend class HoldTimer;
    friend class DDRxmtTimer;
    friend class RqRxmtTimer;
    friend class ProgressTimer;
    friend class OSPF;
    friend class LSA;
    friend class SpfArea;
    friend class SpfNbr;
    friend class CryptK;
};

// Inline functions
inline SpfArea *SpfIfc::area()
{
    return(if_area);
}
inline int SpfIfc::state()
{
    return(if_state);
}
inline InAddr SpfIfc::net()
{
    return(if_net);
}
inline InAddr SpfIfc::mask()
{
    return(if_mask);
}
inline uns16 SpfIfc::cost()
{
    return(if_cost);
}
inline InAddr SpfIfc::dr()
{
    return(if_dr);
}
inline InAddr SpfIfc::bdr()
{
    return(if_bdr);
}
inline byte SpfIfc::rxmt_interval()
{
    return(if_rxmt);
}
inline  void SpfIfc::if_build_dack(LShdr *hdr)
{
    if_build_ack(hdr);
    if (!if_actim.is_running())
	if_actim.start(1*Timer::SECOND);
}
inline  void SpfIfc::if_send_dack()
{
    if_send(&if_dack, if_faddr);
}
inline void SpfIfc::if_send_update()
{
    if (if_update.iphdr)
	if_send(&if_update, if_faddr);
}
inline int SpfIfc::unnumbered()
{
    return (if_addr == 0);
}

/* Superclasses, to describe individual interface types
 */

/* The point-to-point interface, such as serial lines. These send a single
 * copy of each multicast packet out an interface, do not elect a
 * Designated router. Neighbors are identified by their router ID.
 * Note: multicasts current sent to the IP address of the neighbor.
 * This is against the spec, but makes BSD happy.
 */

class PPIfc : public SpfIfc {
  public:
    inline PPIfc(InAddr addr, int phyint);
    int type();
    bool is_multi_access();
    virtual void ifa_start();
    virtual class SpfNbr *find_nbr(InAddr, rtid_t);
    virtual void set_id_or_addr(SpfNbr *, rtid_t, InAddr);
    virtual void if_send(Pkt *, InAddr);
    virtual void nbr_send(Pkt *, SpfNbr *);
    virtual RtrLink *rl_insert(RTRhdr *, RtrLink *);
    virtual int rl_size();
    virtual void add_adj_to_cand(class PriQ &cand);
};

inline PPIfc::PPIfc(InAddr addr, int phyint) : SpfIfc(addr, phyint)
{
}

/* A virtual link. These send a single copy of each multicast packet
 * out an interface, although as a unicast to the neighbor's IP
 * address. They do not elect a Designated router, and only a single
 * neighbor is possible, with router ID pre-configured.
 */

class VLIfc : public PPIfc {
    SpfArea *if_tap;	// Transit area
    rtid_t if_nbrid;	// Configured neighbor ID
    InAddr if_rmtaddr;	// IP address of other end
  public:
    VLIfc(SpfArea *, class RTRrte *);
    ~VLIfc();
    virtual int type();
    virtual SpfArea *transit_area();
    virtual rtid_t *vl_endpt();
    virtual bool is_virtual();
    virtual void ifa_start();
    virtual void if_send(Pkt *, InAddr);
    virtual void nbr_send(Pkt *, SpfNbr *);
    virtual RtrLink *rl_insert(RTRhdr *, RtrLink *);
    void update(class RTRrte *endpt);
    friend class OSPF;
};

/* Interfaces that elect Designated Routers. The broadcast interface
 * and NBMA interfaces are derived from this class.
 */

class DRIfc : public SpfIfc {
  public:
    inline DRIfc(InAddr addr, int phyint);
    virtual int adjacency_wanted(class SpfNbr *np);
    virtual RtrLink *rl_insert(RTRhdr *, RtrLink *);
    virtual void add_adj_to_cand(class PriQ &cand);
    virtual void ifa_start();
    virtual bool elects_dr();
};

inline DRIfc::DRIfc(InAddr addr, int phyint) : SpfIfc(addr, phyint)
{
}

/* The broadcast interface, such as ethernets. These send a single
 * copy of each multicast packet out an interface, and elect a
 * Designated router. Neighbors are identified by their IP address.
 */

class BroadcastIfc : public DRIfc {
  public:
    inline BroadcastIfc(InAddr addr, int phyint);
    virtual int type();
};

inline BroadcastIfc::BroadcastIfc(InAddr addr, int phyint)
: DRIfc(addr, phyint)
{
}

/* The NBMA interface, such full mesh-connected Frame relay subnets.
 *These send a separate packet to each neighbor. They elect a
 * Designated router, and neighbors are identified by their IP address.
 */

class NBMAIfc : public DRIfc {
  public:
    inline NBMAIfc(InAddr addr, int phyint);
    virtual int type();
    virtual void if_send(Pkt *pdesc, InAddr addr);
    virtual void start_hellos();
    virtual void restart_hellos();
    virtual void stop_hellos();
    virtual int adjacency_wanted(class SpfNbr *np);
    virtual void send_hello_response(SpfNbr *np);
};

inline NBMAIfc::NBMAIfc(InAddr addr, int phyint) : DRIfc(addr, phyint)
{
}

/* The point-to-Multipoint interface, such as non-full-mesh connected
 * Frame relay subnets. Separate packets are sent to each neighbor,
 * neighbors are identified by their IP addresses, and no Designated
 * router is elected fro the network.
 */

class P2mPIfc : public SpfIfc {
  public:
    inline P2mPIfc(InAddr addr, int phyint);
    virtual int type();
    virtual void if_send(Pkt *pdesc, InAddr addr);
    virtual void start_hellos();
    virtual void restart_hellos();
    virtual void stop_hellos();
    virtual int adjacency_wanted(class SpfNbr *np);
    virtual void ifa_start();
    virtual RtrLink *rl_insert(RTRhdr *, RtrLink *);
    virtual int rl_size();
    virtual void add_adj_to_cand(class PriQ &cand);
};

inline P2mPIfc::P2mPIfc(InAddr addr, int phyint) : SpfIfc(addr, phyint)
{
}

/* The loopback interface. One allocated for each loopback
 * address assigned to the router. 
 * A dummy loopback interface class HostAddr::ip is created,
 * but it is not linked onto the global or per-area interface
 * lists, but is used only in multipath structures.
 */

class LoopIfc : public SpfIfc {
  public:
    LoopIfc(SpfArea *, InAddr net, InMask mask);
    virtual void ifa_start();
    virtual RtrLink *rl_insert(RTRhdr *, RtrLink *);
    virtual void add_adj_to_cand(class PriQ &cand);
    virtual int type();
};
