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

// Interval timer. When fires, database aging performed.

class DBageTimer : public ITimer {
  public:
    virtual void action();
};

// Exit database overflow timer.

class ExitOverflowTimer : public Timer {
  public:
    virtual void action();
};

// Local LSA origination rate limiting

class LocalOrigTimer : public Timer {
  public:
    virtual void action();
};

// Global timer queue
extern PriQ timerq;		// Currently pending timers

/* The OSPF base class. This class contains all the data necessary
 * to run a sungle instance of the OSPF protocol.
 */

class OSPF : public ConfigItem {
    // Global configuration data
    const rtid_t myid;	// Our router ID
    bool inter_area_mc; // An inter-area multicast forwarder?
    bool g_mospf_enabled;// Running multicast extensions?
    int	ExtLsdbLimit;	// Max # AS-external-LSAs in database
    int	ExitOverflowInterval; // Elapsed time before leaving overflow
    int	new_flood_rate; // # self-orig per second
    uns16 max_rxmt_window;// # back-to-back retransmissions
    byte max_dds;	// # simultaneous DB exchanges
    byte host_mode;	// Don't forward data packets?
    int32 refresh_rate;	// Rate to refresh DoNotAge LSAs
    // Dynamic data
    InAddr myaddr;	// Global address: source on unnumbered
    bool wakeup; 	// Timers running?
    SpfIfc *ifcs; 	// List of interfaces
    int	inter_AS_mc:1;	// Are we an inter-AS multicast forwarder?
    int n_extImports;	// # Imported AS externals
    AVLtree extLSAs;	// AS-external-LSAs
    uns32 ase_xsum;	// checksum of AS-external-LSAs
    AVLtree ASBRtree;	// AVL tree of ASBRs
    ASBRrte *ASBRs; 	// Singly-linked ASBR routing table entries
    int	n_exlsas;	// # non-default AS-external-LSAs
    uns32 wo_donotage;	// #LSAs claiming no DoNotAge support
    bool dna_change;	// Change in network DoNotAge support
    LsaList dna_flushq; // DoNotAge LSAs being flushed from lack of support
    SpfNbr *g_adj_head;	// Adjacencies to form, head
    SpfNbr *g_adj_tail;	// Adjacencies to form, tail
    byte *build_area;	// build area
    uns16 build_size;	// size of build area
    byte *orig_buff;	// Origination staging area
    uns16 orig_size;	// size of staging area
    byte *mon_buff;	// Monitor replay staging area
    int mon_size;	// size of staging area
    int	shutdown_phase;	// Shutting down if > 0
    int	countdown;	// Number of seconds before exit
    bool delete_neighbors; // Neighbors being deleted?
    AVLtree phyints;	// Physical interfaces
    // Flooding queues
    int	n_local_flooded;// AS-external-LSAs originated this tick
    ExRtData *ases_pending; // Pending AS-external-LSA originations
    ExRtData *ases_end;	// End of pending AS-external-LSAs
    LocalOrigTimer origtim; // AS-external-LSA origination timer
    LsaList replied_list; // LSAs that we have recently sent
			 // in reponse to old LSAs received
    // For LSA aging
    DBageTimer dbtim;	// Database aging timer
    LsaList MaxAge_list; // MaxAge LSAs, being flushed
    uns32 total_lsas;	// Total number of LSAs in all databases
    LsaList dbcheck_list; // LSAs whose checksum is being verified
    // Database Overflow variables
    bool OverflowState;	// true => database has overflowed
    ExitOverflowTimer oflwtim; // Exit overflow timer
    // Group membership
    AVLtree ospfd_membership; // Our application's
    AVLtree local_membership; // Of local LAN segments
    AVLtree multicast_cache; // MOSPF Cache entries
    bool clear_mospf;	// Delete cache on next timer tick?

    SpfArea *areas; 	// List of areas
    SpfArea *summary_area;
    SpfArea *first_area;
    int	n_area;		// Number of actively attached areas
    int	n_dbx_nbrs;	// # nbrs undergoing database exchange
    int	n_lcl_inits;	// # locally initiated
    int	n_rmt_inits;	// # remotely initiated
    uns16 ospf_mtu;	// Max IP datagram for all interfaces
    Pkt	o_update;	// Current flood
    Pkt	o_demand_upd;	// Current flood out demand interfaces
    // State flags
    int	full_sched:1,	// true => full calculation scheduled
	ase_sched:1;	// true => all ases should be reexamined
    // Statistics
    uns32 n_dijkstras;
    // Logging variables
    int logno;		// Logging event number
    char logbuf[200];   // Logging buffer
    char *logptr;       // Current place in logging buffer
    char *logend;	// End of logging buffer
    int base_priority;
    bool disabled_msgno[MAXLOG+1];
    bool enabled_msgno[MAXLOG+1];

    // Monitoring routines
    class MonMsg *get_monbuf(int size);
    void global_stats(class MonMsg *, int conn_id);
    void area_stats(class MonMsg *, int conn_id);
    void interface_stats(class MonMsg *, int conn_id);
    void vl_stats(class MonMsg *, int conn_id);
    void neighbor_stats(class MonMsg *, int conn_id);
    void vlnbr_stats(class MonMsg *, int conn_id);
    void lsa_stats(class MonMsg *, int conn_id);
    void rte_stats(class MonMsg *, int conn_id);

    // Utility routines
    void clear_config();
    SpfIfc *find_ifc(uns32 addr, int phyint = -1);
    SpfIfc *next_ifc(uns32 addr, int phyint);
    SpfIfc *find_ifc(Pkt *pdesc);
    SpfIfc *find_vl(aid_t transit_id, rtid_t endpt);
    SpfIfc *next_vl(aid_t transit_id, rtid_t endpt);
    SpfIfc *find_nbr_ifc(InAddr nbr_addr);
    SpfNbr *find_nbr(InAddr nbr_addr, int phyint);
    SpfNbr *next_nbr(InAddr nbr_addr, int phyint);
    int run_fsm(FsmTran *table, int& i_state, int event);
    int	ospf_getpkt(Pkt *pkt, int type, uns16 size);
    void ospf_freepkt(Pkt *pkt);
    void delete_down_neighbors();
    void app_join(int phyint, InAddr group);
    void app_leave(int phyint, InAddr group);
    void phy_attach(int phyint);
    void phy_detach(int phyint, InAddr if_addr);
    void calc_my_addr();
    inline int mospf_enabled();
    inline LShdr *orig_buffer();
    inline bool	mc_abr();
    inline bool	shutting_down();
    inline int donotage();
    inline InAddr my_addr();

    // Database routines
    AVLtree *FindLSdb(SpfArea *ap, byte lstype);
    LSA	*FindLSA(SpfArea *, byte lstype, lsid_t lsid, rtid_t rtid);
    LSA	*myLSA(SpfArea *, byte lstype, lsid_t lsid);
    LSA	*AddLSA(SpfArea *, LSA *current, LShdr *hdr, bool changed);
    void DeleteLSA(LSA *lsap);
    LSA *NextLSA(aid_t, byte, lsid_t, rtid_t);
    void update_lsdb_xsum(LSA *, bool add);
    Range *GetBestRange(INrte *rte);
    SpfArea *FindArea(aid_t id);
    SpfArea *NextArea(aid_t &id);
    inline SpfArea *SummaryArea();	// summary-LSAs from this area used
    void ParseLSA(LSA *lsap, LShdr *hdr);
    void UnParseLSA(LSA *lsap);
    LShdr *BuildLSA(LSA *lsap);
    void send_updates();
    bool maxage_free(byte lstype);
    void flush_self_orig(AVLtree *tree);
    void flush_donotage();
    void shutdown_continue();
    void rl_orig();

    // Database aging
    void dbage();
    void deferred_lsas();
    void checkages();
    void refresh_lsas();
    void maxage_lsas();
    void refresh_donotages();
    void free_maxage_lsas();
    void donotage_changes();

    // LSA origination
    int	self_originated(SpfArea *ap, LShdr *hdr, LSA *database_copy);
    int	get_lsid(INrte *rte, byte lstype, SpfArea *ap, lsid_t &id);
    seq_t ospf_get_seqno(LSA *lsap, int ls_len, int forced);
    LSA	*lsa_reorig(SpfArea *ap, LSA *olsap, LShdr *hdr, int forced);
    void age_prematurely(LSA *);
    void sl_orig(INrte *rte, bool transit_changes_only=false);
    void asbr_orig(ASBRrte *rte);
    void ase_schedule(class ExRtData *);
    void ase_orig(class ExRtData *, int forced);
    void ase_orig(INrte *, int forced);
    void grp_orig(InAddr group, int forced=0);
    void reoriginate_ASEs();
    void build_update(Pkt *pkt, LShdr *hdr, uns16 mtu, bool demand);
    void add_to_update(LShdr *hdr, bool demand);
    void redo_aggregate(INrte *rangerte, SpfArea *ap);
    void EnterOverflowState();

    // Routing calculations
    ASBRrte *add_asbr(uns32 rtid);
    void rtsched(LSA *newlsa, RTE *old_rte);
    void full_calculation();
    void dijk_init(PriQ &cand);
    void host_dijk_init(PriQ &cand);
    void add_cand_node(SpfIfc *ip, TNode *node, PriQ &cand);
    void dijkstra();
    void update_brs();
    void update_asbrs();
    void invalidate_ranges();
    void rt_scan();
    void update_area_ranges(INrte *rte);
    void advertise_ranges();
    void do_all_ases();
    
    // MOSPF routines
    INrte *mc_source(InAddr src);
    void add_negative_mcache_entry(InAddr src, INrte *srte, InAddr group);
    // MOSPF cache maintenance
    void mospf_clear_cache();
    void mospf_clear_inter_source(INrte *rte);
    void mospf_clear_external_source(INrte *rte);
    void mospf_clear_group(InAddr);

    // Logging routines
    bool spflog(int, int);
    void log(int);
    void log(char *);
    void log(Pkt *pdesc);
    void log(InPkt *iphdr);
    void log(class LShdr *);
    void log(class SpfArea *);
    void log(class SpfIfc *);
    void log(class SpfNbr *);
    void log(InAddr *addr);
    void log(class LSA *);
    void log(class INrte *);

  public:
    // Version numbers
    enum {
	vmajor = 0,	// Major version number
	vminor = 1,	// Minor version number
    };

    // Entry points into the OSPF code
    OSPF(uns32 rtid);
    void rxpkt(int phyint, InPkt *pkt, int plen);
    int	timeout();
    void tick();
    void monitor(struct MonMsg *msg, byte type, int size, int conn_id);
    void rxigmp(int phyint, InPkt *pkt, int plen);
    MCache *mclookup(InAddr src, InAddr group);
    void join_indication(InAddr group, int phyint);
    void leave_indication(InAddr group, int phyint);
    void phy_up(int phyint);
    void phy_down(int phyint);
    MPath *ip_lookup(InAddr dest);
    InAddr ip_source(InAddr dest);
    InAddr if_addr(int phyint);
    void shutdown(int seconds);
    void logflush();
    inline rtid_t my_id();
    inline int n_extLSAs();
    inline uns32 xsum_extLSAs();
    
    // Configuration routines
    void cfgOspf(struct CfgGen *msg);
    void cfgArea(struct CfgArea *msg, int status);
    void cfgRnge(struct CfgRnge *msg, int status);
    void cfgIfc(struct CfgIfc *msg, int status);
    void cfgHost(struct CfgHost *msg, int status);
    void cfgVL(struct CfgVL *msg, int status);
    void cfgAuKey(struct CfgAuKey *key, int status);
    void cfgNbr(struct CfgNbr *msg, int status);
    void cfgExRt(struct CfgExRt *msg, int status);
    void cfgStart();
    void cfgDone();

    friend class IfcIterator;
    friend class AreaIterator;
    friend class DBageTimer;
    friend class Timer;
    friend class ITimer;
    friend class SpfNbr;
    friend class ConfigItem;
    friend class SpfIfc;
    friend class VLIfc;
    friend class NBMAIfc;
    friend class PhyInt;
    friend class ASextLSA;
    friend class ExitOverflowTimer;
    friend class LocalOrigTimer;
    friend class SpfArea;
    friend class asbrLSA;
    friend class ASBRrte;
    friend class LSA;
    friend class TNode;
    friend class PPIfc;
    friend class DRIfc;
    friend class P2mPIfc;
    friend class RTE;
    friend class netLSA;
    friend class HostAddr;
    friend class Range;
    friend class INrte;
    friend class FWDrte;
    friend class StaticNbr;
    friend class GroupTimeoutTimer;
    friend class LeaveQueryTimer;
    friend class FWDtbl;
    friend void lsa_flush(class LSA *);
    friend void ExRtData::clear_config();
    friend SpfNbr *GetNextAdj();
    friend void INrte::run_external();
};

// Declaration of the single OSPF protocol instance
extern OSPF *ospf;

// Inline functions
inline rtid_t OSPF::my_id()
{
    return(myid);
}
inline int OSPF::mospf_enabled()
{
    return(g_mospf_enabled);
}
inline LShdr *OSPF::orig_buffer()
{
    return((LShdr *)orig_buff);
}
inline bool OSPF::mc_abr()
{
    return(n_area > 1 && inter_area_mc != 0);
}
inline bool OSPF::shutting_down()
{
    return(shutdown_phase > 0);
}
inline SpfArea *OSPF::SummaryArea()
{
    return(summary_area);
}
inline int OSPF::donotage()
{
    if (wo_donotage != 0)
        return(false);
    else if (summary_area)
        return(summary_area->donotage());
    else
        return(true);
}
inline int OSPF::n_extLSAs()
{
    return(extLSAs.size());
}
inline uns32 OSPF::xsum_extLSAs()
{
    return(ase_xsum);
}
inline InAddr OSPF::my_addr()
{
    return(myaddr);
}

// non-class-related function declarations
void lsa_flush(LSA *lsap);
int flooding_scope(byte lstype);
