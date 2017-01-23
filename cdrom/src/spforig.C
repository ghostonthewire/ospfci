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

/* Routines dealing with the origination and re-origination
 * of LSAs.
 */

#include "ospfinc.h"
#include "system.h"

/* Determine whether a newly received LSA is actually an update
 * of one of our self-originated LSAs. If so, take appropriate
 * action, either flushing the LSA or refreshing it with the
 * data that we really want to send
 */

int OSPF::self_originated(SpfArea *ap, LShdr *hdr, LSA *database_copy)

{
    LSA *lsap;

    if ((ntoh32(hdr->ls_org) != my_id()) &&
	(hdr->ls_type != LST_NET || !find_ifc(ntoh32(hdr->ls_id))))
	return(false);

    // Have received update of self-originated LSA
    if (spflog(LOG_SELFORIG, 4))
	log(hdr);
    // Flush if don't want to advertise
    // Otherwise, simply bump database copy's sequence number
    if (ntoh32(hdr->ls_org) != my_id() ||
	(!database_copy) ||
	database_copy->lsa_age() == MaxAge) {
	lsap = AddLSA(ap, database_copy, hdr, true);
	age_prematurely(lsap);
    }
    else if (ntoh32(hdr->ls_seqno) == (seq_t) MaxLSSeq) {
	lsap = AddLSA(ap, database_copy, hdr, true);
	lsap->rollover = true;
	age_prematurely(lsap);
	return(true);
    }
    else
	database_copy->refresh(ntoh32(hdr->ls_seqno));

    return(true);
}

/* Calculate the new LS sequence number that should be used for
 * this LSA. If MinLSInterval seconds haven't elapsed since the
 * last origination, or if must rollover the sequence number
 * before originating a new instance, return false. This tells
 * the caller that the origination should be put off until
 * later.
 *
 * Returns the new sequence number in machine byte order.
 *
 * If shutting down, return InvalidLSSeq to inhibit further
 * LSA origination.
 */

seq_t OSPF::ospf_get_seqno(LSA *lsap, int ls_len, int forced)

{
    if (shutting_down() || host_mode)
	return(InvalidLSSeq);
    // Allocate large LSA build buffer, if necessary
    if (ls_len > orig_size) {
	orig_size = ls_len;
	delete [] orig_buff;
	orig_buff = new byte[orig_size];
    }

    if (!lsap || !lsap->valid())
	return(InitLSSeq);
    if ((!forced) && 
	lsap->in_agebin && lsap->since_received() < MinLSInterval) {
	lsap->deferring = true;
	if (spflog(LOG_LSADEFER, 3))
	    log(lsap);
	return(InvalidLSSeq);
    }
    if (lsap->ls_seqno() == MaxLSSeq) {
	lsap->rollover = true;
	age_prematurely(lsap);
	return(InvalidLSSeq);
    }

    // Normal case. Just advance old LS sequence by 1
    return(lsap->ls_seqno() + 1);
}

/* Attempt to refresh an LSA with a given sequence number.
 * It is assumed that the caller has already verified that the
 * sequence number is not MaxLSSeq (which requires rollover).
 */

int LSA::refresh(seq_t seqno)

{
    lsa_seqno = seqno;
    reoriginate(true);
    return(true);
}

/* Flush an LSA from the routinmg domain. As long as the LSA is valid,
 * perform the premature aging procedure.
 */

void lsa_flush(LSA *lsap)

{
    if (lsap && lsap->valid() && lsap->lsa_age() != MaxAge) {
	ospf->age_prematurely(lsap);
    }
}

/* We are ready to originate (or reoriginate) an LSA. If we
 * are not forced to originate (LSA refreshes), don't originate
 * if there are no changes.
 *
 * As part of the origination process, add the LSA to the database
 * and flood out appropriate interfaces. The add process will schedule
 * the appropriate routing calculations when the contents have changed.
 *
 * Returns new LSA if originated, 0 otherwise.
 */

LSA *OSPF::lsa_reorig(SpfArea *ap, LSA *olsap, LShdr *hdr, int forced)

{
    int changes;
    LSA *lsap;

    hdr->ls_age = 0;
    if (donotage() && 
	hdr->ls_type == LST_ASL &&
	(refresh_rate < 0 || refresh_rate > LSRefreshTime))
        hdr->ls_age = hton16(ntoh16(hdr->ls_age) | DoNotAge);
    changes = (olsap ? olsap->cmp_contents(hdr) : true);
    if (!changes && !forced && olsap->do_not_age() == hdr->do_not_age())
	return(0);
    // Perform origination
    hdr->generate_cksum();
    if (spflog(LOG_LSAORIG, 3))
	log(hdr);
    // Add to database and flood
    lsap = AddLSA(ap, olsap, hdr, changes);
    lsap->flood(0, hdr);
    return(lsap);
}


/* Get the Link State ID with which to originate a type 3 summary-LSA
 * or an AS-external-LSA. Start with the "natural ID", and search
 * for the first unused entry. In so doing, can preempt Link State
 * IDs for those having less specific masks.
 * Returns false if unable to assign ID, true otherwise.
 */

int OSPF::get_lsid(INrte *rte, byte lstype, SpfArea *ap, lsid_t &ls_id)

{
    uns32 end;

    ls_id = rte->net();
    end = rte->broadcast_address();

    for (; ls_id <= end; ls_id++) {
	rteLSA *lsap;
	INrte *o_rte;
	if (!(lsap = (rteLSA *) myLSA(ap, lstype, ls_id)))
	    return(true);
	else if (!(o_rte = lsap->orig_rte))
	    return(true);
	else if (rte->mask() >= o_rte->mask())
	    return(true);
    }

    return(false);
}



/* Age an LSA prematurely. Set the LS age to MaxAge and then re-add
 * to the database. Will then
 * be removed from database as soon as it is acknowledged by all
 * neighbors.
 * Have to re-checksum, because sometimes we have jumped
 * sequence numbers (messing up the existing checksum) when
 * responding to received, self-originated LSAs.
 */

void OSPF::age_prematurely(LSA *lsap)

{
    LShdr *hdr;
    LSA *nlsap;
    age_t oldage;
    int msgno;
    
    hdr = ospf->BuildLSA(lsap);
    oldage = ntoh16(hdr->ls_age);
    hdr->ls_age = hton16(MaxAge);
    hdr->generate_cksum();

    msgno = (oldage == MaxAge ? LOG_LSAMAXAGE : LOG_LSAFLUSH);
    if (spflog(msgno, 3))
	log(hdr);

    // Add to database and flood
    // lsap may be deleted after this line
    nlsap = AddLSA(lsap->area(), lsap, hdr, true);
    nlsap->flood(0, hdr);
}
