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

/* Routines implementing basic routing table functions.
 */

#include "ospfinc.h"

/* Display strings for the various routing table types.
 * Must match the enum defining RT_SPF, etc.
 */

/* Defines for type of routing table entry
 * Organized from most preferred to least preferred.
 */

char *rtt_ascii[] = {
    "None",
    "Direct",	// RT_DIRECT
    "SPF",	// RT_SPF
    "SPFIA",	// RT_SPFIA
    "SPFE1",	// RT_EXTT1
    "SPFE2",	// RT_EXTT2
    "Reject",	// RT_REJECT
    "Static",	// RT_STATIC
    "Deleted",	// RT_NONE
};


/* Create a single hop routing table entry
 * Don't add virtual links as next hops.
 */

MPath *MPath::create(SpfIfc *ip, InAddr addr)

{
    NH paths[MAXPATH];

    if (ip->is_virtual())
	return(0);
    paths[0].o_ifp = ip;
    paths[0].phyint = ip->if_phyint;
    paths[0].gw = addr;
    return(create(1, paths));
}

/* Create a single hop routing table entry, when
 * you only know the physical interface, not necessary
 * an OSPF interface. Used when adding static routes
 * (advertised by us in AS-external-LSAs) to the routing
 * table.
 * "merge" and "addgw" not called on these next hops, and
 * so phyint need not be included in sort.
 */

MPath *MPath::create(int phyint, InAddr addr)

{
    NH paths[MAXPATH];

    paths[0].o_ifp = 0;
    paths[0].phyint = phyint;
    paths[0].gw = addr;
    return(create(1, paths));
}

/* Add an equal-cost path to a multipath entry, returning
 * the new entry.
 */

MPath *MPath::merge(MPath *mp1, MPath *mp2)

{
    int n_paths = 0;
    NH paths[MAXPATH];
    int i, j;

    if (!mp1)
	return(mp2);
    else if (!mp2)
	return(mp1);
    else if (mp1->npaths == MAXPATH)
	return(mp1);
    else if (mp2->npaths == MAXPATH)
	return(mp2);

    // Merge two sorted multipath entries
    i = 0;
    j = 0;
    for (; i < mp1->npaths && n_paths < MAXPATH; i++) {
	for (; j < mp2->npaths && n_paths < MAXPATH; j++) {
	    if (mp1->NHs[i].o_ifp < mp2->NHs[j].o_ifp)
		break;
	    else if (mp1->NHs[i].o_ifp > mp2->NHs[j].o_ifp)
		paths[n_paths++] = mp2->NHs[j];
	    else if (mp1->NHs[i].phyint < mp2->NHs[j].phyint)
		break;
	    else if (mp1->NHs[i].phyint > mp2->NHs[j].phyint)
		paths[n_paths++] = mp2->NHs[j];
	    else if (mp1->NHs[i].gw < mp2->NHs[j].gw)
		break;
	    else if (mp1->NHs[i].gw > mp2->NHs[j].gw)
		paths[n_paths++] = mp2->NHs[j];
	    else
		continue;
	}
	paths[n_paths++] = mp1->NHs[i];
    }
    // Complete second multipath entry
    for (; j < mp2->npaths && n_paths < MAXPATH; j++)
	paths[n_paths++] = mp2->NHs[j];

    return(create(n_paths, paths));
}

/* Change the gateway entry for one or more directly attached
 * hops. Handles the case where the neighbor advertises two or
 * more addresses on the same subnet.
 */

MPath *MPath::addgw(MPath *mp, InAddr gw)

{
    bool modified=false;
    NH paths[MAXPATH];
    int i, j;
    int n_paths = mp->npaths;

    for (i = 0, j = 0; i < mp->npaths; i++, j++) {
	SpfIfc *ip;
	paths[j] = mp->NHs[i];
	if (!(ip = paths[j].o_ifp))
	    continue;
	else if (ip->net() == 0 || (ip->mask() & gw) != ip->net())
	    continue;
	else if (paths[j].gw == 0) {
	    paths[j].gw = gw;
	    modified = true;
	}
	else if (n_paths == MAXPATH ||
		 paths[j].gw == gw ||
		 (mp->NHs[i+1].o_ifp == ip && paths[j].gw < gw))
	    continue;
	else {
	    modified = true;
	    j++, n_paths++;
	    paths[j].o_ifp = ip;
	    paths[j].phyint = paths[j-1].phyint;
	    if (paths[j-1].gw < gw)
		paths[j].gw = gw;
	    else {
		paths[j].gw = paths[j-1].gw;
		paths[j-1].gw = gw;
	    }
	}
    }

    return(modified ? create(n_paths, paths) : mp);
}

/* Look for an entry in the multipath database. If it's not
 * already there, create it and add to the database.
 * Argument assumed to be an array of size MAXPATH.
 */

MPath *MPath::create(int n_paths, NH *paths)

{
    int i;
    MPath *entry;
    int len;

    // Zero rest of entry
    for (i = n_paths; i < MAXPATH; i++) {
	paths[i].o_ifp = 0;
	paths[i].phyint = 0;
	paths[i].gw = 0;
    }
    //  If already in database, return existing entry
    len = sizeof(NH[MAXPATH]);
    if ((entry = (MPath *) nhdb.find((byte *)paths, len)))
	return(entry);

    // Create new entry
    entry = new MPath;
    entry->npaths = n_paths;
    for (i = 0; i < MAXPATH; i++)
	entry->NHs[i] = paths[i];
    // Add to database
    entry->key = (byte *) entry->NHs;
    entry->keylen = len;
    nhdb.add(entry);
    return(entry);
}

/* Determine whether all the next hops belong to a givem area.
 * If so, don't advertise summary-LSAs into that area.
 */

bool MPath::all_in_area(SpfArea *a)

{
    int i;

    for (i = 0; i < npaths; i++)
	if (NHs[i].o_ifp->area() != a)
	    return(false);
    return(true);
}

/* Add an entry to an IP routing table entry. Install the
 * prefix pointers so that the best match operations will
 * work correctly.
 */

INrte *INtbl::add(uns32 net, uns32 mask)

{
    INrte *rte;
    INrte *parent;
    INrte *child;
    INiterator iter(this);

    if ((rte = (INrte *) root.find(net, mask)))
	return(rte);
    // Add to routing table entry
    rte = new INrte(net, mask);
    root.add(rte);
    // Set prefix pointer
    rte->_prefix = 0;
    parent = (INrte *) root.previous(net, mask);
    for (; parent; parent = parent->prefix()) {
	if (rte->is_child(parent)) {
	    rte->_prefix = parent;
	    break;
	}
    }
    // Set children's parent pointers
    iter.seek(rte);
    while ((child = iter.nextrte()) && child->is_child(rte)) {
	if (child->prefix() && child->prefix()->is_child(rte))
	    continue;
	child->_prefix = rte;
    }

    return(rte);
}

/* Find the best matching routing table entry for a given
 * IP destination.
 */

INrte *INtbl::best_match(uns32 addr)

{
    INrte *rte;
    INrte *prev;

    rte = (INrte *) root.root();
    prev = 0;
    while (rte) {
	if (addr < rte->net())
	    rte = (INrte *) rte->go_left();
	else if (addr > rte->net() ||
		 0xffffffff > rte->mask()) {
	    prev = rte;
	    rte = (INrte *) rte->go_right();
	}
	else
	    // Matching host route
	    break;
    }

    // If no exact match, take previous entry
    if (!rte)
	rte = prev;
    // Go up prefix chain, looking for valid routes
    for (; rte; rte = rte->prefix()) {
	if ((addr & rte->mask()) != rte->net())
	    continue;
	if (rte->valid())
	    break;
    }

    return(rte);
}

/* Add an item to the forwarding database.
 */

FWDrte *FWDtbl::add(uns32 addr)

{
    FWDrte *fwde;

    if ((fwde = (FWDrte *) root.find(addr, 0)))
	return(fwde);

    fwde = new FWDrte(addr);
    root.add(fwde);
    return(fwde);
}

