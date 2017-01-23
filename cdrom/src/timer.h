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

/* Declaration of OSPF timer classes.
 */

/* Implementation of a timer
 * Base class implements a single shot timer.
 * Derived class implements an interval timer
 */

class Timer : public PriQElt {
protected:
    int	active:1;
    uns32 period;		// Period in milliseconds
public:
    enum { SECOND = 1000};
    Timer() {
	active=false;
	period = 0;
    }

    void stop();
    void restart(int millseconds=0);// Stop and start again
    inline int is_running();
    int milliseconds_to_firing();
    virtual void start(int milliseconds, bool randomize=true);
    virtual void fire();
    virtual void action() = 0;
};

// Inline functions
inline int Timer::is_running()
{
    return(active);
}

/* Implementation of a interval timer
 * When start, offsets initial interval in
 * an attempt to randomize. When fires, requeues
 * the timer automatically.
 */

class ITimer : public Timer {
public:
    virtual void start(int milliseconds, bool randomize=true);
    virtual void fire();
    virtual void action() = 0;
};

/* Time constants as used in OSPF timer queue. Time is divided
 * into seconds and microseconds since the program started.
 */

class SPFtime {
public:
    uns32 sec;		// Seconds since start
    uns32 msec;		// Milliseconds since start
};

bool	time_less(SPFtime &a, SPFtime &b);
void	time_add(SPFtime &a, SPFtime &b, SPFtime *result);
void	time_add(SPFtime &a, int milliseconds, SPFtime *result);
bool	time_equal(SPFtime &a, SPFtime &b);
int	time_diff(SPFtime &a, SPFtime &b);

