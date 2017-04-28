/*
Copyright (c) 1997, 1998 Carnegie Mellon University.  All Rights
Reserved. 

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems.

*/

#ifndef __proaodv_h__
#define __proaodv_h__

//#include <agent.h>
//#include <packet.h>
//#include <sys/types.h>
//#include <cmu/list.h>
//#include <scheduler.h>

#include <cmu-trace.h>
#include <priqueue.h>
#include <proaodv/proaodv_rtable.h>
#include <proaodv/proaodv_rqueue.h>
#include <classifier/classifier-port.h>
#include <mac.h>

/*
  Allows local repair of routes 
*/
#define AODV_LOCAL_REPAIR

/*
  Allows AODV to use link-layer (802.11) feedback in determining when
  links are up/down.
*/
#define AODV_LINK_LAYER_DETECTION

/*
  Causes AODV to apply a "smoothing" function to the link layer feedback
  that is generated by 802.11.  In essence, it requires that RT_MAX_ERROR
  errors occurs within a window of RT_MAX_ERROR_TIME before the link
  is considered bad.
*/
#define AODV_USE_LL_METRIC

/*
  Only applies if AODV_USE_LL_METRIC is defined.
  Causes AODV to apply omniscient knowledge to the feedback received
  from 802.11.  This may be flawed, because it does not account for
  congestion.
*/
//#define AODV_USE_GOD_FEEDBACK


class PROAODV;

#define MY_ROUTE_TIMEOUT        10                      	// 100 seconds
#define ACTIVE_ROUTE_TIMEOUT    10				// 50 seconds
#define REV_ROUTE_LIFE          6				// 5  seconds
#define BCAST_ID_SAVE           6				// 3 seconds


// No. of times to do network-wide search before timing out for 
// MAX_RREQ_TIMEOUT sec. 
#define RREQ_RETRIES            3  
// timeout after doing network-wide search RREQ_RETRIES times
#define MAX_RREQ_TIMEOUT	10.0 //sec

/* Various constants used for the expanding ring search */
#define TTL_START     5
#define TTL_THRESHOLD 7
#define TTL_INCREMENT 2 

// This should be somewhat related to arp timeout
#define NODE_TRAVERSAL_TIME     0.03             // 30 ms
#define LOCAL_REPAIR_WAIT_TIME  0.15 //sec

// Should be set by the user using best guess (conservative) 
#define NETWORK_DIAMETER        30             // 30 hops

// Must be larger than the time difference between a node propagates a route 
// request and gets the route reply back.

//#define RREP_WAIT_TIME     (3 * NODE_TRAVERSAL_TIME * NETWORK_DIAMETER) // ms
//#define RREP_WAIT_TIME     (2 * REV_ROUTE_LIFE)  // seconds
#define RREP_WAIT_TIME         1.0  // sec

#define ID_NOT_FOUND    0x00
#define ID_FOUND        0x01
//#define INFINITY        0xff

// The followings are used for the forward() function. Controls pacing.
#define DELAY 1.0           // random delay
#define NO_DELAY -1.0       // no delay 

// think it should be 30 ms
#define ARP_DELAY 0.01      // fixed delay to keep arp happy


#define HELLO_INTERVAL          1               // 1000 ms
#define ALLOWED_HELLO_LOSS      3               // packets
#define BAD_LINK_LIFETIME       3               // 3000 ms
#define MaxHelloInterval        (1.25 * HELLO_INTERVAL)
#define MinHelloInterval        (0.75 * HELLO_INTERVAL)

/*
  Timers (Broadcast ID, Hello, Neighbor Cache, Route Cache)
*/
class ProAodvBroadcastTimer : public Handler {
public:
        ProAodvBroadcastTimer(PROAODV* a) : agent(a) {}
        void	handle(Event*);
private:
        PROAODV    *agent;
	Event	intr;
};

class ProAodvHelloTimer : public Handler {
public:
        ProAodvHelloTimer(PROAODV* a) : agent(a) {}
        void	handle(Event*);
private:
        PROAODV    *agent;
	Event	intr;
};

class ProAodvNeighborTimer : public Handler {
public:
        ProAodvNeighborTimer(PROAODV* a) : agent(a) {}
        void	handle(Event*);
private:
        PROAODV    *agent;
	Event	intr;
};

class ProAodvRouteCacheTimer : public Handler {
public:
        ProAodvRouteCacheTimer(PROAODV* a) : agent(a) {}
        void	handle(Event*);
private:
        PROAODV    *agent;
	Event	intr;
};

class ProAodvLocalRepairTimer : public Handler {
public:
        ProAodvLocalRepairTimer(PROAODV* a) : agent(a) {}
        void	handle(Event*);
private:
        PROAODV    *agent;
	Event	intr;
};


/*
  Broadcast ID Cache
*/
class ProAodvBroadcastID {
        friend class PROAODV;
 public:
        ProAodvBroadcastID(nsaddr_t i, u_int32_t b) { src = i; id = b;  }
 protected:
        LIST_ENTRY(ProAodvBroadcastID) link;
        nsaddr_t        src;
        u_int32_t       id;
        double          expire;         // now + BCAST_ID_SAVE s
};

LIST_HEAD(aodv_bcache, ProAodvBroadcastID);


/*
  The Routing Agent
*/
class PROAODV: public Tap, public Agent {

  /*
   * make some friends first 
   */

        friend class proaodv_rt_entry;
        friend class ProAodvBroadcastTimer;
        friend class ProAodvHelloTimer;
        friend class ProAodvNeighborTimer;
        friend class ProAodvRouteCacheTimer;
        friend class ProAodvLocalRepairTimer;

 public:
        PROAODV(nsaddr_t id);
        //to support promiscuous mode
        void        tap(const Packet *p);

        void		recv(Packet *p, Handler *);
        bool        isClusterhead();

 protected:
        int             command(int, const char *const *);
        int             initialized() { return 1 && target_; }
        // To support promiscuous mode
        bool promiscuous_mode;
        Mac *mac_;
        
        /*
         * Route Table Management
         */
        void            rt_resolve(Packet *p);
        void            rt_update(proaodv_rt_entry *rt, u_int32_t seqnum,
		     	  	u_int16_t metric, nsaddr_t nexthop,
		      		double expire_time);
        void            rt_down(proaodv_rt_entry *rt);
        void            local_rt_repair(proaodv_rt_entry *rt, Packet *p);
 public:
        void            rt_ll_failed(Packet *p);
        void            handle_link_failure(nsaddr_t id);
 protected:
        void            rt_purge(void);

        void            enque(proaodv_rt_entry *rt, Packet *p);
        Packet*         deque(proaodv_rt_entry *rt);

        /*
         * Neighbor Management
         */
        void            nb_insert(nsaddr_t id);
        void            nb_insert(nsaddr_t id, bool clusterhead);
        PROAODV_Neighbor*       nb_lookup(nsaddr_t id);
        void            nb_delete(nsaddr_t id);
        void            nb_purge(void);

        /*
         * Broadcast ID Management
         */

        void            id_insert(nsaddr_t id, u_int32_t bid);
        bool	        id_lookup(nsaddr_t id, u_int32_t bid);
        void            id_purge(void);

        /*
         * Packet TX Routines
         */
        void            forward(proaodv_rt_entry *rt, Packet *p, double delay);
        void            sendHello(void);
        bool            sendSpecialMsg(proaodv_rt_entry *rt, Packet *p);
        void            sendRequest(nsaddr_t dst);

        void            sendReply(nsaddr_t ipdst, u_int32_t hop_count,
                                  nsaddr_t rpdst, u_int32_t rpseq,
                                  u_int32_t lifetime, double timestamp);
        void            sendError(Packet *p, bool jitter = true);
                                          
        /*
         * Packet RX Routines
         */
        void            recvPROAODV(Packet *p);
        void            recvHello(Packet *p);
        void            recvSpecialMsg(Packet *p);
        void            recvRequest(Packet *p);
        void            recvReply(Packet *p);
        void            recvError(Packet *p);

	/*
	 * History management
	 */
	
	double 		PerHopTime(proaodv_rt_entry *rt);


        nsaddr_t        index;                  // IP Address of this node
        u_int32_t       seqno;                  // Sequence Number
        int             bid;                    // Broadcast ID

        proaodv_rtable         rthead;                 // routing table
        proaodv_ncache         nbhead;                 // Neighbor Cache
        aodv_bcache          bihead;                 // Broadcast ID Cache

        /*
         * Timers
         */
        ProAodvBroadcastTimer  btimer;
        ProAodvHelloTimer      htimer;
        ProAodvNeighborTimer   ntimer;
        ProAodvRouteCacheTimer rtimer;
        ProAodvLocalRepairTimer lrtimer;

        /*
         * Routing Table
         */
        proaodv_rtable          rtable;
        /*
         *  A "drop-front" queue used by the routing layer to buffer
         *  packets to which it does not have a route.
         */
        proaodv_rqueue         rqueue;

        /*
         * A mechanism for logging the contents of the routing
         * table.
         */
        Trace           *logtarget;

        /*
         * A pointer to the network interface queue that sits
         * between the "classifier" and the "link layer".
         */
        PriQueue        *ifqueue;

        /*
         * Logging stuff
         */
        void            log_link_del(nsaddr_t dst);
        void            log_link_broke(Packet *p);
        void            log_link_kept(nsaddr_t dst);

	/* for passing packets up to agents */
	PortClassifier *dmux_;
    
    /**
     * Cluster Head management
     */
    bool clusterhead;
    struct monitor_info {
      nsaddr_t src;
      nsaddr_t dst;
      nsaddr_t nexthop;
    };
    monitor_info mi;
    nsaddr_t mi_src;
    nsaddr_t mi_dst;
    nsaddr_t mi_nexthop;
};

#endif /* __aodv_h__ */
