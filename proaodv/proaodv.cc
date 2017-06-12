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

The AODV code developed by the CMU/MONARCH group was optimized and tuned by Samir Das and Mahesh Marina, University of Cincinnati. The work was partially done in Sun Microsystems. Modified for gratuitous replies by Anant Utgikar, 09/16/02.

*/

//#include <ip.h>

#include <proaodv/proaodv.h>
#include <proaodv/proaodv_packet.h>
#include <random.h>
#include <cmu-trace.h>
//#include <energy-model.h>

#define max(a,b)        ( (a) > (b) ? (a) : (b) )
#define CURRENT_TIME    Scheduler::instance().clock()

#define DEBUG = true;
//#define ERROR

#ifdef DEBUG
static int route_request = 0;
#endif
#ifdef DEBUG
static int special_message_request = 0;
#endif


/*
  TCL Hooks
 */


int hdr_proaodv::offset_;

static class PROAODVHeaderClass : public PacketHeaderClass {
public:

  PROAODVHeaderClass() : PacketHeaderClass("PacketHeader/PROAODV",
  sizeof (hdr_all_proaodv)) {
    bind_offset(&hdr_proaodv::offset_);
  }
} class_rtProtoAODV_hdr;

static class PROAODVclass : public TclClass {
public:

  PROAODVclass() : TclClass("Agent/PROAODV") {
  }

  TclObject* create(int argc, const char*const* argv) {
    assert(argc == 5);
    //return (new AODV((nsaddr_t) atoi(argv[4])));
    return (new PROAODV((nsaddr_t) Address::instance().str2addr(argv[4])));
  }
} class_rtProtoAODV;

int
PROAODV::command(int argc, const char*const* argv) {
  if (argc == 2) {
    Tcl& tcl = Tcl::instance();

    if (strncasecmp(argv[1], "id", 2) == 0) {
      tcl.resultf("%d", index);
      return TCL_OK;
    }
    if (strncasecmp(argv[1], "clusterh", 8) == 0) {
      fprintf(stderr, "node %d, has clusterhead = %d : command is %s\n", index, clusterhead, argv[1]);
      this->clusterhead = true;
#ifdef DEBUG
      fprintf(stderr, "node %d, has clusterhead = %d : command is %s\n", index, clusterhead, argv[1]);
#endif
      return TCL_OK;
    }

    if (strncasecmp(argv[1], "start", 2) == 0) {
      btimer.handle((Event*) 0);

//#ifndef AODV_LINK_LAYER_DETECTION
      htimer.handle((Event*) 0);
      ntimer.handle((Event*) 0);
//#endif // LINK LAYER DETECTION

      rtimer.handle((Event*) 0);
      return TCL_OK;
    }
  } else if (argc == 3) {
    if (strcmp(argv[1], "index") == 0) {
      index = atoi(argv[2]);
      return TCL_OK;
    }
    else if (strcmp(argv[1], "log-target") == 0 || strcmp(argv[1], "tracetarget") == 0) {
      logtarget = (Trace*) TclObject::lookup(argv[2]);
      if (logtarget == 0)
        return TCL_ERROR;
      return TCL_OK;
    } else if (strcmp(argv[1], "drop-target") == 0) {
      int stat = rqueue.command(argc, argv);
      if (stat != TCL_OK) return stat;
      return Agent::command(argc, argv);
    } else if (strcmp(argv[1], "if-queue") == 0) {
      ifqueue = (PriQueue*) TclObject::lookup(argv[2]);

      if (ifqueue == 0)
        return TCL_ERROR;
      return TCL_OK;
    } else if (strcmp(argv[1], "port-dmux") == 0) {
      dmux_ = (PortClassifier *) TclObject::lookup(argv[2]);
      if (dmux_ == 0) {
        fprintf(stderr, "%s: %s lookup of %s failed\n", __FILE__,
                argv[1], argv[2]);
        return TCL_ERROR;
      }
      return TCL_OK;
    } else if (strcmp(argv[1], "install-tap") == 0) {
      mac_ = (Mac*) TclObject::lookup(argv[2]);
      if (mac_ == 0) return TCL_ERROR;
      mac_->installTap(this);
      return TCL_OK;
    }
  }
  return Agent::command(argc, argv);
}

/* 
   Constructor
 */

PROAODV::PROAODV(nsaddr_t id) : Agent(PT_PROAODV),
  btimer(this), htimer(this), ntimer(this), rtimer(this), lrtimer(this), vrtimer(this), alerttimer(this), rqueue() {
  // alerttimer(this),
  index = id;
  seqno = 2;
  bid = 1;
  clusterhead = false;
  promiscuous_mode = false;
  //  bind("clusterhead_", &clusterhead); 

  LIST_INIT(&nbhead);
  LIST_INIT(&bihead);

  logtarget = 0;
  ifqueue = 0;
}

/*
  Timers
 */

void
ProAodvBroadcastTimer::handle(Event*) {
  agent->id_purge();
  Scheduler::instance().schedule(this, &intr, BCAST_ID_SAVE);
}

void
ProAodvHelloTimer::handle(Event*) {
  agent->sendHello();
  double interval = MinHelloInterval +
          ((MaxHelloInterval - MinHelloInterval) * Random::uniform());
  assert(interval >= 0);
  Scheduler::instance().schedule(this, &intr, interval);
}

void
ProAodvNeighborTimer::handle(Event*) {
  agent->nb_purge();
  Scheduler::instance().schedule(this, &intr, HELLO_INTERVAL);
}

void
ProAodvRouteCacheTimer::handle(Event*) {
  agent->rt_purge();
#define FREQUENCY 0.5 // sec
  Scheduler::instance().schedule(this, &intr, FREQUENCY);
}

void
ProAodvLocalRepairTimer::handle(Event* p) { // SRD: 5/4/99
  proaodv_rt_entry *rt;
  struct hdr_ip *ih = HDR_IP((Packet *) p);

  /* you get here after the timeout in a local repair attempt */
  /*	fprintf(stderr, "%s\n", __FUNCTION__); */


  rt = agent->rtable.rt_lookup(ih->daddr());

  if (rt && rt->rt_flags != RTF_UP) {
    // route is yet to be repaired
    // I will be conservative and bring down the route
    // and send route errors upstream.
    /* The following assert fails, not sure why */
    /* assert (rt->rt_flags == RTF_IN_REPAIR); */

    //rt->rt_seqno++;
    agent->rt_down(rt);
    // send RERR
#ifdef DEBUG
    fprintf(stderr, "Dst - %d, failed local repair\n", rt->rt_dst);
#endif      
  }
  Packet::free((Packet *) p);
}

void
ProAodvSendVoteTimer::handle(Event*) {
  if(agent->mi_nexthop != 0)  {
    agent->sendVoteRequest(agent->mi_nexthop);
  }
}

void
ProAodvSendAlertTimer::handle(Event* p) {
  if(agent->mi_nexthop != 0)  {
    agent->sendVoteRequest(agent->mi_nexthop);
  }
}

/**
 * The Handle packets received in Promiscuous mode
 * @param p
 */
void
PROAODV::tap(const Packet *p) {
  //#ifdef DEBUG
  //      fprintf(stderr,"Promiscuous mode node(%d) got Packet in function %s\n", index,  __FUNCTION__);
  //#endif 
  if (promiscuous_mode == false) {
    return;
  }
  struct hdr_cmn *hdr = HDR_CMN(p);
  struct hdr_ip *iph = HDR_IP(p);
  struct hdr_proaodv_reply *rp = HDR_PROAODV_REPLY(p);
  if (p_info::data_packet(hdr->ptype_)) {
#ifdef DEBUG
    fprintf(stderr, "Promiscuous mode: node(%d) got Packet with type - %d, nexthop - %d, prevhop - %d, Dst - %d, Src - %d \n",
            index,
            hdr->ptype_,
            hdr->next_hop_,
            hdr->prev_hop_,
            iph->dst_.addr_,
            iph->src_.addr_
            );
//    fprintf(stderr, "Promiscuous mode: node(%d) got Packet with nexthop - %d \n", index, hdr->next_hop_);
//    fprintf(stderr, "Promiscuous mode: node(%d) got Packet with prevhop - %d \n", index, hdr->prev_hop_);
//    fprintf(stderr, "Promiscuous mode: node(%d) got Packet with Dst - %d \n", index, iph->dst_.addr_);
//    fprintf(stderr, "Promiscuous mode: node(%d) got Packet with Src - %d \n", index, iph->src_.addr_);
//    fprintf(stderr, "Promiscuous mode: node(%d) got Packet with Reply Src - %d \n", index, rp->rp_src); This is always 0???
#endif
    if(mi_timeout > CURRENT_TIME)   {
      promiscuous_mode = false;
    }
    if (mi_src == iph->src_.addr_ && mi_dst == iph->dst_.addr_ && mi_nexthop != hdr->next_hop_ && hdr->last_hop_ == mi_nexthop) {
        //TODO add the timing mechanism to trigger the vote
#ifdef DEBUG
      fprintf(stderr, "Promiscuous mode: node(%d) found our packet to from %d to %d nexthop_ not %d and last_hop_ is %d \n\n",
              index, iph->src_.addr_, iph->dst_.addr_, mi_nexthop, hdr->last_hop_);
#endif
//      bool found = true;
      mi_nexthop = 0;
      mi_dst = 0;
      mi_src = 0;
      promiscuous_mode = false;
    }
  }
}

/*
 * Broadcast ID Management  Functions
 */
void
PROAODV::id_insert(nsaddr_t id, u_int32_t bid) {
  ProAodvBroadcastID *b = new ProAodvBroadcastID(id, bid);

  assert(b);
  b->expire = CURRENT_TIME + BCAST_ID_SAVE;
  LIST_INSERT_HEAD(&bihead, b, link);
}

/* SRD */
bool
PROAODV::id_lookup(nsaddr_t id, u_int32_t bid) {
  ProAodvBroadcastID *b = bihead.lh_first;

  // Search the list for a match of source and bid
  for (; b; b = b->link.le_next) {
    if ((b->src == id) && (b->id == bid))
      return true;
  }
  return false;
}

void
PROAODV::id_purge() {
  ProAodvBroadcastID *b = bihead.lh_first;
  ProAodvBroadcastID *bn;
  double now = CURRENT_TIME;

  for (; b; b = bn) {
    bn = b->link.le_next;
    if (b->expire <= now) {
      LIST_REMOVE(b, link);
      delete b;
    }
  }
}

/*
  Helper Functions
 */

double
PROAODV::PerHopTime(proaodv_rt_entry *rt) {
  int num_non_zero = 0, i;
  double total_latency = 0.0;

  if (!rt)
    return ((double) NODE_TRAVERSAL_TIME);

  for (i = 0; i < MAX_HISTORY; i++) {
    if (rt->rt_disc_latency[i] > 0.0) {
      num_non_zero++;
      total_latency += rt->rt_disc_latency[i];
    }
  }
  if (num_non_zero > 0)
    return (total_latency / (double) num_non_zero);
  else
    return ((double) NODE_TRAVERSAL_TIME);

}

/*
  Link Failure Management Functions
 */

static void
proaodv_rt_failed_callback(Packet *p, void *arg) {
  ((PROAODV*) arg)->rt_ll_failed(p);
}

/*
 * This routine is invoked when the link-layer reports a route failed.
 */
void
PROAODV::rt_ll_failed(Packet *p) {
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  proaodv_rt_entry *rt;
  nsaddr_t broken_nbr = ch->next_hop_;

#ifndef PROAODV_LINK_LAYER_DETECTION
  drop(p, DROP_RTR_MAC_CALLBACK);
#else 

  /*
   * Non-data packets and Broadcast Packets can be dropped.
   */
  if (!DATA_PACKET(ch->ptype()) ||
          (u_int32_t) ih->daddr() == IP_BROADCAST) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_broke(p);
  if ((rt = rtable.rt_lookup(ih->daddr())) == 0) {
    drop(p, DROP_RTR_MAC_CALLBACK);
    return;
  }
  log_link_del(ch->next_hop_);

#ifdef PROAODV_LOCAL_REPAIR
  /* if the broken link is closer to the dest than source, 
     attempt a local repair. Otherwise, bring down the route. */


  if (ch->num_forwards() > rt->rt_hops) {
    local_rt_repair(rt, p); // local repair
    // retrieve all the packets in the ifq using this link,
    // queue the packets for which local repair is done, 
    return;
  } else
#endif // LOCAL REPAIR	
 {
    drop(p, DROP_RTR_MAC_CALLBACK);
    // Do the same thing for other packets in the interface queue using the
    // broken link -Mahesh
    while ((p = ifqueue->filter(broken_nbr))) {
      drop(p, DROP_RTR_MAC_CALLBACK);
    }
    nb_delete(broken_nbr);
  }

#endif // LINK LAYER DETECTION
}

void
PROAODV::handle_link_failure(nsaddr_t id) {
  proaodv_rt_entry *rt, *rtn;
  Packet *rerr = Packet::alloc();
  struct hdr_proaodv_error *re = HDR_PROAODV_ERROR(rerr);

  re->DestCount = 0;
  for (rt = rtable.head(); rt; rt = rtn) { // for each rt entry
    rtn = rt->rt_link.le_next;
    if ((rt->rt_hops != INFINITY2) && (rt->rt_nexthop == id)) {
      assert(rt->rt_flags == RTF_UP);
      assert((rt->rt_seqno % 2) == 0);
      rt->rt_seqno++;
      re->unreachable_dst[re->DestCount] = rt->rt_dst;
      re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
#ifdef DEBUG
      fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
              index, re->unreachable_dst[re->DestCount],
              re->unreachable_dst_seqno[re->DestCount], rt->rt_nexthop);
#endif // DEBUG
      re->DestCount += 1;
      rt_down(rt);
    }
    // remove the lost neighbor from all the precursor lists
    rt->pc_delete(id);
  }

  if (re->DestCount > 0) {
#ifdef DEBUG
    fprintf(stderr, "%s(%f): %d\tsending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
    sendError(rerr, false);
  } else {
    Packet::free(rerr);
  }
}

void
PROAODV::local_rt_repair(proaodv_rt_entry *rt, Packet *p) {
#ifdef DEBUG
  fprintf(stderr, "%s: Dst - %d\n", __FUNCTION__, rt->rt_dst);
#endif  
  // Buffer the packet 
  rqueue.enque(p);

  // mark the route as under repair 
  rt->rt_flags = RTF_IN_REPAIR;

  sendRequest(rt->rt_dst);

  // set up a timer interrupt
  Scheduler::instance().schedule(&lrtimer, p->copy(), rt->rt_req_timeout);
}

void
PROAODV::rt_update(proaodv_rt_entry *rt, u_int32_t seqnum, u_int16_t metric,
        nsaddr_t nexthop, double expire_time) {

  rt->rt_seqno = seqnum;
  rt->rt_hops = metric;
  rt->rt_flags = RTF_UP;
  rt->rt_nexthop = nexthop;
  rt->rt_expire = expire_time;
}

void
PROAODV::rt_down(proaodv_rt_entry *rt) {
  /*
   *  Make sure that you don't "down" a route more than once.
   */

  if (rt->rt_flags == RTF_DOWN) {
    return;
  }

  // assert (rt->rt_seqno%2); // is the seqno odd?
  rt->rt_last_hop_count = rt->rt_hops;
  rt->rt_hops = INFINITY2;
  rt->rt_flags = RTF_DOWN;
  rt->rt_nexthop = 0;
  rt->rt_expire = 0;

} /* rt_down function */

/*
  Route Handling Functions
 */

void
PROAODV::rt_resolve(Packet *p) {
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  proaodv_rt_entry *rt;

  /*
   *  Set the transmit failure callback.  That
   *  won't change.
   */
  ch->xmit_failure_ = proaodv_rt_failed_callback;
  ch->xmit_failure_data_ = (void*) this;
  rt = rtable.rt_lookup(ih->daddr());
  if (rt == 0) {
    rt = rtable.rt_add(ih->daddr());
  }

  /*
   * If the route is up, forward the packet 
   */

  if (rt->rt_flags == RTF_UP) {
    assert(rt->rt_hops != INFINITY2);
    //TODO Possibly Add the special message sending here (Have to recheck)?
//    sendSpecialMsg(rt,p);
    forward(rt, p, NO_DELAY);
  }    /*
  *  if I am the source of the packet, then do a Route Request.
  */
  else if (ih->saddr() == index) {
    rqueue.enque(p);
    sendRequest(rt->rt_dst);
  }    /*
  *	A local repair is in progress. Buffer the packet. 
  */
  else if (rt->rt_flags == RTF_IN_REPAIR) {
    rqueue.enque(p);
  }
    /*
     * I am trying to forward a packet for someone else to which
     * I don't have a route.
     */
  else {
    Packet *rerr = Packet::alloc();
    struct hdr_proaodv_error *re = HDR_PROAODV_ERROR(rerr);
    /* 
     * For now, drop the packet and send error upstream.
     * Now the route errors are broadcast to upstream
     * neighbors - Mahesh 09/11/99
     */

    assert(rt->rt_flags == RTF_DOWN);
    re->DestCount = 0;
    re->unreachable_dst[re->DestCount] = rt->rt_dst;
    re->unreachable_dst_seqno[re->DestCount] = rt->rt_seqno;
    re->DestCount += 1;
#ifdef DEBUG
    fprintf(stderr, "%s: sending RERR...\n", __FUNCTION__);
#endif
    sendError(rerr, false);

    drop(p, DROP_RTR_NO_ROUTE);
  }

}

void
PROAODV::rt_purge() {
  proaodv_rt_entry *rt, *rtn;
  double now = CURRENT_TIME;
  double delay = 0.0;
  Packet *p;

  for (rt = rtable.head(); rt; rt = rtn) { // for each rt entry
    rtn = rt->rt_link.le_next;
    if ((rt->rt_flags == RTF_UP) && (rt->rt_expire < now)) {
      // if a valid route has expired, purge all packets from 
      // send buffer and invalidate the route.                    
      assert(rt->rt_hops != INFINITY2);
      while ((p = rqueue.deque(rt->rt_dst))) {
#ifdef DEBUG
        fprintf(stderr, "%s: calling drop()\n",
                __FUNCTION__);
#endif // DEBUG
        drop(p, DROP_RTR_NO_ROUTE);
      }
      rt->rt_seqno++;
      assert(rt->rt_seqno % 2);
      rt_down(rt);
    } else if (rt->rt_flags == RTF_UP) {
      // If the route is not expired,
      // and there are packets in the sendbuffer waiting,
      // forward them. This should not be needed, but this extra 
      // check does no harm.
      assert(rt->rt_hops != INFINITY2);
      while ((p = rqueue.deque(rt->rt_dst))) {
        forward(rt, p, delay);
        delay += ARP_DELAY;
      }
    }
    else if (rqueue.find(rt->rt_dst))
      // If the route is down and 
      // if there is a packet for this destination waiting in
      // the sendbuffer, then send out route request. sendRequest
      // will check whether it is time to really send out request
      // or not.
      // This may not be crucial to do it here, as each generated 
      // packet will do a sendRequest anyway.

      sendRequest(rt->rt_dst);
  }

}

/*
  Packet Reception Routines
 */

void
PROAODV::recv(Packet *p, Handler*) {
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);

  assert(initialized());
  //assert(p->incoming == 0);
  // XXX NOTE: use of incoming flag has been deprecated; In order to track direction of pkt flow, direction_ in hdr_cmn is used instead. see packet.h for details.
  if (p_info::data_packet(ch->ptype())) {
    #ifdef DEBUG
        fprintf(stderr, "%s: node(%d) calling nb_update: prev_hop: %d, last_hop: %d, next_hop: %d, dst: %d, src: %d\n", 
                __FUNCTION__,
                index,
                ch->prev_hop_,
                ch->last_hop_,
                ch->next_hop_,
                ih->dst_.addr_,
                ih->src_.addr_
                );
    #endif // DEBUG
    nb_update(ch->last_hop_, CURRENT_TIME);
  }
      
  if (ch->ptype() == PT_PROAODV) {
    ih->ttl_ -= 1;
    recvPROAODV(p);
    return;
  }


  /*
   *  Must be a packet I'm originating...
   */
  if ((ih->saddr() == index) && (ch->num_forwards() == 0)) {
    /*
     * Add the IP Header.  
     * TCP adds the IP header too, so to avoid setting it twice, we check if
     * this packet is not a TCP or ACK segment.
     */
    if (ch->ptype() != PT_TCP && ch->ptype() != PT_ACK) {
      ch->size() += IP_HDR_LEN;
    }
    // Added by Parag Dadhania && John Novatnack to handle broadcasting
    if ((u_int32_t) ih->daddr() != IP_BROADCAST) {
      ih->ttl_ = NETWORK_DIAMETER;
    }
  }    
 /*
  *  I received a packet that I sent.  Probably
  *  a routing loop.
  */
  else if (ih->saddr() == index) {
    drop(p, DROP_RTR_ROUTE_LOOP);
    return;
  }    
 /*
  *  Packet I'm forwarding...
  */
  else {
    /*
     *  Check the TTL.  If it is zero, then discard.
     */
    if (--ih->ttl_ == 0) {
      drop(p, DROP_RTR_TTL);
      return;
    }
  }
  // Added by Parag Dadhania && John Novatnack to handle broadcasting
  if ((u_int32_t) ih->daddr() != IP_BROADCAST)
    rt_resolve(p);
  else
    forward((proaodv_rt_entry*) 0, p, NO_DELAY);
}

void
PROAODV::recvPROAODV(Packet *p) {
  struct hdr_proaodv *ah = HDR_PROAODV(p);

  assert(HDR_IP(p)->sport() == RT_PORT);
  assert(HDR_IP(p)->dport() == RT_PORT);

  /*
   * Incoming Packets.
   */
  switch (ah->ah_type) {

    case PROAODVTYPE_RREQ:
      recvRequest(p);
      break;

    case PROAODVTYPE_RREP:
      recvReply(p);
      break;

    case PROAODVTYPE_RERR:
      recvError(p);
      break;

    case PROAODVTYPE_HELLO:
      recvHello(p);
      break;

    case PROAODVTYPE_SP_MSG:
      recvSpecialMsg(p);
      break;
      
    case PROAODVTYPE_SP_VREQ:
      recvVoteRequest(p);
      break;
      
    case PROAODVTYPE_SP_VREP:
      recvVoteReply(p);
      break;
      
    case PROAODVTYPE_SP_ALERT:
      recvAlert(p);
      break;

    default:
      fprintf(stderr, "Invalid AODV type (%x)\n", ah->ah_type);
      exit(1);
  }

}

void
PROAODV::recvRequest(Packet *p) {
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_request *rq = HDR_PROAODV_REQUEST(p);
  proaodv_rt_entry *rt;

  /*
   * Drop if:
   *      - I'm the source
   *      - I recently heard this request.
   */

  if (rq->rq_src == index) {
#ifdef DEBUG
    fprintf(stderr, "%s: got my own REQUEST\n", __FUNCTION__);
#endif // DEBUG
    Packet::free(p);
    return;
  }

  if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
    fprintf(stderr, "%s: discarding request\n", __FUNCTION__);
#endif // DEBUG

    Packet::free(p);
    return;
  }

  /*
   * Cache the broadcast ID
   */
  id_insert(rq->rq_src, rq->rq_bcast_id);



  /* 
   * We are either going to forward the REQUEST or generate a
   * REPLY. Before we do anything, we make sure that the REVERSE
   * route is in the route table.
   */
  proaodv_rt_entry *rt0; // rt0 is the reverse route 

  rt0 = rtable.rt_lookup(rq->rq_src);
  if (rt0 == 0) { /* if not in the route table */
    // create an entry for the reverse route.
    rt0 = rtable.rt_add(rq->rq_src);
  }

  rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));

  if ((rq->rq_src_seqno > rt0->rt_seqno) ||
          ((rq->rq_src_seqno == rt0->rt_seqno) &&
          (rq->rq_hop_count < rt0->rt_hops))) {
    // If we have a fresher seq no. or lesser #hops for the 
    // same seq no., update the rt entry. Else don't bother.
    rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
            max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)));
    if (rt0->rt_req_timeout > 0.0) {
      // Reset the soft state and 
      // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
      // This is because route is used in the forward direction,
      // but only sources get benefited by this change
      rt0->rt_req_cnt = 0;
      rt0->rt_req_timeout = 0.0;
      rt0->rt_req_last_ttl = rq->rq_hop_count;
      rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
    }

    /* Find out whether any buffered packet can benefit from the 
     * reverse route.
     * May need some change in the following code - Mahesh 09/11/99
     */
    assert(rt0->rt_flags == RTF_UP);
    Packet *buffered_pkt;
    while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
      if (rt0 && (rt0->rt_flags == RTF_UP)) {
        assert(rt0->rt_hops != INFINITY2);
        forward(rt0, buffered_pkt, NO_DELAY);
      }
    }
  }
  // End for putting reverse route in rt table


  /*
   * We have taken care of the reverse route stuff.
   * Now see whether we can send a route reply. 
   */

  rt = rtable.rt_lookup(rq->rq_dst);

  // First check if I am the destination ..

  if (rq->rq_dst == index) {

#ifdef DEBUG
    fprintf(stderr, "%d - %s: destination sending reply\n",
            index, __FUNCTION__);
#endif // DEBUG


    // Just to be safe, I use the max. Somebody may have
    // incremented the dst seqno.
    seqno = max(seqno, rq->rq_dst_seqno) + 1;
    if (seqno % 2) seqno++;

    sendReply(rq->rq_src, // IP Destination
            1, // Hop Count
            index, // Dest IP Address
            seqno, // Dest Sequence Num
            MY_ROUTE_TIMEOUT, // Lifetime
            rq->rq_timestamp); // timestamp

    Packet::free(p);
  }
    // I am not the destination, but I may have a fresh enough route.

  else if (rt && (rt->rt_hops != INFINITY2) &&
          (rt->rt_seqno >= rq->rq_dst_seqno)) {

    //assert (rt->rt_flags == RTF_UP);
    assert(rq->rq_dst == rt->rt_dst);
    //assert ((rt->rt_seqno%2) == 0);	// is the seqno even?
    sendReply(rq->rq_src,
            rt->rt_hops + 1,
            rq->rq_dst,
            rt->rt_seqno,
            (u_int32_t) (rt->rt_expire - CURRENT_TIME),
            //             rt->rt_expire - CURRENT_TIME,
            rq->rq_timestamp);
    // Insert nexthops to RREQ source and RREQ destination in the
    // precursor lists of destination and source respectively
    rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source
    rt0->pc_insert(rt->rt_nexthop); // nexthop to RREQ destination

#ifdef RREQ_GRAT_RREP  

    // WASTODO: send grat RREP to dst if G flag set in RREQ using rq->rq_src_seqno, rq->rq_hop_counT
    // DONE: Included gratuitous replies to be sent as per IETF aodv draft specification. As of now, G flag has not been dynamically used and is always set or reset in aodv-packet.h --- Anant Utgikar, 09/16/02.
    sendReply(rq->rq_dst,
            rq->rq_hop_count,
            rq->rq_src,
            rq->rq_src_seqno,
            (u_int32_t) (rt->rt_expire - CURRENT_TIME),
            //             rt->rt_expire - CURRENT_TIME,
            rq->rq_timestamp);
#endif


    Packet::free(p);
  }    /*
  * Can't reply. So forward the  Route Request
  */
  else {
    ih->saddr() = index;
    ih->daddr() = IP_BROADCAST;
    rq->rq_hop_count += 1;
    // Maximum sequence number seen en route
    if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
    forward((proaodv_rt_entry*) 0, p, DELAY);
  }

}

void
PROAODV::recvReply(Packet *p) {
  //struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_reply *rp = HDR_PROAODV_REPLY(p);
  proaodv_rt_entry *rt;
  char suppress_reply = 0;
  double delay = 0.0;

#ifdef DEBUG
  fprintf(stderr, "%d - %s: received a REPLY\n", index, __FUNCTION__);
  fprintf(stderr, "REPLY has dst %d, src %d, hopcount %d \n", rp->rp_dst, rp->rp_src, rp->rp_hop_count);
  fprintf(stderr, "HDR_IP has dst %d, src %d, hopcount %d \n", ih->dst_, ih->src_, ih->daddr());
#endif // DEBUG


  /*
   *  Got a reply. So reset the "soft state" maintained for 
   *  route requests in the request table. We don't really have
   *  have a separate request table. It is just a part of the
   *  routing table itself. 
   */
  // Note that rp_dst is the dest of the data packets, not the
  // the dest of the reply, which is the src of the data packets.

  rt = rtable.rt_lookup(rp->rp_dst);

  /*
   *  If I don't have a rt entry to this host... adding
   */
  if (rt == 0) {
    rt = rtable.rt_add(rp->rp_dst);
  }

  /*
   * Add a forward route table entry... here I am following 
   * Perkins-Royer AODV paper almost literally - SRD 5/99
   */

  if ((rt->rt_seqno < rp->rp_dst_seqno) || // newer route 
          ((rt->rt_seqno == rp->rp_dst_seqno) &&
          (rt->rt_hops > rp->rp_hop_count))) { // shorter or better route

    // Update the rt entry 
    rt_update(rt, rp->rp_dst_seqno, rp->rp_hop_count,
            rp->rp_src, CURRENT_TIME + rp->rp_lifetime);

    // reset the soft state
    rt->rt_req_cnt = 0;
    rt->rt_req_timeout = 0.0;
    rt->rt_req_last_ttl = rp->rp_hop_count;

    if (ih->daddr() == index) { // If I am the original source
      // Update the route discovery latency statistics
      // rp->rp_timestamp is the time of request origination

      rt->rt_disc_latency[(unsigned char) rt->hist_indx] = (CURRENT_TIME - rp->rp_timestamp)
              / (double) rp->rp_hop_count;
      // increment indx for next time
      rt->hist_indx = (rt->hist_indx + 1) % MAX_HISTORY;
    }

    // rp->rp_dst is the destination for the data packets
    // rp->rp_src is the source of the data packets

    /*
     * Send all packets queued in the sendbuffer destined for
     * this destination. 
     * XXX - observe the "second" use of p.
     */
    Packet *buf_pkt;
    bool smSent = false;
    PROAODV_Neighbor *nb = nb_lookup(rt->rt_nexthop);
    if(rt->rt_nexthop == rt->rt_dst || nb->nb_clusterhead == true) {
      smSent = true;
    }
    while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
      if (rt->rt_hops != INFINITY2) {
        assert(rt->rt_flags == RTF_UP);
        // Delay them a little to help ARP. Otherwise ARP 
        // may drop packets. -SRD 5/23/99
        if (!smSent) {
          smSent = sendSpecialMsg(rt, buf_pkt);
        }
        forward(rt, buf_pkt, delay);
        delay += ARP_DELAY;
      }
    }
  } else {
    suppress_reply = 1;
  }

  /*
   * If reply is for me, discard it.
   */

  if (ih->daddr() == index || suppress_reply) {
    Packet::free(p);
  }    /*
  * Otherwise, forward the Route Reply.
  */
  else {
    // Find the rt entry
    proaodv_rt_entry *rt0 = rtable.rt_lookup(ih->daddr());
    // If the rt is up, forward
    if (rt0 && (rt0->rt_hops != INFINITY2)) {
      assert(rt0->rt_flags == RTF_UP);
      rp->rp_hop_count += 1;
      rp->rp_src = index;
      forward(rt0, p, NO_DELAY);
      // Insert the nexthop towards the RREQ source to 
      // the precursor list of the RREQ destination
      rt->pc_insert(rt0->rt_nexthop); // nexthop to RREQ source

    } else {
      // I don't know how to forward .. drop the reply. 
#ifdef DEBUG
      fprintf(stderr, "%s: dropping Route Reply\n", __FUNCTION__);
#endif // DEBUG
      drop(p, DROP_RTR_NO_ROUTE);
    }
  }
}

void PROAODV::recvVoteRequest(Packet* p) {
struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_request *rq = HDR_PROAODV_REQUEST(p);
  proaodv_rt_entry *rt;

  /*
   * Drop if:
   *      - I'm the source
   *      - I recently heard this vote request.
   */

  if (rq->rq_src == index) {
#ifdef DEBUG
    fprintf(stderr, "%s: got my own vote request\n", __FUNCTION__);
#endif // DEBUG
    Packet::free(p);
    return;
  }

  if (id_lookup(rq->rq_src, rq->rq_bcast_id)) {

#ifdef DEBUG
    fprintf(stderr, "%s: discarding vote request (seen)\n", __FUNCTION__);
#endif // DEBUG

    Packet::free(p);
    return;
  }

  /*
   * Cache the broadcast ID
   */
  id_insert(rq->rq_src, rq->rq_bcast_id);
  PROAODV_Neighbor *thenode;
//  rq_dst is the neighbor we are interested in
  thenode = nb_lookup(rq->rq_dst);
  if(thenode != 0)  {
    if(thenode->nb_received < CURRENT_TIME - SM_DATA_TIMEOUT) {
      // wait for the data packet
      // Then send vote Reply
      //maybe stick this in a timer??
      sendVoteReply(ih->saddr(), 1);
    }
    else {
      sendVoteReply(ih->saddr(), 1);
    }
  }

  if(rq->rq_hop_count > MAX_VOTE_HOPS)  {
#ifdef DEBUG
        fprintf(stderr, "%s: not forwarding vote request\n", __FUNCTION__);
#endif // DEBUG
        Packet::free(p);
        return;
  }
  else {
#ifdef DEBUG
        fprintf(stderr, "%s: forwarding vote request\n", __FUNCTION__);
#endif // DEBUG
    ih->saddr() = index;
    ih->daddr() = IP_BROADCAST;
    rq->rq_hop_count += 1;
    // Maximum sequence number seen en route
    if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
    forward((proaodv_rt_entry*) 0, p, DELAY);
  }

}

void PROAODV::recvVoteReply(Packet* p) {
  //struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_reply *rp = HDR_PROAODV_REPLY(p);
  struct hdr_proaodv_sp_vote *vp = HDR_PROAODV_SP_VOTE(p);
  double delay = 0.0;

#ifdef DEBUG
  fprintf(stderr, "%d - %s: received a VOTE REPLY from\n", index, __FUNCTION__);
  fprintf(stderr, "REPLY has dst %d, src %d, hopcount %d \n", rp->rp_dst, rp->rp_src, rp->rp_hop_count);
  fprintf(stderr, "HDR_IP has dst %d, src %d, hopcount %d \n", ih->dst_, ih->src_, ih->daddr());
#endif // DEBUG
  if(isClusterhead() && rp->rp_dst == index && mi_nexthop != 0) {
    if(vp->vote == true) {
      mi_nexthop = 0;
      mi_dst = 0;
      mi_src = 0;
      mi_timeout = 0;
      promiscuous_mode = false;
    }
  }
}

void PROAODV::recvAlert(Packet* p) {

}


void
PROAODV::recvError(Packet *p) {
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_error *re = HDR_PROAODV_ERROR(p);
  proaodv_rt_entry *rt;
  u_int8_t i;
  Packet *rerr = Packet::alloc();
  struct hdr_proaodv_error *nre = HDR_PROAODV_ERROR(rerr);

  nre->DestCount = 0;

  for (i = 0; i < re->DestCount; i++) {
    // For each unreachable destination
    rt = rtable.rt_lookup(re->unreachable_dst[i]);
    if (rt && (rt->rt_hops != INFINITY2) &&
            (rt->rt_nexthop == ih->saddr()) &&
            (rt->rt_seqno <= re->unreachable_dst_seqno[i])) {
      assert(rt->rt_flags == RTF_UP);
      assert((rt->rt_seqno % 2) == 0); // is the seqno even?
#ifdef DEBUG
      fprintf(stderr, "%s(%f): %d\t(%d\t%u\t%d)\t(%d\t%u\t%d)\n", __FUNCTION__, CURRENT_TIME,
              index, rt->rt_dst, rt->rt_seqno, rt->rt_nexthop,
              re->unreachable_dst[i], re->unreachable_dst_seqno[i],
              ih->saddr());
#endif // DEBUG
      rt->rt_seqno = re->unreachable_dst_seqno[i];
      rt_down(rt);

      // Not sure whether this is the right thing to do
      Packet *pkt;
      while ((pkt = ifqueue->filter(ih->saddr()))) {
        drop(pkt, DROP_RTR_MAC_CALLBACK);
      }

      // if precursor list non-empty add to RERR and delete the precursor list
      if (!rt->pc_empty()) {
        nre->unreachable_dst[nre->DestCount] = rt->rt_dst;
        nre->unreachable_dst_seqno[nre->DestCount] = rt->rt_seqno;
        nre->DestCount += 1;
        rt->pc_delete();
      }
    }
  }

  if (nre->DestCount > 0) {
#ifdef DEBUG
    fprintf(stderr, "%s(%f): %d\t sending RERR...\n", __FUNCTION__, CURRENT_TIME, index);
#endif // DEBUG
    sendError(rerr);
  } else {
    Packet::free(rerr);
  }

  Packet::free(p);
}

//void
//PROAODV::testPacket(p) {};

/*
   Packet Transmission Routines
 */

void
PROAODV::forward(proaodv_rt_entry *rt, Packet *p, double delay) {
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  ch->last_hop_ = index;

  if (ih->ttl_ == 0) {

#ifdef DEBUG
    fprintf(stderr, "%s: calling drop()\n", __PRETTY_FUNCTION__);
#endif // DEBUG

    drop(p, DROP_RTR_TTL);
    return;
  }

  if (((ch->ptype() != PT_PROAODV && ch->direction() == hdr_cmn::UP) &&
          ((u_int32_t) ih->daddr() == IP_BROADCAST))
          || (ih->daddr() == here_.addr_)) {
    dmux_->recv(p, 0);
    return;
  }

  if (rt) {
    assert(rt->rt_flags == RTF_UP);
    rt->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
    ch->next_hop_ = rt->rt_nexthop;
    ch->addr_type() = NS_AF_INET;
    ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction
  } else { // if it is a broadcast packet
    // assert(ch->ptype() == PT_PROAODV); // maybe a diff pkt type like gaf
    assert(ih->daddr() == (nsaddr_t) IP_BROADCAST);
    ch->addr_type() = NS_AF_NONE;
    ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction
  }

  if (ih->daddr() == (nsaddr_t) IP_BROADCAST) {
    // If it is a broadcast packet
    assert(rt == 0);
    if (ch->ptype() == PT_PROAODV) {
      /*
       *  Jitter the sending of AODV broadcast packets by 10ms
       */
      Scheduler::instance().schedule(target_, p,
              0.01 * Random::uniform());
    } else {
      Scheduler::instance().schedule(target_, p, 0.); // No jitter
    }
  } else { // Not a broadcast packet 
    if (delay > 0.0) {
      Scheduler::instance().schedule(target_, p, delay);
    } else {
      // Not a broadcast packet, no delay, send immediately
      Scheduler::instance().schedule(target_, p, 0.);
    }
  }

}

void
PROAODV::sendRequest(nsaddr_t dst) {
  // Allocate a RREQ packet 
  Packet *p = Packet::alloc();
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_request *rq = HDR_PROAODV_REQUEST(p);
  proaodv_rt_entry *rt = rtable.rt_lookup(dst);

  assert(rt);

  /*
   *  Rate limit sending of Route Requests. We are very conservative
   *  about sending out route requests. 
   */

  if (rt->rt_flags == RTF_UP) {
    assert(rt->rt_hops != INFINITY2);
    Packet::free((Packet *) p);
    return;
  }

  if (rt->rt_req_timeout > CURRENT_TIME) {
    Packet::free((Packet *) p);
    return;
  }

  // rt_req_cnt is the no. of times we did network-wide broadcast
  // RREQ_RETRIES is the maximum number we will allow before 
  // going to a long timeout.

  if (rt->rt_req_cnt > RREQ_RETRIES) {
    rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
    rt->rt_req_cnt = 0;
    Packet *buf_pkt;
    while ((buf_pkt = rqueue.deque(rt->rt_dst))) {
      drop(buf_pkt, DROP_RTR_NO_ROUTE);
    }
    Packet::free((Packet *) p);
    return;
  }

#ifdef DEBUG
  fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d\n",
          ++route_request, index, rt->rt_dst);
#endif // DEBUG

  // Determine the TTL to be used this time. 
  // Dynamic TTL evaluation - SRD

  rt->rt_req_last_ttl = max(rt->rt_req_last_ttl, rt->rt_last_hop_count);

  if (0 == rt->rt_req_last_ttl) {
    // first time query broadcast
    ih->ttl_ = TTL_START;
  } else {
    // Expanding ring search.
    if (rt->rt_req_last_ttl < TTL_THRESHOLD)
      ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
    else {
      // network-wide broadcast
      ih->ttl_ = NETWORK_DIAMETER;
      rt->rt_req_cnt += 1;
    }
  }

  // remember the TTL used  for the next time
  rt->rt_req_last_ttl = ih->ttl_;

  // PerHopTime is the roundtrip time per hop for route requests.
  // The factor 2.0 is just to be safe .. SRD 5/22/99
  // Also note that we are making timeouts to be larger if we have 
  // done network wide broadcast before. 

  rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt);
  if (rt->rt_req_cnt > 0)
    rt->rt_req_timeout *= rt->rt_req_cnt;
  rt->rt_req_timeout += CURRENT_TIME;

  // Don't let the timeout to be too large, however .. SRD 6/8/99
  if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
    rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
  rt->rt_expire = 0;

#ifdef DEBUG
  fprintf(stderr, "(%2d) - %2d sending Route Request, dst: %d, tout %f ms\n",
          ++route_request,
          index, rt->rt_dst,
          rt->rt_req_timeout - CURRENT_TIME);
#endif // DEBUG


  // Fill out the RREQ packet 
  // ch->uid() = 0;
  ch->ptype() = PT_PROAODV;
  ch->size() = IP_HDR_LEN + rq->size();
  ch->iface() = -2;
  ch->error() = 0;
  ch->addr_type() = NS_AF_NONE;
  ch->prev_hop_ = index; // AODV hack

  ih->saddr() = index;
  ih->daddr() = IP_BROADCAST;
  ih->sport() = RT_PORT;
  ih->dport() = RT_PORT;

  // Fill up some more fields. 
  rq->rq_type = PROAODVTYPE_RREQ;
  rq->rq_hop_count = 1;
  rq->rq_bcast_id = bid++;
  rq->rq_dst = dst;
  rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
  rq->rq_src = index;
  seqno += 2;
  assert((seqno % 2) == 0);
  rq->rq_src_seqno = seqno;
  rq->rq_timestamp = CURRENT_TIME;

  Scheduler::instance().schedule(target_, p, 0.);

}

void
PROAODV::sendReply(nsaddr_t ipdst, u_int32_t hop_count, nsaddr_t rpdst,
        u_int32_t rpseq, u_int32_t lifetime, double timestamp) {
  Packet *p = Packet::alloc();
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_reply *rp = HDR_PROAODV_REPLY(p);
  proaodv_rt_entry *rt = rtable.rt_lookup(ipdst);

#ifdef DEBUG
  fprintf(stderr, "sending Reply from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG
  assert(rt);

  rp->rp_type = PROAODVTYPE_RREP;
  //rp->rp_flags = 0x00;
  rp->rp_hop_count = hop_count;
  rp->rp_dst = rpdst;
  rp->rp_dst_seqno = rpseq;
  rp->rp_src = index;
  rp->rp_lifetime = lifetime;
  rp->rp_timestamp = timestamp;

  // ch->uid() = 0;
  ch->ptype() = PT_PROAODV;
  ch->size() = IP_HDR_LEN + rp->size();
  ch->iface() = -2;
  ch->error() = 0;
  ch->addr_type() = NS_AF_INET;
  ch->next_hop_ = rt->rt_nexthop;
  ch->prev_hop_ = index; // AODV hack
  ch->direction() = hdr_cmn::DOWN;

  ih->saddr() = index;
  ih->daddr() = ipdst;
  ih->sport() = RT_PORT;
  ih->dport() = RT_PORT;
  ih->ttl_ = NETWORK_DIAMETER;

  Scheduler::instance().schedule(target_, p, 0.);

}

void
PROAODV::sendError(Packet *p, bool jitter) {
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_error *re = HDR_PROAODV_ERROR(p);

#ifdef ERROR
  fprintf(stderr, "sending Error from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

  re->re_type = PROAODVTYPE_RERR;
  //re->reserved[0] = 0x00; re->reserved[1] = 0x00;
  // DestCount and list of unreachable destinations are already filled

  // ch->uid() = 0;
  ch->ptype() = PT_PROAODV;
  ch->size() = IP_HDR_LEN + re->size();
  ch->iface() = -2;
  ch->error() = 0;
  ch->addr_type() = NS_AF_NONE;
  ch->next_hop_ = 0;
  ch->prev_hop_ = index; // AODV hack
  ch->direction() = hdr_cmn::DOWN; //important: change the packet's direction

  ih->saddr() = index;
  ih->daddr() = IP_BROADCAST;
  ih->sport() = RT_PORT;
  ih->dport() = RT_PORT;
  ih->ttl_ = 1;

  // Do we need any jitter? Yes
  if (jitter)
    Scheduler::instance().schedule(target_, p, 0.01 * Random::uniform());
  else
    Scheduler::instance().schedule(target_, p, 0.0);

}

/*
   Neighbor Management Functions
 */

void
PROAODV::sendHello() {
  Packet *p = Packet::alloc();
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_reply *rh = HDR_PROAODV_REPLY(p);
  struct hdr_proaodv_sp_msg *sh = HDR_PROAODV_SP_MSG(p);
#ifdef DEBUG
  fprintf(stderr, "sending Hello from %d at %.2f\n", index, Scheduler::instance().clock());
#endif // DEBUG

  rh->rp_type = PROAODVTYPE_HELLO;
  //rh->rp_flags = 0x00;
  rh->rp_hop_count = 1;
  rh->rp_dst = index;
  rh->rp_dst_seqno = seqno;
  rh->rp_lifetime = (1 + ALLOWED_HELLO_LOSS) * HELLO_INTERVAL;
  
  // ch->uid() = 0;
  ch->ptype() = PT_PROAODV;
  ch->size() = IP_HDR_LEN + rh->size() + sh->size();
  ch->iface() = -2;
  ch->error() = 0;
  ch->addr_type() = NS_AF_NONE;
  ch->prev_hop_ = index; // AODV hack

  ih->saddr() = index;
  ih->daddr() = IP_BROADCAST;
  ih->sport() = RT_PORT;
  ih->dport() = RT_PORT;
  ih->ttl_ = 1;
  if(isClusterhead()) {
    sh->sm_src = index;
  }
  
  Scheduler::instance().schedule(target_, p, 0.0);
}

void
PROAODV::recvHello(Packet *p) {
  //struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_reply *rp = HDR_PROAODV_REPLY(p);
  struct hdr_proaodv_sp_msg *sh = HDR_PROAODV_SP_MSG(p);
  PROAODV_Neighbor *nb;
  nb = nb_lookup(rp->rp_dst);
#ifdef DEBUG
  fprintf(stderr, "in function %s (sh->sm_src %d == rp->rp_dst %d) \n",__FUNCTION__, sh->sm_src, rp->rp_dst);
#endif
  bool isCH = (sh->sm_src == rp->rp_dst && sh->sm_src != 0);
  if (nb == 0) {
    nb_insert(rp->rp_dst, isCH);
  } else {
    if(nb->nb_clusterhead != isCH)  {
      nb->nb_clusterhead = isCH;
    }
    nb->nb_expire = CURRENT_TIME +
            (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
  }

  Packet::free(p);
}

/**
 * Receive Special Message Packet
 * @param p
 * @return 
 * 
 * TODO Recheck this method. It should only initiate a CHECK/VOTE when the route generator is not the destination node
 * TODO RECHECK THE DOCUMENTATION/PAPER
 */
void
PROAODV::recvSpecialMsg(Packet *p) {
#ifdef DEBUG
  fprintf(stdout, "Node %d Received a Cluster Head Special Message at %.2f\n", index, Scheduler::instance().clock());
#endif
  if (!isClusterhead()) {
#ifdef DEBUG
    fprintf(stdout, "I (%d) am not a Cluster Head Discarding at %.2f\n", index, Scheduler::instance().clock());
#endif
    Packet::free(p);
  } else {
#ifdef DEBUG
    fprintf(stdout, "I am a Cluster Head: Processing at %.2f\n", Scheduler::instance().clock());
#endif
    struct hdr_ip *ih = HDR_IP(p);
    struct hdr_proaodv_request *rq = HDR_PROAODV_REQUEST(p);
    /*
     * Drop if:
     *      - I'm the source
     *      - I recently got this special Message .
     */
    if (rq->rq_src == index) {
  #ifdef DEBUG
      fprintf(stderr, "%s: got my own Special Message\n", __FUNCTION__);
  #endif // DEBUG
      Packet::free(p);
      return;
    }

    if (id_lookup(rq->rq_src, rq->rq_bcast_id)) { // reusing the id_lookup function as I am using a broadcast
  #ifdef DEBUG
      fprintf(stderr, "%s: Already Seen this special Message \n", __FUNCTION__);
  #endif // DEBUG
      Packet::free(p);
      return;
    }
    struct hdr_proaodv_sp_msg *sp = HDR_PROAODV_SP_MSG(p);
#ifdef DEBUG
    fprintf(stdout, "Special message has src %d and nexthop %d at %.2f\n", rq->rq_src, sp->rt_nexthop, Scheduler::instance().clock());
#endif
    // if the nexthop is me then it is chilled, just ignore processing
    if(sp->rt_nexthop == index) {
    #ifdef DEBUG
      fprintf(stdout, "Nexthop %d is me dropping special message packet at %.2f\n", sp->rt_nexthop, Scheduler::instance().clock());
    #endif
      Packet::free(p);
      return;
    }
    /* 
     * This is generic code from recvRequest function
     * Clusterheads are supposed to be in Broadcast Range of each other so this 
     * should not have to be here, but it is here just in case these 2 have never 
     * communicated before
     */
//    proaodv_rt_entry *rt;
    
    /*
     * Cache the broadcast ID
     * Using the Same Queue/List that is used RREQ Broadcasts
     * I have no idea if this will have a negative effect 
     */
    id_insert(rq->rq_src, rq->rq_bcast_id);

    /* 
     * We are either going to forward the Special Message or Begin Monitoring the network
     * Before we do anything, we make sure that the REVERSE
     * route is in the route table. the same as a normal route request
     */
    proaodv_rt_entry *rt0; // rt0 is the reverse route 

    rt0 = rtable.rt_lookup(rq->rq_src);
    if (rt0 == 0) { /* if not in the route table */
      // create an entry for the reverse route.
      rt0 = rtable.rt_add(rq->rq_src);
    }

    rt0->rt_expire = max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE));

    if ((rq->rq_src_seqno > rt0->rt_seqno) ||
            ((rq->rq_src_seqno == rt0->rt_seqno) &&
            (rq->rq_hop_count < rt0->rt_hops))) {
      // If we have a fresher seq no. or lesser #hops for the 
      // same seq no., update the rt entry. Else don't bother.
      rt_update(rt0, rq->rq_src_seqno, rq->rq_hop_count, ih->saddr(),
              max(rt0->rt_expire, (CURRENT_TIME + REV_ROUTE_LIFE)));
      if (rt0->rt_req_timeout > 0.0) {
        // Reset the soft state and 
        // Set expiry time to CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT
        // This is because route is used in the forward direction,
        // but only sources get benefited by this change
        rt0->rt_req_cnt = 0;
        rt0->rt_req_timeout = 0.0;
        rt0->rt_req_last_ttl = rq->rq_hop_count;
        rt0->rt_expire = CURRENT_TIME + ACTIVE_ROUTE_TIMEOUT;
      }

      /* Find out whether any buffered packet can benefit from the 
       * reverse route.
       * May need some change in the following code - Mahesh 09/11/99
       * Commenting out, but Keeping this here for now. may be of use Later
       */
      assert(rt0->rt_flags == RTF_UP);
      Packet *buffered_pkt;
      while ((buffered_pkt = rqueue.deque(rt0->rt_dst))) {
        if (rt0 && (rt0->rt_flags == RTF_UP)) {
          assert(rt0->rt_hops != INFINITY2);
          forward(rt0, buffered_pkt, NO_DELAY);
        }
      }
    }

    PROAODV_Neighbor *nb;
    nb = nb_lookup(sp->rt_nexthop);
    if (nb == 0) {
#ifdef DEBUG
        fprintf(stdout, "We Don't Have this Neighbor , SENDING OUR OWN SPECIAL MESSAGE packet at %.2f\n", Scheduler::instance().clock());
#endif
        proaodv_rt_entry *rt = rtable.rt_lookup(rq->rq_src);

        ih->saddr() = index;
        ih->daddr() = IP_BROADCAST;
        rq->rq_hop_count += 1;
        // Maximum sequence number seen en route
        if (rt) rq->rq_dst_seqno = max(rt->rt_seqno, rq->rq_dst_seqno);
        forward((proaodv_rt_entry*) 0, p, DELAY);

    } else {
#ifdef DEBUG
      fprintf(stdout, "We Have this Neighbor and it is not a clusterhead: Monitoring at %.2f\n", Scheduler::instance().clock());
      fprintf(stdout, "Saving Data: src: %d, dst %d, Nexthop %d \n", rq->rq_src, rq->rq_dst, sp->rt_nexthop);
#endif
      promiscuous_mode = true;
      // TODO Implement a queue/list to take care of multiple request that come through at the same time
      // Neighbor is on Local Table We will monitor
//      mi = new monitor_info;
      Scheduler::instance().schedule(&vrtimer,new Event(), SM_DATA_TIMEOUT);
      mi_dst = rq->rq_dst;
      mi_src = rq->rq_src;
      mi_nexthop = sp->rt_nexthop;
      mi_timeout = CURRENT_TIME + SM_DATA_TIMEOUT;
      
      Packet::free(p);
    }

  }
}

/**
 * Send the Special message to the cluster head
 * Check recvSpecialMsg as to how this is handled
 */
bool
PROAODV::sendSpecialMsg(proaodv_rt_entry *rt1, Packet *p1) {
  if (isClusterhead()) return true;
  if (rt1->rt_dst == rt1->rt_nexthop) return true;
  struct hdr_cmn *ch1 = HDR_CMN(p1);
  if (ch1->ptype_ == PT_PROAODV || ch1->ptype_ == PT_ARP || ch1->ptype_ == PT_MAC) {
    return true;
  }
  // Allocate a Special Message Packet
  Packet *p = Packet::alloc();
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_request *rq = HDR_PROAODV_REQUEST(p);
  struct hdr_proaodv_sp_msg *sm = HDR_PROAODV_SP_MSG(p);
  proaodv_rt_entry *rt = rtable.rt_lookup(rt1->rt_dst);

  assert(rt);

#ifdef DEBUG
  fprintf(stderr, "(%2d) - %2d sending Special Message Request, nexthop %d, dst: %d\n",
          ++special_message_request, index, rt->rt_nexthop, rt->rt_dst);
#endif // DEBUG

  // Determine the TTL to be used this time. 
  // Dynamic TTL evaluation - SRD

  rt->rt_req_last_ttl = max(rt->rt_req_last_ttl, rt->rt_last_hop_count);

  if (0 == rt->rt_req_last_ttl) {
    // first time query broadcast
    ih->ttl_ = TTL_START;
  } else {
    // Expanding ring search.
    if (rt->rt_req_last_ttl < TTL_THRESHOLD)
      ih->ttl_ = rt->rt_req_last_ttl + TTL_INCREMENT;
    else {
      // network-wide broadcast
      ih->ttl_ = NETWORK_DIAMETER;
      rt->rt_req_cnt += 1;
    }
  }

  // remember the TTL used  for the next time
  rt->rt_req_last_ttl = ih->ttl_;

  // PerHopTime is the roundtrip time per hop for route requests.
  // The factor 2.0 is just to be safe .. SRD 5/22/99
  // Also note that we are making timeouts to be larger if we have 
  // done network wide broadcast before. 

  rt->rt_req_timeout = 2.0 * (double) ih->ttl_ * PerHopTime(rt);
  if (rt->rt_req_cnt > 0)
    rt->rt_req_timeout *= rt->rt_req_cnt;
  rt->rt_req_timeout += CURRENT_TIME;

  // Don't let the timeout to be too large, however .. SRD 6/8/99
  if (rt->rt_req_timeout > CURRENT_TIME + MAX_RREQ_TIMEOUT)
    rt->rt_req_timeout = CURRENT_TIME + MAX_RREQ_TIMEOUT;
  rt->rt_expire = 0;

#ifdef DEBUG
  fprintf(stderr, "(%2d) - %2d sending Special Message Request, nexthop %d , dst: %d, tout %f ms\n",
          ++special_message_request,
          index, rt->rt_nexthop, rt->rt_dst,
          rt->rt_req_timeout - CURRENT_TIME);
#endif // DEBUG


  // Fill out the RREQ packet 
  // ch->uid() = 0;
  ch->ptype() = PT_PROAODV;
  ch->size() = IP_HDR_LEN + rq->size() + sm->size();
  ch->iface() = -2;
  ch->error() = 0;
  ch->addr_type() = NS_AF_NONE;
  ch->prev_hop_ = index; // AODV hack

  ih->saddr() = index;
  ih->daddr() = IP_BROADCAST;
  ih->sport() = RT_PORT;
  ih->dport() = RT_PORT;

//  nsaddr_t theroutedest = rt1->rt_dst;
//  fprintf(stdout,"theroutedest = %d\n", theroutedest);
 
  // Fill up some more fields. 
  
  rq->rq_hop_count = 1;
  rq->rq_bcast_id = bid++;
  rq->rq_dst = rt1->rt_dst;
  rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
  rq->rq_src = index;
  seqno += 2;
  assert((seqno % 2) == 0);
  rq->rq_src_seqno = seqno;
  rq->rq_timestamp = CURRENT_TIME;
  sm->rt_dst = rt1->rt_dst;
  sm->sm_src = index;
  sm->rt_nexthop = rt1->rt_nexthop;
  rq->rq_type = PROAODVTYPE_SP_MSG;
#ifdef DEBUG
  fprintf(stdout, "sending special packet with sm->rt_dst = %d sm->sm_src %d, sm->rt_nexthop %d, rt1->rt_dst = %d \n", sm->rt_dst, sm->sm_src, sm->rt_nexthop, rt1->rt_dst );
#endif
  Scheduler::instance().schedule(target_, p, 0.);
  return true;
}

void PROAODV::sendVoteRequest(nsaddr_t addr)    {
  // Allocate a Packet
  Packet *p = Packet::alloc();
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_request *rq = HDR_PROAODV_REQUEST(p);
  struct hdr_proaodv_sp_msg *sm = HDR_PROAODV_SP_MSG(p);
  proaodv_rt_entry *rt = rtable.rt_lookup(addr);

  assert(rt);
  // Fill out the RREQ packet 
  // ch->uid() = 0;
  ch->ptype() = PT_PROAODV;
  ch->size() = IP_HDR_LEN + rq->size() + sm->size();
  ch->iface() = -2;
  ch->error() = 0;
  ch->addr_type() = NS_AF_NONE;
  ch->prev_hop_ = index; // AODV hack

  ih->saddr() = index;
  ih->daddr() = IP_BROADCAST;
  ih->sport() = RT_PORT;
  ih->dport() = RT_PORT;

  // Fill up some more fields. 
  rq->rq_type = PROAODVTYPE_SP_VREQ;
  rq->rq_hop_count = 1;
  rq->rq_bcast_id = bid++;
  rq->rq_dst = addr; // This is the route generator
  rq->rq_dst_seqno = (rt ? rt->rt_seqno : 0);
  rq->rq_src = index;
  seqno += 2;
  assert((seqno % 2) == 0);
  rq->rq_src_seqno = seqno;
  rq->rq_timestamp = CURRENT_TIME;
  sm->sm_src = index;

  Scheduler::instance().schedule(target_, p, 0.);
  
}

void PROAODV::sendVoteReply(nsaddr_t addr, bool vote)  {
  Packet *p = Packet::alloc();
  struct hdr_cmn *ch = HDR_CMN(p);
  struct hdr_ip *ih = HDR_IP(p);
  struct hdr_proaodv_reply *rp = HDR_PROAODV_REPLY(p);
  struct hdr_proaodv_sp_vote *vp = HDR_PROAODV_SP_VOTE(p);
  proaodv_rt_entry *rt = rtable.rt_lookup(addr);

  vp->vote = vote;
#ifdef DEBUG
  fprintf(stderr, "sending Reply from %d to %d at %.2f\n", index, addr, Scheduler::instance().clock());
#endif // DEBUG
  assert(rt);

  rp->rp_type = PROAODVTYPE_RREP;
  rp->rp_hop_count = 2;
  rp->rp_dst = addr;
  rp->rp_dst_seqno = 1;
  rp->rp_src = index;
  rp->rp_lifetime = CURRENT_TIME + SM_DATA_TIMEOUT;
  rp->rp_timestamp = CURRENT_TIME;

  ch->ptype() = PT_PROAODV;
  ch->size() = IP_HDR_LEN + rp->size() + vp->size();
  ch->iface() = -2;
  ch->error() = 0;
  ch->addr_type() = NS_AF_INET;
  ch->next_hop_ = rt->rt_nexthop;
  ch->prev_hop_ = index; // AODV hack
  ch->direction() = hdr_cmn::DOWN;

  ih->saddr() = index;
  ih->daddr() = addr;
  ih->sport() = RT_PORT;
  ih->dport() = RT_PORT;
  ih->ttl_ = MAX_VOTE_HOPS;

  Scheduler::instance().schedule(target_, p, 0.);
}

void PROAODV::sendAlarm(nsaddr_t addr)  {
    
}

void
PROAODV::nb_insert(nsaddr_t id) {
  PROAODV_Neighbor *nb = new PROAODV_Neighbor(id);

  assert(nb);
  nb->nb_clusterhead = false;
  nb->nb_expire = CURRENT_TIME +
          (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
  LIST_INSERT_HEAD(&nbhead, nb, nb_link);
  seqno += 2; // set of neighbors changed
  assert((seqno % 2) == 0);
}
void
PROAODV::nb_insert(nsaddr_t id, bool clusterhead) {
  PROAODV_Neighbor *nb = new PROAODV_Neighbor(id);

  assert(nb);
#ifdef DEBUG
  fprintf(stderr, "neighbor d% is clusterhead? %d\n", id, clusterhead);
#endif
  nb->nb_clusterhead = clusterhead;
  nb->nb_expire = CURRENT_TIME +
          (1.5 * ALLOWED_HELLO_LOSS * HELLO_INTERVAL);
  LIST_INSERT_HEAD(&nbhead, nb, nb_link);
  seqno += 2; // set of neighbors changed
  assert((seqno % 2) == 0);
}

PROAODV_Neighbor*
PROAODV::nb_lookup(nsaddr_t id) {
  PROAODV_Neighbor *nb = nbhead.lh_first;

  for (; nb; nb = nb->nb_link.le_next) {
    if (nb->nb_addr == id) break;
  }
  return nb;
}

/*
 * Called when we receive *explicit* notification that a Neighbor
 * is no longer reachable.
 */
void
PROAODV::nb_delete(nsaddr_t id) {
  PROAODV_Neighbor *nb = nbhead.lh_first;

  log_link_del(id);
  seqno += 2; // Set of neighbors changed
  assert((seqno % 2) == 0);

  for (; nb; nb = nb->nb_link.le_next) {
    if (nb->nb_addr == id) {
      LIST_REMOVE(nb, nb_link);
      delete nb;
      break;
    }
  }

  handle_link_failure(id);

}

/*
 * Used to update when we the last time was that we receive data from a Neighbor
 */
void
PROAODV::nb_update(nsaddr_t id, double receive_time) {
  PROAODV_Neighbor *nb = nbhead.lh_first;

  for (; nb; nb = nb->nb_link.le_next) {
    if (nb->nb_addr == id) {
      nb->nb_received = receive_time;
      break;
    }
  }
}

/*
 * Purges all timed-out Neighbor Entries - runs every
 * HELLO_INTERVAL * 1.5 seconds.
 */
void
PROAODV::nb_purge() {
  PROAODV_Neighbor *nb = nbhead.lh_first;
  PROAODV_Neighbor *nbn;
  double now = CURRENT_TIME;

  for (; nb; nb = nbn) {
    nbn = nb->nb_link.le_next;
    if (nb->nb_expire <= now) {
      nb_delete(nb->nb_addr);
    }
  }

}

/**
 * Returns true is the node is a cluster head
 * @return boolean
 */
bool
PROAODV::isClusterhead() {
    return clusterhead;
}