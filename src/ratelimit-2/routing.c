#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <assert.h>

#include "../ext/uthash.h"
#include "../ext/packet_cache.h"
#include "../ext/packet_trace.h"
#include "../log.h"
#include "../utils.h"
#include "../net.h"
#include "../tun.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

#include "routing.h"

enum {
    TYPE_DATA,
    TYPE_RREQ_FF, // full flood
    TYPE_RREQ_PF, // pruned flood
    TYPE_RREP,
    TYPE_RREP2
};

#define DISABLE_RATELIMIT 1
#define HOP_TIMEOUT_MIN_SECONDS 10
#define HOP_TIMEOUT_MAX_SECONDS (60 * 60 * 24)
#define TRAFFIC_DEGRADE_MAX_SECONDS (60 * 60 * 24)
#define TRAFFIC_DEGRADE_SECONDS 10
#define MIN_BROADCAST_PACKETS_PER_SECONDS 1000
#define MIN_BROADCAST_PACKETS_PERCENT 5

typedef struct {
    Address next_hop_addr; // use neighbor object with id and address?
    uint64_t time_updated;
    uint64_t time_created; // by default time_updated + MAX_TIMEOUT
    uint16_t hop_count;
    UT_hash_handle hh;
} Hop;

// per destination
typedef struct {
    uint32_t id;
    uint16_t seq_num; // sequence number
    Hop *hops;
    UT_hash_handle hh;
} Node;

// Per interface state. Removed/added only by interface_handler().
typedef struct {
    uint32_t ifindex;

    // We need to forward a broadcast (RREQ) if a neighbor uses us a source.
    uint64_t recv_own_broadcast_time;
    uint64_t recv_foreign_broadcast_time;
    uint64_t send_broadcast_time;
    uint64_t neighbor_change_time;

    uint16_t received_broadcast_packets;
    uint16_t received_unicast_packets;
    uint16_t send_broadcast_packets;
    uint16_t send_unicast_packets;
    uint64_t time_broadcast_send;
    UT_hash_handle hh;
} InterfaceState;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t sender;
    uint32_t prev_sender;
} RREQ;

// response to a RREQ
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
} RREP;

// response to a RREQ (but from a any node)
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t req_id; // dst_id from RREQ
    uint16_t req_seq_num;
    uint8_t req_hops;  // hop distance of req_id from src_id
    uint8_t req_age; // age of routing information in seconds
} RREP2;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t payload_length;
    uint8_t payload_data[];
} DATA;

static uint16_t g_sequence_number = 0;
static uint32_t g_broadcast_send_counter = 0; // for debugging only
static uint32_t g_broadcast_dropped_counter = 0; // for debugging only
static InterfaceState *g_ifstates = NULL;
static Node *g_nodes = NULL;

// called once per second
static void traffic_degrade()
{
    static uint64_t g_ifstate_last_degraded = 0;
    const uint64_t time_now = gstate.time_now;

    if ((time_now - g_ifstate_last_degraded) > (1000 * TRAFFIC_DEGRADE_SECONDS)) {
        InterfaceState *cur;
        InterfaceState *tmp;
        HASH_ITER(hh, g_ifstates, cur, tmp) {
            cur->received_broadcast_packets /= 2;
            cur->received_unicast_packets /= 2;
            cur->send_broadcast_packets /= 2;
            cur->send_unicast_packets /= 2;
        }

        g_ifstate_last_degraded = time_now;
    }
}

static InterfaceState *ifstate_find(const uint32_t ifindex)
{
    InterfaceState *ifstate = NULL;
    HASH_FIND(hh, g_ifstates, &ifindex, sizeof(uint32_t), ifstate);
    return ifstate;
}

static void ifstate_remove(const uint32_t ifindex)
{
    InterfaceState *ifstate = ifstate_find(ifindex);
    if (ifstate != NULL) {
        // remove entry
        HASH_DEL(g_ifstates, ifstate);
        free(ifstate);
    }
}

static InterfaceState *ifstate_create(const uint32_t ifindex)
{
    InterfaceState *ifstate = ifstate_find(ifindex);
    if (ifstate == NULL) {
        // add new entry
        ifstate = (InterfaceState*) calloc(1, sizeof(InterfaceState));
        ifstate->ifindex = ifindex;
        HASH_ADD(hh, g_ifstates, ifindex, sizeof(uint32_t), ifstate);
    } else {
        log_warning("ifstate_create() %s/%zu entry already exists", str_ifindex(ifindex), ifindex);
    }
    return ifstate;
}

// create non-existing entries
static InterfaceState *ifstate_get(const uint32_t ifindex)
{
    InterfaceState *ifstate = ifstate_find(ifindex);
    return ifstate ? ifstate : ifstate_create(ifindex);
}

static void count_broadcast_traffic(InterfaceState *ifstate, uint32_t send_bytes, uint32_t received_bytes)
{
    // send bytes
    if (send_bytes > 0) {
        const uint32_t n = 1 + send_bytes / 512;
        ifstate->send_broadcast_packets += n;
        ifstate->time_broadcast_send = gstate.time_now;
    }

    // received bytes
    if (received_bytes > 0) {
        const uint32_t n = 1 + received_bytes / 512;
        ifstate->received_broadcast_packets += n;
    }
}

static void count_unicast_traffic(InterfaceState *ifstate, uint32_t send_bytes, uint32_t received_bytes)
{
    // send bytes
    if (send_bytes > 0) {
        const uint32_t n = 1 + send_bytes / 512;
        ifstate->send_unicast_packets += n;
    }

    // received bytes
    if (received_bytes > 0) {
        const uint32_t n = 1 + received_bytes / 512;
        ifstate->received_unicast_packets += n;
    }
}

static bool get_is_needed(const InterfaceState *ifstate)
{
    uint64_t now = gstate.time_now;
    uint64_t t1 = ifstate->send_broadcast_time;
    uint64_t t2 = ifstate->recv_own_broadcast_time; // must have been 
    uint64_t t3 = ifstate->recv_foreign_broadcast_time;

    bool ret = true;
    int d = 0;

    if (t2) {
        //if (t3) {
            if ((now - t2) < 8) {
                // we got our own echo recently => broadcast
                d = 1;
                ret = true;
            } else {
                //d = 2;
                //ret = false;
                /*
                ret = false;
                if ((now - t3) < 8) {
                    d = 2;
                    ret = true;
                } else {
                    d = 3;
                    ret = false;
                }*/
            }
        //} else {

        //}
    } else {
        if (t3) {
            if ((now - t3) < 8) {
                // we got an old packet
                d = 4;
                ret = false;
            }
        } else {

        }
    }

    log_debug("get_is_needed() %s (d: %d, t1: %s, t2: %s)", str_bool(ret), d, str_duration(t1, now), str_duration(t1, now));

    return ret;
}

// send a RREQ as broadcast
static void send_RREQ(RREQ* rreq, bool from_tun)
{
    //bool from_tun = (rreq->src_id == gstate.own_id);
    InterfaceState *ifstate;
    InterfaceState *tmp;
    HASH_ITER(hh, g_ifstates, ifstate, tmp) {
        bool is_needed = get_is_needed(ifstate);
        if (is_needed || from_tun) {
            uint32_t bpackets = ifstate->received_broadcast_packets;
            uint32_t upackets = ifstate->received_unicast_packets;

            //TODO: better calculation!
            size_t pc = (100 * (1 + bpackets)) / (1 + bpackets + upackets);
            uint64_t last_broadcast = (gstate.time_now - ifstate->time_broadcast_send);

            log_debug("RREQ[%s]: bpackets: %zu (%zu%%), upackets: %zu, last_broadcast: %s ago, is_needed: %s",
                        str_ifindex(ifstate->ifindex), (size_t) bpackets,
                        pc, (size_t) upackets, str_since(ifstate->time_broadcast_send), str_bool(is_needed));

            if (DISABLE_RATELIMIT || pc <= MIN_BROADCAST_PACKETS_PERCENT
                    || last_broadcast == 0
                    || last_broadcast >= (1000 * MIN_BROADCAST_PACKETS_PER_SECONDS)) {

                ifstate->send_broadcast_time = gstate.time_now;

                log_debug("RREQ[%s]: => send", str_ifindex(ifstate->ifindex));

                send_bcast_l2(ifstate->ifindex, rreq, sizeof(RREQ));
                count_broadcast_traffic(ifstate, sizeof(RREQ), 0);

                // for statistics only
                g_broadcast_send_counter += 1;
            } else {
                log_debug("RREQ[%s]: above rate limit => drop", str_ifindex(ifstate->ifindex));

                // for statistics only
                g_broadcast_dropped_counter += 1;
            }
        } else {
            log_debug("RREQ[%s]: is not needed => drop", str_ifindex(ifstate->ifindex));
        }
    }
}

// send and count outgoing unicast traffic
static void send_ucast_l2_wrapper(const Address *next_hop_addr, const void* data, size_t data_len)
{
    send_ucast_l2(next_hop_addr, data, data_len);

    uint32_t ifindex = address_ifindex(next_hop_addr);
    InterfaceState *ifstate = ifstate_get(ifindex);
    count_unicast_traffic(ifstate, data_len, 0);
}

static Node *next_node_by_id(uint32_t id)
{
    Node *node;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    return node;
}

static bool is_new_neighbor(uint32_t id, uint16_t hop_count)
{
    if (id == gstate.own_id || hop_count != 0) {
        return false;
    }

    return (NULL == next_node_by_id(id));
}

static bool packet_is_duplicate(uint32_t id, uint16_t seq_num)
{
    if (id == gstate.own_id) {
        return true;
    }

    Node *node = next_node_by_id(id);
    if (node) {
        if (is_newer_seqnum(node->seq_num, seq_num)) {
            node->seq_num = seq_num;
            return false; // new sequence number
        } else {
            return true; // old sequence number, packet is a duplicate
        }
    } else {
        return false;
    }
}

// add uint16_t age bias
static void nodes_update(uint32_t id, const Address *addr, uint16_t hop_count, uint16_t seq_num, uint16_t req_age)
{
    if (id == gstate.own_id) {
        //log_error("nodes_update() got own id => ignore");
        return;
    } else {
        //log_debug("nodes_update() id: 0x%08x, addr: %s, hop_count: %zu, seq_num: %zu, req_age: %zu",
        //    id, str_addr(addr), (size_t) hop_count, (size_t) seq_num, (size_t) req_age);
    }

    Node *node;
    Hop *hop;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);
    if (node == NULL) {
        // add new entry
        node = (Node*) malloc(sizeof(Node));
        node->id = id;
        node->seq_num = seq_num;
        node->hops = NULL;
        HASH_ADD(hh, g_nodes, id, sizeof(uint32_t), node);
    }

    HASH_FIND(hh, node->hops, addr, sizeof(Address), hop);
    if (hop == NULL) {
        // add new entry
        hop = (Hop*) malloc(sizeof(Hop));
        hop->time_created = gstate.time_now - req_age;
        hop->next_hop_addr = *addr;
        HASH_ADD(hh, node->hops, next_hop_addr, sizeof(Address), hop);
    }

    hop->hop_count = hop_count;
    hop->time_updated = gstate.time_now;
}

static void nodes_timeout()
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;
    const uint64_t time_now = gstate.time_now;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        //bool is_neighbor = false;

        // timeout next hops
        HASH_ITER(hh, node->hops, hop, htmp) {
            /*
             * Dynamic Timeout - The longer a hop is used, the longer the timeout.
            */
            const uint32_t age1 = hop->time_updated - hop->time_created;
            const uint32_t age2 = time_now - hop->time_updated;
            if (age2 > (1000 * HOP_TIMEOUT_MIN_SECONDS)
                && ((age2 > (1000 * HOP_TIMEOUT_MAX_SECONDS)) || (age1 < age2))) {
                log_debug("timeout node 0x%08x, hop %s (age1: %s, age2: %s)",
                    node->id, str_addr(&hop->next_hop_addr), str_time(age1), str_time(age2));
                HASH_DEL(node->hops, hop);

                if (hop->hop_count == 1) {
                    //is_neighbor = true;
                    uint32_t ifindex = address_ifindex(&hop->next_hop_addr);
                    InterfaceState *ifstate = ifstate_find(ifindex);
                    if (ifstate) {
                        ifstate->neighbor_change_time = gstate.time_now;
                    }
                }

                free(hop);
            }
        }

        // no hops left => remove node
        if (node->hops == NULL) {
            log_debug("remove node 0x%08x", node->id);
/*
            if (is_neighbor) {
                // Full Flood: Network change detected.
                // A neighbor vanished.
                uint32_t ifindex = address_ifindex(&hop->next_hop_addr); // TODO: hop is NULL
                InterfaceState *ifstate = ifstate_find(ifindex);
                if (ifstate) {
                    ifstate->flood_needed = true;
                } else {
                    log_error("nodes_timeout() failed to find ifindex %zu", ifindex);
                }
            }
*/
            HASH_DEL(g_nodes, node);
            free(node);
        }
    }
}

static bool is_better_hop(const Hop *cur, const Hop *new)
{
    if (cur == NULL) {
        // prefer new one
        return true;
    }

    // choose
    if (new->time_updated > (cur->time_updated + 4)) {
        return true;
    }

    // prefer everything over MAC addresses (that is IPv4/IPv6)
    // despite the hops
    if (cur->next_hop_addr.family == AF_MAC
            && new->next_hop_addr.family != AF_MAC) {
        return ((new->hop_count / 2) < cur->hop_count);
    }

    return (new->hop_count < cur->hop_count);
}

static Hop *next_hop_by_node(Node *node)
{
    if (node == NULL) {
        return NULL;
    }

    Hop *hop;
    Hop *tmp;
    Hop *best = NULL;
    HASH_ITER(hh, node->hops, hop, tmp) {
        if (is_better_hop(best, hop)) {
            best = hop;
        }
    }

    return best;
}

static size_t get_data_size(DATA *p)
{
    return (sizeof(DATA) + p->payload_length);
}

static uint8_t* get_data_payload(DATA *p)
{
    return ((uint8_t*) p) + offsetof(DATA, payload_data);
}

// return node behind an address (only possible if neighbor)
// beware: slow - only for debugging
static Node *find_neighbor_by_address(const Address *addr)
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            if (hop->hop_count == 1 && 0 == memcmp(&hop->next_hop_addr, addr, sizeof(Address))) {
                return node;
            }
        }
    }

    return NULL;
}

static void periodic_handler()
{
    nodes_timeout();
    traffic_degrade();
}

static void send_cached_packet(uint32_t dst_id)
{
    uint8_t buffer[ETH_FRAME_LEN - sizeof(DATA)];

    Node *node = next_node_by_id(dst_id);
    Hop *hop = next_hop_by_node(node);
    if (node && hop) {
        DATA *data = (DATA*) &buffer[0];
        uint8_t* data_payload = get_data_payload(data);
        size_t data_payload_length = 0;
        packet_cache_get_and_remove(data_payload, &data_payload_length, dst_id);

        if (data_payload_length > 0) {
            data->type = TYPE_DATA;
            data->hop_count = 0,
            data->seq_num = g_sequence_number++;
            data->src_id = gstate.own_id;
            data->dst_id = dst_id;
            data->payload_length = data_payload_length;

            log_debug("send_cached_packet() send DATA (0x%08x => 0x%08x) via next hop %s, hop_count: %zu",
                data->src_id, data->dst_id, str_addr(&hop->next_hop_addr), (size_t) hop->hop_count);

            send_ucast_l2_wrapper(&hop->next_hop_addr, data, get_data_size(data));
        } else {
            // no cached packet found
            log_debug("send_cached_packet() no cached packet found for destiantion 0x%08x => ignore", dst_id);
        }
    } else {
        log_warning("send_cached_packet() no next hop found for destination 0x%08x => ignore", dst_id);
    }
}

// Common behavior for Full and Pruned Flood RREQ. May is_old RREP and RREP2.
static bool try_reply_RREQ(const char* context, const Address *src, RREQ *p)
{
    // we are the destination
    if (p->dst_id == gstate.own_id) {
        log_debug("%s: destination reached => send RREP", context);
        RREP rrep = {
            .type = TYPE_RREP,
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
        };

        // send back unicast
        send_ucast_l2_wrapper(src, &rrep, sizeof(rrep));
        return true;
    } else {
        // we know a node
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop && (1UL + p->hop_count + hop->hop_count) <= UINT16_MAX) {
            log_debug("%s: destination known => send RREP2", context);
            uint8_t age = MIN(gstate.time_now - hop->time_updated, UINT8_MAX);
            RREP2 rrep2 = {
                .type = TYPE_RREP2,
                .hop_count = 0,
                .seq_num = g_sequence_number++,
                .src_id = gstate.own_id,
                .dst_id = p->src_id,
                .req_id = p->dst_id,
                .req_seq_num = node->seq_num,
                .req_hops = hop->hop_count + 1, // or use hop_count from RREQ?
                .req_age = age,
            };

            send_ucast_l2_wrapper(src, &rrep2, sizeof(RREP2));
            return true;
        } else {
            /*
                p->hop_count += 1;
                p->prev_sender = p->sender;
                p->sender = gstate.own_id;
                send_RREQ(p, false);
            */

            return false;
        }
    }
}

static void handle_RREQ(InterfaceState *ifstate, const Address *rcv, const Address *src, const Address *dst, RREQ *p, size_t length)
{
    // we expect broadcasts or packets for us
    if (!(address_is_broadcast(dst) || address_equal(rcv, dst))) {
        log_trace("RREQ[%s]: unexpected destination (%s) => drop", str_ifindex(ifstate->ifindex), str_addr(dst));
        return;
    }

    if (length != sizeof(RREQ)) {
        log_debug("RREQ[%s]: invalid packet size => drop", str_ifindex(ifstate->ifindex));
        return;
    }

    // Full Flood: Network change detected.
    // neighbor is new
    bool new_neighbor = is_new_neighbor(p->src_id, p->hop_count);
    if (new_neighbor) {
        ifstate->neighbor_change_time = gstate.time_now;
    }

    // packet is new
    bool is_duplicate = packet_is_duplicate(p->src_id, p->seq_num);

    log_debug("RREQ[%s]: got packet 0x%08x => 0x%08x / sender: 0x%08x, prev_sender: 0x%08x, hop_count: %u, seq_num: %u, is_duplicate: %s",
           str_ifindex(ifstate->ifindex), p->src_id, p->dst_id, p->sender, p->prev_sender, p->hop_count, p->seq_num, str_yesno(is_duplicate));

    if (is_duplicate) {
        // call nodes_update()?
        // got echo
        if (p->prev_sender == gstate.own_id) {
            ifstate->recv_own_broadcast_time = gstate.time_now;
            //ifstate->flood_needed = true;
            //ifstate->flood_needed_time = gstate.time_now;
            log_debug("RREQ[%s]: own echo => drop", str_ifindex(ifstate->ifindex));
        } else {
            ifstate->recv_foreign_broadcast_time = gstate.time_now;
            // hm - this would mean that the sender does not need us?
            // not our echo
            log_debug("RREQ[%s]: foreign echo => drop", str_ifindex(ifstate->ifindex));
        }

    } else {
        nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num, 0);
        //nodes_update(p->prev_sender, src, 1, p->seq_num, 0); // prev_sender and seq_num does not match

        // packet is new
        if (!try_reply_RREQ("RREQ", src, p)) {
            p->hop_count += 1;
            p->prev_sender = p->sender;
            p->sender = gstate.own_id;
            send_RREQ(p, false);
        }
    }
}

static void handle_RREP(const Address *rcv, const Address *src, const Address *dst, RREP *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("RREP: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(RREP)) {
        log_debug("RREP: invalid packet size => drop");
        return;
    }

    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("RREP: packet is old => drop");
        return;
    }

    log_debug("RREP: got packet 0x%08x => 0x%08x / hop_count: %zu, seq_num: %zu",
        p->src_id, p->dst_id, (size_t) p->hop_count, (size_t) p->seq_num);

    nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num, 0);

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->src_id);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RREP: send to %s => forward", str_addr(&hop->next_hop_addr));
            p->hop_count += 1;
            send_ucast_l2_wrapper(&hop->next_hop_addr, p, sizeof(RREP));
        } else {
            log_debug("RREP: no next hop found => drop");
        }
    }
}

static void handle_RREP2(const Address *rcv, const Address *src, const Address *dst, RREP2 *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("RREP2: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(RREP2)) {
        log_debug("RREP2: invalid packet size => drop");
        return;
    }

    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("RREP2: packet already is old => drop (0x%08x, seq_num: %zu)", p->src_id, (size_t) p->seq_num);
        return;
    }

    log_debug("RREP2: got packet 0x%08x => 0x%08x / hop_count: %zu, seq_num: %zu,"
              " req_id: 0x%08x, req_seq_num: %zu, req_hops: %zu, req_age: %zu)",
        p->src_id, p->dst_id, (size_t) p->hop_count, (size_t) p->seq_num,
        p->req_id, (size_t) p->req_seq_num, (size_t) p->req_hops, (size_t) p->req_age);

    // add information about originator node
    nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num, 0);
    // add information from originator node about requested node
    nodes_update(p->req_id, src, p->hop_count + p->req_hops + 1, p->req_seq_num, p->req_age);

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->req_id);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RREP2: send to %s => forward", str_addr(&hop->next_hop_addr));
            p->hop_count += 1;
            send_ucast_l2_wrapper(&hop->next_hop_addr, p, sizeof(RREP2));
        } else {
            log_debug("RREP2: no next hop found => drop");
        }
    }
}

static void handle_DATA(const Address *rcv, const Address *src, const Address *dst, DATA *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("DATA: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length < sizeof(DATA) || length != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("DATA: packet is old => drop");
        return;
    }

    uint8_t *payload = get_data_payload(p);

    packet_trace_set("FORWARD", payload, p->payload_length);

    log_debug("DATA: got packet 0x%08x => 0x%08x / hop_count: %zu",
        p->src_id, p->dst_id, (size_t) p->hop_count);

    nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num, 0);

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: reached destination => accept");
        // destination is the local tun0 interface => write packet to tun0
        tun_write(payload, p->payload_length);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("DATA: send to next hop %s => forward", str_addr(&hop->next_hop_addr));
            // forward
            p->hop_count += 1;

            send_ucast_l2_wrapper(&hop->next_hop_addr, p, get_data_size(p));
        } else {
            log_debug("DATA: no next hop found => drop");
        }
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    Node *node = next_node_by_id(dst_id);
    Hop *hop = next_hop_by_node(node);
    if (node && hop) {
        // packet pointer points into an allocated chunk to fit some added header
        DATA *data = (DATA*) (packet - sizeof(DATA));

        data->type = TYPE_DATA;
        data->hop_count = 0;
        data->seq_num = g_sequence_number++;
        data->src_id = gstate.own_id;
        data->dst_id = dst_id;
        data->payload_length = packet_length;

        log_debug("tun_handler: send DATA packet (0x%08x => 0x%08x) to %s, hop_count: %zu",
            data->src_id, data->dst_id, str_addr(&hop->next_hop_addr), (size_t) hop->hop_count);

        send_ucast_l2_wrapper(&hop->next_hop_addr, data, get_data_size(data));
    } else {
        RREQ rreq = {
            .type = TYPE_RREQ_PF, // conservative?
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = dst_id,
            .sender = gstate.own_id,
            .prev_sender = gstate.own_id,
        };

        packet_cache_add(dst_id, packet, packet_length);

        log_debug("tun_handler: send packet (0x%08x => 0x%08x)", rreq.src_id, rreq.dst_id);

        send_RREQ(&rreq, true);
    }
}

static bool interface_handler(uint32_t ifindex, const char *ifname, bool added)
{
    //log_info("interface_handler: %s ifname %s", added ? "add" : "remove", ifname);

    if (added) {
        ifstate_create(ifindex);
    } else {
        ifstate_remove(ifindex);
    }

    return true;
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    bool is_broadcast = address_is_broadcast(dst);
    if (!is_broadcast && !address_equal(dst, rcv)) {
        // packet is not for us (possible e.g. when device is in monitor mode)
        return;
    }

    // count incoming traffic
    uint32_t ifindex = address_ifindex(src);
    InterfaceState *ifstate = ifstate_get(ifindex);
    if (is_broadcast) {
        count_broadcast_traffic(ifstate, 0, packet_length);
    } else {
        count_unicast_traffic(ifstate, 0, packet_length);
    }

    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(rcv, src, dst, (DATA*) packet, packet_length);
        break;
    case TYPE_RREQ_FF:
        handle_RREQ(ifstate, rcv, src, dst, (RREQ*) packet, packet_length);
        break;
    case TYPE_RREQ_PF:
        handle_RREQ(ifstate, rcv, src, dst, (RREQ*) packet, packet_length);
        break;
    case TYPE_RREP:
        handle_RREP(rcv, src, dst, (RREP*) packet, packet_length);
        break;
    case TYPE_RREP2:
        handle_RREP2(rcv, src, dst, (RREP2*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src));
    }
}

static bool console_handler(FILE* fp, int argc, const char *argv[])
{
    if (match(argv, "h")) {
        fprintf(fp, "r                       print routing table\n");
    } else if (match(argv, "i")) {
        fprintf(fp, "broadcasts:      %zu (send)/ %zu (dropped)\n", (size_t) g_broadcast_send_counter, (size_t) g_broadcast_dropped_counter);
        fprintf(fp, "HOP_TIMEOUT_MIN: %s\n", str_time(1000 * HOP_TIMEOUT_MIN_SECONDS));
        fprintf(fp, "HOP_TIMEOUT_MAX: %s\n", str_time(1000 * HOP_TIMEOUT_MAX_SECONDS));
        fprintf(fp, "TRAFFIC_DEGRADE_MAX: %s\n", str_time(1000 * TRAFFIC_DEGRADE_MAX_SECONDS));
        fprintf(fp, "TRAFFIC_DEGRADE:  %s\n", str_time(1000 * TRAFFIC_DEGRADE_SECONDS));
/*
        size_t interface_count = 0;
        InterfaceState *tmp;
        InterfaceState *ifstate;
        fprintf(fp, "   interface   flood_true_time  flood_false_time flood_needed\n");
        HASH_ITER(hh, g_ifstates, ifstate, tmp) {
            fprintf(fp, "%s [%zu] %s %s %s\n",
                str_ifindex(ifstate->ifindex),
                (size_t) ifstate->ifindex,
                str_since(ifstate->flood_needed_set_true_time),
                str_since(ifstate->flood_needed_set_false_time),
                str_yesno(ifstate->flood_needed)
            );
            interface_count += 1;
        }
        fprintf(fp, "%zu interfaces\n", interface_count);
*/
    } else if (match(argv, "r")) {
        Node *node;
        Node *ntmp;
        Hop *hop;
        Hop *htmp;
        size_t node_count = 0;
        size_t neighbor_count = 0;

        fprintf(fp, "hop-nodes:\n");
        fprintf(fp, " id          hop-count  next-hop-id   next-hop-address   last-updated\n");
        HASH_ITER(hh, g_nodes, node, ntmp) {
            node_count += 1;
            fprintf(fp, " 0x%08x\n", node->id);
            bool is_neighbor = false;
            HASH_ITER(hh, node->hops, hop, htmp) {
                if (hop->hop_count == 1) {
                    is_neighbor = true;
                }
                Node *neighbor = find_neighbor_by_address(&hop->next_hop_addr);
                fprintf(fp, "             %-9zu  0x%08x    %-18s %-8s ago\n",
                    (size_t) hop->hop_count,
                    (neighbor ? neighbor->id : 0),
                    str_addr(&hop->next_hop_addr),
                    str_since(hop->time_updated)
                );
            }

            if (is_neighbor) {
                neighbor_count += 1;
            }
        }
        fprintf(fp, "nodes: %zu, neighbors: %zu\n", node_count, neighbor_count);
    } else if (match(argv, "json")) {
        fprintf(fp, "{");
        fprintf(fp, "\"own_id\": \"0x%08x\",", gstate.own_id);
        fprintf(fp, "\"node_count\": %zu,", (size_t) HASH_COUNT(g_nodes));
        fprintf(fp, "\"broadcasts_send_counter\": %zu,", (size_t) g_broadcast_send_counter);
        fprintf(fp, "\"broadcasts_dropped_counter\": %zu,", (size_t) g_broadcast_dropped_counter);
        fprintf(fp, "\"ifstates\": {\n");
        InterfaceState *ifstate;
        InterfaceState *tmp;
        HASH_ITER(hh, g_ifstates, ifstate, tmp) {
            fprintf(fp, "\"%s\": {\n", str_ifindex(ifstate->ifindex));
            fprintf(fp, "\"flood_needed\": %s", str_bool(get_is_needed(ifstate)));
            fprintf(fp, "}\n");
        }
        fprintf(fp, "},\n");
        fprintf(fp, "\"packet_trace\": ");
        packet_trace_json(fp);
        fprintf(fp, "}\n");
    } else {
        return false;
    }

    return true;
}

static void init()
{
    net_add_handler(-1, &periodic_handler);
    packet_cache_init(20);
}

void ratelimit_2_register()
{
    static const Protocol p = {
        .name = "ratelimit-2",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
        .interface_handler = &interface_handler
    };

    protocols_register(&p);
}
