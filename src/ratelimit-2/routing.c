#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

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

enum Type {
    TYPE_DATA,
    TYPE_RREQ_FF, // full flood
    TYPE_RREQ_PF, // partial flood
    TYPE_RREP,
    TYPE_RREP2
};

#define HOP_TIMEOUT_MIN_SECONDS (10)
#define HOP_TIMEOUT_MAX_SECONDS (60 * 60 * 24)
#define TRAFFIC_DEGRADE_MAX_SECONDS (60 * 60 * 24)
#define TRAFFIC_DEGRADE_SECONDS (10)
#define MIN_BROADCAST_PACKETS_PER_SECONDS (1)
#define MIN_BROADCAST_PACKETS_PERCENT (5)
#define FULL_FLOOD_SEND_INTERVAL_SECONDS 3

typedef struct {
    Address next_hop_addr; // use neighbor object with id and address?
    time_t time_updated;
    time_t time_created; // by default time_updated + MAX_TIMEOUT
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

/*
 * Per interface state.
 * Not removed by any timeout, but interface callback.
*/
typedef struct {
    uint32_t ifindex;

    time_t full_flood_time; // last behavior change
    bool full_flood; // current behavior

    uint16_t received_broadcast_packets;
    uint16_t received_unicast_packets;
    uint16_t send_broadcast_packets;
    uint16_t send_unicast_packets;
    time_t time_broadcast_send;
    time_t time_updated;
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
    static time_t g_ifstate_last_degraded = 0;
    const time_t time_now = gstate.time_now;

    if ((time_now - g_ifstate_last_degraded) > TRAFFIC_DEGRADE_SECONDS) {
        InterfaceState *cur;
        InterfaceState *tmp;
        HASH_ITER(hh, g_ifstates, cur, tmp) {
            /*if ((time_now - cur->time_updated) > TRAFFIC_DEGRADE_MAX_SECONDS) {
                HASH_DEL(g_ifstates, cur);
                free(cur);
            } else if (degrade) { */
                cur->received_broadcast_packets /= 2;
                cur->received_unicast_packets /= 2;
                cur->send_broadcast_packets /= 2;
                cur->send_unicast_packets /= 2;
            //}
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
        ifstate->time_updated = gstate.time_now;
        ifstate->full_flood = true;
        HASH_ADD(hh, g_ifstates, ifindex, sizeof(uint32_t), ifstate);
    } else {
        log_warning("ifstate_create() ifindex %zu entry already exists", ifindex);
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
        ifstate->time_updated = gstate.time_now;
        ifstate->time_broadcast_send = gstate.time_now;
    }

    // received bytes
    if (received_bytes > 0) {
        const uint32_t n = 1 + received_bytes / 512;
        ifstate->received_broadcast_packets += n;
        ifstate->time_updated = gstate.time_now;
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

    if (send_bytes > 0 || received_bytes > 0) {
        ifstate->time_updated = gstate.time_now;
    }
}

static const char *str_type(enum Type type)
{
    switch (type) {
        case TYPE_DATA: return "DATA";
        case TYPE_RREQ_FF: return "RREQ_FF";
        case TYPE_RREQ_PF: return "RREQ_PF";
        case TYPE_RREP: return "RREP";
        case TYPE_RREP2: return "RREP2";
        default:
            log_warning("str_type() invalid type %zu", type);
            return "<invalid>";
    }
}

// send a RREQ as broadcast
static void send_rreq(RREQ* rreq)
{
    enum Type orig_type = rreq->type;

    InterfaceState *cur;
    InterfaceState *tmp;
    HASH_ITER(hh, g_ifstates, cur, tmp) {
        uint32_t bpackets = cur->received_broadcast_packets;
        uint32_t upackets = cur->received_unicast_packets;

        size_t pc = (100 * (1 + bpackets)) / (1 + bpackets + upackets);
        time_t last_broadcast = (gstate.time_now - cur->time_broadcast_send);

        // determine per interface if send as full or partial flood
        if (cur->full_flood) {
            rreq->type = TYPE_RREQ_FF;
        } else {
            rreq->type = orig_type;
        }

        if (pc <= MIN_BROADCAST_PACKETS_PERCENT
                || last_broadcast >= MIN_BROADCAST_PACKETS_PER_SECONDS) {
            log_debug("send_rreq() %s ifname: %s, bpackets: %zu (%zu%%), upackets: %zu, full_flood: %s, last_broadcast: %s ago => send",
                    str_type(rreq->type), str_ifindex(cur->ifindex), (size_t) bpackets, pc, (size_t) upackets, str_bool(cur->full_flood), str_time(last_broadcast));

            send_bcast_l2(cur->ifindex, rreq, sizeof(RREQ));
            count_broadcast_traffic(cur, sizeof(RREQ), 0);

            // for statistics only
            g_broadcast_send_counter += 1;
        } else {
            log_debug("send_rreq() %s ifname: %s, bpackets: %zu (%zu%%), upackets: %zu, full_flood: %s, last_broadcast: %s ago => drop",
                    str_type(rreq->type), str_ifindex(cur->ifindex), (size_t) bpackets, pc, (size_t) upackets, str_bool(cur->full_flood), str_time(last_broadcast));

            // for statistics only
            g_broadcast_dropped_counter += 1;
        }

        // broadcast done
        cur->full_flood_time = gstate.time_now;
        cur->full_flood = false;
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

static int is_newer_seqnum(uint16_t cur, uint16_t new)
{
    if (cur >= new) {
        return (cur - new) > 0x7fff;
    } else {
        return (new - cur) < 0x7fff;
    }
}

static bool is_new_neighbor(uint32_t id, uint16_t hop_count)
{
    Node *node;

    if (id == gstate.own_id || hop_count != 0) {
        return false;
    }

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    return (node == NULL);
}

static bool packet_seen(uint32_t id, uint16_t seq_num)
{
    Node *node;

    if (id == gstate.own_id) {
        return true;
    }

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

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
        log_error("nodes_update() got own id => ignore");
        return;
    } else {
        log_debug("nodes_update() id: 0x%08x, addr: %s, hop_count: %zu, seq_num: %zu, req_age: %zu",
            id, str_addr(addr), (size_t) hop_count, (size_t) seq_num, (size_t) req_age);
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
    Node *ncur;
    Node *ntmp;
    Hop *hcur;
    Hop *htmp;
    const time_t time_now = gstate.time_now;

    HASH_ITER(hh, g_nodes, ncur, ntmp) {
        // timeout next hops
        HASH_ITER(hh, ncur->hops, hcur, htmp) {
            /*
             * Dynamic Timeout - The longer a hop is used, the longer the timeout.
            */
            const uint32_t age1 = hcur->time_updated - hcur->time_created;
            const uint32_t age2 = time_now - hcur->time_updated;
            if (age2 > HOP_TIMEOUT_MIN_SECONDS
                && ((age2 > HOP_TIMEOUT_MAX_SECONDS) || (age1 < age2))) {
                log_debug("timeout node 0x%08x, hop %s (age1: %s, age2: %s)",
                    ncur->id, str_addr(&hcur->next_hop_addr), str_time(age1), str_time(age2));
                HASH_DEL(ncur->hops, hcur);

                if (hcur->hop_count == 1) {
                    // get interface?
                    uint32_t ifindex = address_ifindex(&hcur->next_hop_addr);
                    InterfaceState *ifstate = ifstate_find(ifindex);
                    if (ifstate) {
                        ifstate->full_flood = true;
                    } else {
                        log_error("nodes_timeout() failed to find ifindex %zu", ifindex);
                    }
                }

                free(hcur);
            }
        }

        // no hops left => remove node
        if (ncur->hops == NULL) {
            log_debug("remove node 0x%08x", ncur->id);
            HASH_DEL(g_nodes, ncur);
            free(ncur);
        }
    }
}

static Node *next_node_by_id(uint32_t id)
{
    Node *node;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    return node;
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

    Hop *hcur;
    Hop *htmp;
    Hop *hbest = NULL;
    HASH_ITER(hh, node->hops, hcur, htmp) {
        if (is_better_hop(hbest, hcur)) {
            hbest = hcur;
        }
    }

    return hbest;
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
static Node *find_node_by_address(const Address *addr)
{
    Node *ncur;
    Node *ntmp;
    Hop *hcur;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, ncur, ntmp) {
        HASH_ITER(hh, ncur->hops, hcur, htmp) {
            if (hcur->hop_count == 1 && 0 == memcmp(&hcur->next_hop_addr, addr, sizeof(Address))) {
                return ncur;
            }
        }
    }

    return NULL;
}

static void periodic_handler()
{
    nodes_timeout();
    traffic_degrade();

    InterfaceState *cur;
    InterfaceState *tmp;
    HASH_ITER(hh, g_ifstates, cur, tmp) {
        // fall back to full flood after FULL_FLOOD_SEND_INTERVAL seconds
        if (gstate.time_now >= (cur->full_flood_time + FULL_FLOOD_SEND_INTERVAL_SECONDS))  {
            cur->full_flood = true;
        }
    }
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

// Common behavior for Full and Partial Flood RREQ. May seend RREP and RREP2.
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
    }

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
    }

    return false;
}

static void handle_RREQ_PF(InterfaceState *ifstate, const Address *rcv, const Address *src, const Address *dst, RREQ *p, size_t length)
{
    // we expect broadcasts or packets for us
    if (!(address_is_broadcast(dst) || address_equal(rcv, dst))) {
        log_trace("RREQ_PF: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(RREQ)) {
        log_debug("RREQ_PF: invalid packet size => drop");
        return;
    }

    // new neighbor node appeared
    if (is_new_neighbor(p->src_id, p->hop_count)) {
        ifstate->full_flood = true;
    }

    if (packet_seen(p->src_id, p->seq_num)) {
        log_debug("RREQ_PF: duplicate packet => drop");
        return;
    }

    log_debug("RREQ_PF: got packet: %s / 0x%08x => 0x%08x / sender: %08x, prev_sender: %08x, hop_count: %u, seq_num: %u",
        str_addr(dst), p->src_id, p->dst_id, p->sender, p->prev_sender, p->hop_count, p->seq_num);

    nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num, 0);
    //nodes_update(p->sender, src, 1, p->seq_num, 0);
    //nodes_update(p->prev_sender, src, 2, p->seq_num, 0); // needed? What if we are the previous sender?

    if (!try_reply_RREQ("RREQ_PF", src, p)) {
        if (ifstate->full_flood) { // TODO: this must be the sending interface?
            log_debug("RREQ_PF: is needed => rebroadcast");
            p->hop_count += 1;
            p->prev_sender = p->sender;
            p->sender = gstate.own_id;
            send_rreq(p);
        } else {
            log_debug("RREQ_PF: not needed => drop");
        }
    }
}

static void handle_RREQ_FF(InterfaceState *ifstate, const Address *rcv, const Address *src, const Address *dst, RREQ *p, size_t length)
{
    // we expect broadcasts or packets for us
    if (!(address_is_broadcast(dst) || address_equal(rcv, dst))) {
        log_trace("RREQ_FF: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(RREQ)) {
        log_debug("RREQ_FF: invalid packet size => drop");
        return;
    }

    bool seen = packet_seen(p->src_id, p->seq_num);

    log_debug("RREQ_FF: got packet: %s / 0x%08x => 0x%08x / sender: %08x, prev_sender: %08x, hop_count: %u, seq_num: %u, seen: %s",
        str_addr(dst), p->src_id, p->dst_id, p->sender, p->prev_sender, p->hop_count, p->seq_num, str_bool(seen));

    if (!seen) {
        nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num, 0);
        //nodes_update(p->prev_sender, src, 1, p->seq_num, 0); // prev_sender and seq_num does not match

        // packet seen the first time
        if (!try_reply_RREQ("RREQ_FF", src, p)) {
            log_debug("RREQ_FF: is needed => rebroadcast");
            p->hop_count += 1;
            p->prev_sender = p->sender;
            p->sender = gstate.own_id;
            send_rreq(p);
        }
    } else {
        // packet already seen
        if (p->prev_sender == gstate.own_id && p->src_id == gstate.own_id) {
            log_debug("RREQ_FF: duplicate packet (echo) => drop");
        } else {
            log_debug("RREQ_FF: duplicate packet (no echo) => drop");
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

    if (packet_seen(p->src_id, p->seq_num)) {
        log_debug("RREP: packet already seen => drop");
        return;
    }

    log_debug("RREP: got packet: %s / 0x%08x => 0x%08x / hop_count: %zu, seq_num: %zu",
        str_addr(src), p->src_id, p->dst_id, (size_t) p->hop_count, (size_t) p->seq_num);

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

    if (packet_seen(p->src_id, p->seq_num)) {
        log_debug("RREP2: packet already seen => drop (0x%08x, seq_num: %zu)", p->src_id, (size_t) p->seq_num);
        return;
    }

    log_debug("RREP2: got packet: %s / 0x%08x => 0x%08x / hop_count: %zu, seq_num: %zu,"
              " req_id: 0x%08x, req_seq_num: %zu, req_hops: %zu, req_age: %zu)",
        str_addr(src), p->src_id, p->dst_id, (size_t) p->hop_count, (size_t) p->seq_num,
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

    if (packet_seen(p->src_id, p->seq_num)) {
        log_debug("DATA: packet already seen => drop");
        return;
    }

    uint8_t *payload = get_data_payload(p);

    packet_trace_set("FORWARD", payload, p->payload_length);

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x / hop_count: %zu",
        str_addr(src), p->src_id, p->dst_id, (size_t) p->hop_count);

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

        send_rreq(&rreq);
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
        handle_RREQ_FF(ifstate, rcv, src, dst, (RREQ*) packet, packet_length);
        break;
    case TYPE_RREQ_PF:
        handle_RREQ_PF(ifstate, rcv, src, dst, (RREQ*) packet, packet_length);
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

static bool console_handler(FILE* fp, const char *argv[])
{
    if (match(argv, "h")) {
        fprintf(fp, "r                       print routing table\n");
    } else if (match(argv, "i")) {
        fprintf(fp, "broadcasts:      %zu (send)/ %zu (dropped)\n", (size_t) g_broadcast_send_counter, (size_t) g_broadcast_dropped_counter);
        fprintf(fp, "HOP_TIMEOUT_MIN: %s\n", str_time(HOP_TIMEOUT_MIN_SECONDS));
        fprintf(fp, "HOP_TIMEOUT_MAX: %s\n", str_time(HOP_TIMEOUT_MAX_SECONDS));
        fprintf(fp, "TRAFFIC_DEGRADE_MAX: %s\n", str_time(TRAFFIC_DEGRADE_MAX_SECONDS));
        fprintf(fp, "TRAFFIC_DEGRADE:  %s\n", str_time(TRAFFIC_DEGRADE_SECONDS));

        size_t interface_count = 0;
        InterfaceState *icur;
        InterfaceState *itmp;
        fprintf(fp, "   interface   full_flood_time  full_flood time_updated\n");
        HASH_ITER(hh, g_ifstates, icur, itmp) {
            fprintf(fp, "%s [%zu] %s %s %s\n",
                str_ifindex(icur->ifindex),
                (size_t) icur->ifindex,
                str_ago(icur->full_flood_time),
                str_bool(icur->full_flood),
                str_ago(icur->time_updated)
            );
            interface_count += 1;
        }
        fprintf(fp, "%zu interfaces\n", interface_count);
    } else if (match(argv, "r")) {
        Node *ncur;
        Node *ntmp;
        Hop *hcur;
        Hop *htmp;
        size_t node_count = 0;
        size_t neighbor_count = 0;

        fprintf(fp, "hop-nodes:\n");
        fprintf(fp, " id          hop-count  next-hop-id   next-hop-address   last-updated\n");
        HASH_ITER(hh, g_nodes, ncur, ntmp) {
            node_count += 1;
            fprintf(fp, " 0x%08x\n", ncur->id);
            bool is_neighbor = false;
            HASH_ITER(hh, ncur->hops, hcur, htmp) {
                if (hcur->hop_count == 1) {
                    is_neighbor = true;
                }
                Node *node = find_node_by_address(&hcur->next_hop_addr);
                fprintf(fp, "             %-9zu  0x%08x    %-18s %-8s ago\n",
                    (size_t) hcur->hop_count,
                    (node ? node->id : 0),
                    str_addr(&hcur->next_hop_addr),
                    str_ago(hcur->time_updated)
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
        fprintf(fp, "\"broadcasts_send_counter\": %zu,", (size_t) g_broadcast_send_counter);
        fprintf(fp, "\"broadcasts_dropped_counter\": %zu,", (size_t) g_broadcast_dropped_counter);
        fprintf(fp, "\"packet_trace\": ");
        packet_trace_json(fp);
        fprintf(fp, "}\n");
    } else {
        return true;
    }

    return false;
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
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
        .interface_handler = &interface_handler
    };

    protocols_register(&p);
}
