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
    TYPE_RREQ,
    TYPE_RREP,
    TYPE_RREP2,
    TYPE_PING,
    TYPE_PONG,
    TYPE_RERR
};

#define HOP_TIMEOUT_MIN_SECONDS 10
#define HOP_TIMEOUT_MAX_SECONDS (60 * 60 * 24)
#define TRAFFIC_DURATION_SECONDS 10

// maximum number of entries in a packet
#define MAX_RREQ_ENTRIES 10

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

typedef struct {
    uint64_t updated_time;
    uint32_t out_bytes[TRAFFIC_DURATION_SECONDS];
    uint32_t in_bytes[TRAFFIC_DURATION_SECONDS];
} Traffic;

// for detecting connection breaks
typedef struct {
    Address addr;
    uint8_t pinged;
    uint64_t time_created;
    uint64_t time_last_recv;
    uint64_t time_last_send;
    uint64_t time_send_DATA;

    // TODO: use
    Traffic unicast_traffic;
    Traffic broadcast_traffic;

    UT_hash_handle hh;
} Neighbor;

// Per interface state. Removed/added only by interface_handler().
typedef struct {
    uint32_t ifindex;

    // We need to forward a broadcast (RREQ) if a neighbor uses us a source.
    uint64_t recv_own_broadcast_time;
    uint64_t recv_foreign_broadcast_time;
    uint64_t send_broadcast_time;

    // TODO: use
    Traffic unicast_traffic;
    Traffic broadcast_traffic;

    UT_hash_handle hh;
} InterfaceState;

typedef struct __attribute__((__packed__)) {
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
} RREQ_ENTRY;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t sender;
    uint32_t prev_sender;
    uint8_t entries_count;
    RREQ_ENTRY entries[MAX_RREQ_ENTRIES];
} RREQ;

// response to a RREQ from destiantion node
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

// used to probe a neighbor is still alive
typedef struct __attribute__((__packed__)) {
    uint8_t type;
} PING;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
} PONG;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num;
    uint8_t hop_count;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t unreachable_id;
} RERR;

static uint16_t g_sequence_number = 0;
static InterfaceState *g_ifstates = NULL;
static Node *g_nodes = NULL;
static Neighbor *g_neighbors = NULL;

// accumulate RREQ entries
static uint32_t g_rreq_entries_last_prev_sender = 0;
static RREQ_ENTRY g_rreq_entries[MAX_RREQ_ENTRIES] = {0};
static size_t g_rreq_entries_count = 0;

// forward declaration
static void send_ucast_l2_wrapper(const Address *next_hop_addr, const void* data, size_t data_len);

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

static InterfaceState *ifstate_get_by_address(const Address *address)
{
    uint32_t ifindex = address_ifindex(address);
    return ifstate_get(ifindex);
}

static Neighbor *neighbors_find(const Address *addr)
{
    Neighbor *neighbor = NULL;
    HASH_FIND(hh, g_neighbors, addr, sizeof(Address), neighbor);
    return neighbor;
}

static Neighbor *neighbors_get(const Address *addr)
{
    Neighbor *neighbor = neighbors_find(addr);
    if (neighbor == NULL) {
        // add new entry
        neighbor = (Neighbor*) calloc(1, sizeof(Neighbor));
        neighbor->time_created = gstate.time_now;
        memcpy(&neighbor->addr, addr, sizeof(Address));
        HASH_ADD(hh, g_neighbors, addr, sizeof(Address), neighbor);
    }
    return neighbor;
}

// received packet by neighbor
static void neighbors_recv_packet(const Address *addr, uint8_t type)
{
    Neighbor *neighbor = neighbors_get(addr);
    neighbor->time_last_recv = gstate.time_now;
    neighbor->pinged = 0;
}

// send packet to neighbor
static void neighbors_send_packet(const Address *addr, uint8_t type)
{
    Neighbor *neighbor = neighbors_get(addr);
    neighbor->time_last_send = gstate.time_now;
    if (type == TYPE_DATA) {
        neighbor->time_send_DATA = gstate.time_now;
        log_debug("set time_send_DATA");
    }
}

static void nodes_remove_by_addr(const Address *addr)
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            if (0 == memcmp(&hop->next_hop_addr, addr, sizeof(Address))) {
                log_debug("neighbors_remove() remove hop to 0x%08x via %s", node->id, str_addr(&hop->next_hop_addr));
                HASH_DEL(node->hops, hop);
                free(hop);
            }
        }
        if (node->hops == NULL) {
            log_debug("neighbors_remove() remove node 0x%08x", node->id);
            HASH_DEL(g_nodes, node);
            free(node);
        }
    }
}

static void neighbors_periodic()
{
    /*
    * Make sure neighbors are still there:
    * 1. directly after a DATA packet is send to them and no DATA reply was seen
    * 2. after extended periods (check with exponential backoff)
    */
    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        if (
            //((neighbor->time_last_recv - neighbor->time_created) <= (gstate.time_now - neighbor->time_last_recv))
            //||
            (neighbor->time_send_DATA != 0) // is set
            && (neighbor->time_last_recv != 0) // is set
            && ((neighbor->time_send_DATA + 1000) < gstate.time_now) // data packet >1s ago
            && (neighbor->time_send_DATA > (neighbor->time_last_recv + 2 * gstate.time_resolution))) // no response for last data packet
        {
            log_debug("time_send_DATA: %u, time_last_recv: %u", (unsigned) neighbor->time_send_DATA, (unsigned) neighbor->time_last_recv);

            // we have send a DATA packet and have not seen a DATA back or PONG back => send PING
            if (neighbor->pinged > 2) {
                log_debug("neighbors_periodic() remove neighbor");
                nodes_remove_by_addr(&neighbor->addr);
                HASH_DEL(g_neighbors, neighbor);
                free(neighbor);
            } else {
                // A response PONG will update the entry in g_neighbors and g_nodes.
                PING ping = {
                    .type = TYPE_PING,
                };
                log_debug("neighbors_periodic() ping neighbor");
                send_ucast_l2_wrapper(&neighbor->addr, &ping, sizeof(ping));
                neighbor->pinged += 1;
            }
        }
    }
}

static void clear_old_traffic_counters(Traffic *traffic)
{
    size_t idx = gstate.time_now % TRAFFIC_DURATION_SECONDS;
    uint32_t since = (gstate.time_now - traffic->updated_time);
    size_t n = MIN(since, TRAFFIC_DURATION_SECONDS);

    // clear old traffic measurement buckets
    for (size_t i = 0; i < n; ++i) {
        size_t j = (TRAFFIC_DURATION_SECONDS + idx + i + 1) % TRAFFIC_DURATION_SECONDS;
        traffic->in_bytes[j] = 0;
        traffic->out_bytes[j] = 0;
    }
}

static void record_traffic(Traffic *traffic, uint32_t in_bytes, uint32_t out_bytes)
{
    clear_old_traffic_counters(traffic);

    size_t idx = gstate.time_now % TRAFFIC_DURATION_SECONDS;
    traffic->updated_time = gstate.time_now;
    traffic->in_bytes[idx] += out_bytes;
    traffic->out_bytes[idx] += in_bytes;
}

static void record_traffic_by_addr(const Address *src, uint32_t out_bytes, uint32_t in_bytes)
{
    if (address_is_broadcast(src)) {
        InterfaceState *ifstate = ifstate_get_by_address(src);
        record_traffic(&ifstate->broadcast_traffic, out_bytes, in_bytes);
        //Neighbor *neighbor = neighbors_find(src);
        //record_traffic(&neighbor->broadcast_traffic, out_bytes, in_bytes);
    } else {
        InterfaceState *ifstate = ifstate_get_by_address(src);
        record_traffic(&ifstate->unicast_traffic, out_bytes, in_bytes);
        Neighbor *neighbor = neighbors_find(src);
        record_traffic(&neighbor->unicast_traffic, out_bytes, in_bytes);
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
            }
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

static void print_RREQ(const RREQ *p)
{
    for (size_t i = 0; i < p->entries_count; ++i) {
        const RREQ_ENTRY *e = &p->entries[i];
        log_debug("RREQ: i: %u, 0x%08x => 0x%08x (hop_count: %u, seq_num: %u)", (unsigned) i, e->src_id, e->dst_id, (unsigned) e->hop_count, (unsigned) e->seq_num);
    }
}

static size_t get_RREQ_size(const RREQ *p)
{
    return offsetof(RREQ, entries) + p->entries_count * sizeof(RREQ_ENTRY);
}

// send a RREQ as broadcast
static void send_RREQ(const RREQ* rreq)
{
    //log_debug("RREQ: entries_count: %u", rreq->entries_count);
    print_RREQ(rreq);

    InterfaceState *ifstate;
    InterfaceState *tmp;
    HASH_ITER(hh, g_ifstates, ifstate, tmp) {
        bool is_needed = get_is_needed(ifstate);
        if (is_needed) {
            log_debug("RREQ: is_needed: %s => send", str_bool(is_needed));

            ifstate->send_broadcast_time = gstate.time_now;

            size_t size = get_RREQ_size(rreq);
            send_bcast_l2(ifstate->ifindex, rreq, size);
            record_traffic(&ifstate->broadcast_traffic, size, 0);

            // for statistics only
            g_broadcast_send_counter += 1;
        } else {
            log_debug("RREQ: is not needed => drop");
        }
    }
}

// send and count outgoing unicast traffic
static void send_ucast_l2_wrapper(const Address *next_hop_addr, const void* data, size_t data_len)
{
    send_ucast_l2(next_hop_addr, data, data_len);

    record_traffic_by_addr(next_hop_addr, data_len, 0);

    neighbors_send_packet(next_hop_addr, ((const uint8_t*)data)[0]);
}

static Node *next_node_by_id(uint32_t id)
{
    Node *node;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    return node;
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

    //node->time_seen = gstate.time_now;

    hop->hop_count = hop_count;
    hop->time_updated = gstate.time_now;
}

static void nodes_periodic()
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            uint64_t span1 = (hop->time_updated - hop->time_created) / 1000;
            uint64_t span2 = (gstate.time_now - hop->time_updated) / 1000;
            if ((span2 > HOP_TIMEOUT_MIN_SECONDS) && ((span2 > HOP_TIMEOUT_MAX_SECONDS) || (span1 < span2))) {
                log_debug("nodes_periodic() timeout node 0x%08x via %s, hop %s (span1: %s, span2: %s)",
                    node->id, str_addr(&hop->next_hop_addr), str_addr(&hop->next_hop_addr), str_time(span1), str_time(span2));
                HASH_DEL(node->hops, hop);
                free(hop);
            }
        }
        if (node->hops == NULL) {
            log_debug("nodes_periodic() remove node 0x%08x", node->id);
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

static size_t get_DATA_size(DATA *p)
{
    return (offsetof(DATA, payload_data) + p->payload_length);
}

static uint8_t* get_DATA_payload(DATA *p)
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

// forward delcaration
static void send_rreq2_periodic();

static void periodic_handler()
{
    neighbors_periodic();
    nodes_periodic();
    //traffic_periodic();
    send_rreq2_periodic();
}

static void send_cached_packet(uint32_t dst_id)
{
    uint8_t buffer[ETH_FRAME_LEN - offsetof(DATA, payload_data)];

    Node *node = next_node_by_id(dst_id);
    Hop *hop = next_hop_by_node(node);
    if (node && hop) {
        DATA *data = (DATA*) &buffer[0];
        uint8_t* data_payload = get_DATA_payload(data);
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

            send_ucast_l2_wrapper(&hop->next_hop_addr, data, get_DATA_size(data));
        } else {
            // no cached packet found
            log_debug("send_cached_packet() no cached packet found for destiantion 0x%08x => ignore", dst_id);
        }
    } else {
        log_warning("send_cached_packet() no next hop found for destination 0x%08x => ignore", dst_id);
    }
}

//TODO:
// * tie tokens per second to traffic
// * use token buckets per interface
static void send_rreq2_periodic()
{
#define MAX_TOKENS 2
#define ADD_TOKENS_PER_SECOND 2

    static uint32_t send_tokens = MAX_TOKENS;
    static uint64_t prev_call = 0;

    uint32_t add_tokens = (ADD_TOKENS_PER_SECOND * (gstate.time_now - prev_call)) / 1024;
    if (add_tokens > 0) {
        send_tokens = MIN(send_tokens + add_tokens, MAX_TOKENS);
        prev_call = gstate.time_now;
    }

    if (send_tokens > 0 && g_rreq_entries_count > 0) {
        send_tokens -= 1;

        // re-send immediately
        RREQ rreq2 = {
            .type = TYPE_RREQ,
            .sender = gstate.own_id,
            .prev_sender = g_rreq_entries_last_prev_sender,
            .entries_count = g_rreq_entries_count,
        };

        // add entries
        for (size_t i = 0; i < g_rreq_entries_count; ++i) {
            rreq2.entries[i] = g_rreq_entries[i];
            rreq2.entries[i].hop_count += 1;
        }

        send_RREQ(&rreq2);

        g_rreq_entries_last_prev_sender = 0;
        g_rreq_entries_count = 0;
    }
}

static void store_RREQ_ENTRY(uint32_t last_sender, const RREQ_ENTRY *e1)
{
    /*
      Add entry for next RREQ that we can send.
      Priorize lower hop counts.
    */
    if (e1->hop_count == UINT8_MAX) {
        log_debug("store_RREQ_ENTRY() max hop count reached => drop");
        return;
    }

    // check for duplicate entry
    for (size_t i = 0; i < g_rreq_entries_count; ++i) {
        const RREQ_ENTRY *e2 = &g_rreq_entries[i];
        if (e1->src_id == e2->src_id && e1->dst_id == e2->dst_id) {
            g_rreq_entries_last_prev_sender = last_sender;
            g_rreq_entries[i] = *e1;
            log_debug("store_RREQ_ENTRY() => inserted");
            return;
        }
    }

    // replace least recently added (LRU)
    g_rreq_entries_last_prev_sender = last_sender;
    g_rreq_entries[(g_rreq_entries_count) % MAX_RREQ_ENTRIES] = *e1;
    g_rreq_entries_count += 1;

    log_debug("store_RREQ_ENTRY() entry num %u => added", (unsigned) g_rreq_entries_count);
}

static void handle_RREQ(const Address *rcv, const Address *src, const Address *dst, RREQ *p, size_t length)
{
    // we expect broadcasts or packets for us
    if (!(address_is_broadcast(dst) || address_equal(rcv, dst))) {
        log_trace("RREQ: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != get_RREQ_size(p)) {
        log_debug("RREQ: invalid packet size => drop");
        return;
    }

    if (p->prev_sender == gstate.own_id) {
        InterfaceState *ifstate = ifstate_get_by_address(src);
        ifstate->recv_own_broadcast_time = gstate.time_now;
        log_debug("RREQ: own echo => drop");
        return;
    }

    log_debug("RREQ: got packet, entries_count: %u, 0x%08x => 0x%08x (hop_count: %u, seq_num: %u), sender: 0x%08x, prev_sender: 0x%08x",
        (unsigned) p->entries_count, p->entries[0].src_id, p->entries[0].dst_id,
        (unsigned) p->entries[0].hop_count, (unsigned) p->entries[0].seq_num, p->sender, p->prev_sender);

    // check if sequence number is old
    for (size_t i = 0; i < p->entries_count; ++i) {
        const RREQ_ENTRY *e = &p->entries[i];

        if (packet_is_duplicate(e->src_id, e->seq_num)) {
            //log_debug("RREQ_ENTRY: old entry (src_id: 0x%08x / seq_num: %zu) => drop", e->src_id, (size_t) e->seq_num);
            continue;
        }

        nodes_update(e->src_id, src, e->hop_count + 1, e->seq_num, 0);
        //nodes_update(e->prev_sender, src, 1, e->seq_num, 0); // prev_sender and seq_num does not match

        // we are the destination
        if (e->dst_id == gstate.own_id) {
            log_debug("RREQ_ENTRY: destination reached => send RREP");
            RREP rrep = {
                .type = TYPE_RREP,
                .hop_count = 0,
                .seq_num = g_sequence_number++,
                .src_id = gstate.own_id,
                .dst_id = e->src_id,
            };

            // send back unicast
            send_ucast_l2_wrapper(src, &rrep, sizeof(rrep));
        } else {
            // we know a node
            Node *node = next_node_by_id(e->dst_id);
            Hop *hop = next_hop_by_node(node);
            if (node && hop && (1UL + e->hop_count + hop->hop_count) <= UINT16_MAX) {
                log_debug("RREQ_ENTRY: destination known => send RREP2");
                uint8_t age = MIN(gstate.time_now - hop->time_updated, UINT8_MAX);
                RREP2 rrep2 = {
                    .type = TYPE_RREP2,
                    .hop_count = 0,
                    .seq_num = g_sequence_number++,
                    .src_id = gstate.own_id,
                    .dst_id = e->src_id,
                    .req_id = e->dst_id,
                    .req_seq_num = node->seq_num,
                    .req_hops = hop->hop_count + 1, // or use hop_count from RREQ?
                    .req_age = age,
                };

                send_ucast_l2_wrapper(src, &rrep2, sizeof(RREP2));
            } else {
                store_RREQ_ENTRY(p->prev_sender, e);
            }
        }
    }

    // resend immediately if possible
    send_rreq2_periodic();
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

    if (length < offsetof(DATA, payload_data) || length != get_DATA_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("DATA: packet is old => drop");
        return;
    }

    uint8_t *payload = get_DATA_payload(p);

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

            send_ucast_l2_wrapper(&hop->next_hop_addr, p, get_DATA_size(p));
        } else {
            log_debug("DATA: no next hop found => drop and send unreachable");

            RERR ur = {
                .type = TYPE_RERR,
                .seq_num = g_sequence_number++,
                .hop_count = 0,
                .src_id = gstate.own_id,
                .dst_id = p->src_id,
                .unreachable_id = p->dst_id,
            };
            send_ucast_l2_wrapper(src, &ur, sizeof(ur));
        }
    }
}

static void handle_PING(const Address *rcv, const Address *src, const Address *dst, PING *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("PING: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(PING)) {
        log_debug("PING: invalid packet size => drop");
        return;
    }

/*
    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("PING: packet is old => drop");
        return;
    }
*/

    //log_debug("PING: got packet 0x%08x => 0x%08x / hop_count: %zu",
    //    p->src_id, p->dst_id, 1);
    log_debug("PING: got packet from %s => send pong", str_addr(src));

    //nodes_update(p->src_id, src, 1, p->seq_num, 0);

    //if (p->dst_id == gstate.own_id) {
        //log_debug("PING: for me => send pong");
        PONG pong = {
            .type = TYPE_PONG,
            //.seq_num = g_sequence_number++,
        };
        send_ucast_l2_wrapper(src, &pong, sizeof(pong));
    //} else {
    //    log_debug("PING: not for me => drop");
    //}
}

static void handle_PONG(const Address *rcv, const Address *src, const Address *dst, PONG *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("PONG: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(PONG)) {
        log_debug("PONG: invalid packet size => drop");
        return;
    }

    log_debug("PONG: got packet from %s => ignore", str_addr(src));
}

static void handle_RERR(const Address *rcv, const Address *src, const Address *dst, RERR *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("RERR: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(RERR)) {
        log_debug("RERR: invalid packet size => drop");
        return;
    }

    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("RERR: packet is old => drop");
        return;
    }

    // link between src_id and unreachable_id nodes broke
    Node *unreachable_node = next_node_by_id(p->unreachable_id);

    if (unreachable_node) {
        log_debug("RERR: remove hop");

        // remove entry
        Hop *htmp;
        Hop *hop;
        HASH_ITER(hh, unreachable_node->hops, hop, htmp) {
            if (0 == memcmp(src, &hop->next_hop_addr, sizeof(Address))) {
                log_debug("RERR: remove next hop %s for 0x%08x => delete", str_addr(src), unreachable_node->id);
                HASH_DEL(unreachable_node->hops, hop);
                free(hop);
                if (unreachable_node->hops == NULL) {
                    log_debug("RERR: node 0x%08x has no further hops => delete", unreachable_node->id);
                    HASH_DEL(g_nodes, unreachable_node);
                    free(unreachable_node);
                }
                break;
            }
        }
    }

    // record the node that is sending us the report
    nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0);

    if (p->dst_id == gstate.own_id) {
        log_debug("RERR: destiantion reached => drop");
    } else {
        // forward
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RERR: send to next hop %s => forward", str_addr(&hop->next_hop_addr));
            // forward
            p->hop_count += 1;

            send_ucast_l2_wrapper(&hop->next_hop_addr, p, length);
        } else {
            log_debug("RERR: no next hop found => drop");
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
        DATA *data = (DATA*) (packet - offsetof(DATA, payload_data));

        data->type = TYPE_DATA;
        data->hop_count = 0;
        data->seq_num = g_sequence_number++;
        data->src_id = gstate.own_id;
        data->dst_id = dst_id;
        data->payload_length = packet_length;

        log_debug("tun_handler: send DATA packet (0x%08x => 0x%08x) to %s, hop_count: %zu",
            data->src_id, data->dst_id, str_addr(&hop->next_hop_addr), (size_t) hop->hop_count);

        send_ucast_l2_wrapper(&hop->next_hop_addr, data, get_DATA_size(data));
    } else {
        RREQ_ENTRY entry = {
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = dst_id,
        };

        packet_cache_add(dst_id, packet, packet_length);

        log_debug("tun_handler: send packet (0x%08x => 0x%08x)", entry.src_id, entry.dst_id);

        store_RREQ_ENTRY(gstate.own_id, &entry);
        send_rreq2_periodic();
    }
}

// called once for added/removed interfaces
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
    bool is_destination = address_equal(dst, rcv);
    bool is_broadcast = address_is_broadcast(dst);

    if (!is_broadcast && !is_destination) {
        // packet is not for us (possible e.g. when device is in monitor mode)
        return;
    }

    // packet is for us
    neighbors_recv_packet(src, packet[0]);

    // count incoming traffic
    record_traffic_by_addr(src, 0, packet_length);

    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(rcv, src, dst, (DATA*) packet, packet_length);
        break;
    case TYPE_RREQ:
        handle_RREQ(rcv, src, dst, (RREQ*) packet, packet_length);
        break;
    case TYPE_RREP:
        handle_RREP(rcv, src, dst, (RREP*) packet, packet_length);
        break;
    case TYPE_RREP2:
        handle_RREP2(rcv, src, dst, (RREP2*) packet, packet_length);
        break;
    case TYPE_PING:
        handle_PING(rcv, src, dst, (PING*) packet, packet_length);
        break;
    case TYPE_PONG:
        handle_PONG(rcv, src, dst, (PONG*) packet, packet_length);
        break;
    case TYPE_RERR:
        handle_RERR(rcv, src, dst, (RERR*) packet, packet_length);
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
        fprintf(fp, "HOP_TIMEOUT_MIN: %s\n", str_time(HOP_TIMEOUT_MIN_SECONDS));
        fprintf(fp, "HOP_TIMEOUT_MAX: %s\n", str_time(HOP_TIMEOUT_MAX_SECONDS));
        fprintf(fp, "TRAFFIC_DURATION_SECONDS:  %s\n", str_time(TRAFFIC_DURATION_SECONDS));
    } else if (match(argv, "r")) {
        Node *node;
        Node *ntmp;
        Hop *hop;
        Hop *htmp;
        size_t node_count = 0;
        size_t neighbor_count = 0;

        fprintf(fp, "nodes:\n");
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
    } else if (match(argv, "n")) {
        Neighbor *neighbor;
        Neighbor *tmp;

        fprintf(fp, "neighbors:\n");
        fprintf(fp, " address    time_created time_last_send time_last_recv\n");
        HASH_ITER(hh, g_neighbors, neighbor, tmp) {
            fprintf(fp, " %s %s %s %s\n",
                str_addr(&neighbor->addr),
                str_time(neighbor->time_created),
                str_time(neighbor->time_last_send),
                str_time(neighbor->time_last_recv)
            );
        }
    } else if (match(argv, "json")) {
        fprintf(fp, "{");
        fprintf(fp, "\"own_id\": \"0x%08x\",", gstate.own_id);
        fprintf(fp, "\"node_count\": %zu,", (size_t) HASH_COUNT(g_nodes));
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

void ratelimit_3_register()
{
    static const Protocol p = {
        .name = "ratelimit-3",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
        .interface_handler = &interface_handler
    };

    protocols_register(&p);
}
