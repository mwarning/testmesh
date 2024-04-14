#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <assert.h>
#include <inttypes.h>

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
#include "ranges.h"


enum {
    TYPE_DATA,

    TYPE_ROOT_CREATE,
    TYPE_ROOT_STORE,

    TYPE_RREQ,
    TYPE_RREP,
    TYPE_RREP2,
    TYPE_PING,
    TYPE_PONG,
    TYPE_RERR,

    TYPE_NETWORK_SHORTCUT_IPV4,
    TYPE_NETWORK_SHORTCUT_IPV6,
};

//static bool g_root_enable = true;
/*
enum ROOT_SETTING {
    ROOT_SETTING_NO, // never send a ROOT packet
    ROOT_SETTING_YES, //
    ROOT_SETTING_MAYBE, // send root if not other ROOT is there
};
*/

enum FLAGS {
    FLAG_IS_BROADCAST = 1,
    FLAG_IS_UNICAST = 2,
    FLAG_IS_DESTINATION = 4,
};

#define ENABLE_SEND_RREP2 true

#define HOP_TIMEOUT_MS (8 * 1000)
#define TRAFFIC_DURATION_SECONDS 8
#define UNKNOWN_SEQUENCE_NUMBER UINT32_MAX

typedef struct {
    Address next_hop_addr; // use neighbor object with id and address?
    uint64_t time_updated;
    uint64_t time_created;
    uint16_t hop_count;
    UT_hash_handle hh;
} Hop;

// per destination
typedef struct {
    uint32_t id;
    uint64_t time_created;
    uint64_t time_updated;
    uint32_t seq_num; // sequence numbers are 16bit, use UINT32_MAX for unknown value
    Hop *hops;
    UT_hash_handle hh;
} Node;

typedef struct {
    uint64_t updated_time;
    uint32_t out_bytes[TRAFFIC_DURATION_SECONDS];
    uint32_t in_bytes[TRAFFIC_DURATION_SECONDS];
} Traffic;

typedef struct {
    uint32_t root_id;
    uint16_t hop_count;
    uint16_t root_seq_num;
    uint64_t root_recv_time;
    uint64_t root_send_time; //needed?
    uint32_t parent_id; // for debugging

    uint64_t store_send_time; // needed?
    uint32_t store_send_counter;
    uint64_t time_created; // or use neighbor creation time?
} Root;

// for detecting connection breaks
typedef struct {
    Address address;
    //bool is_child;

    // needed?
    uint64_t packets_send_count;
    uint64_t packets_send_time;

    uint8_t pinged;
    uint64_t time_created;
    uint64_t time_updated;


    uint64_t root_store_to_others_received_time;
    uint64_t root_store_to_us_received_time;

    bool root_set;
    Root root;

    bool ranges_set;
    Ranges ranges;
    // neighbor is a child only if we received ranges recently and have not seen this node sending it do a different node
    //uint64_t ranges_updated;
    //uint64_t ranges_updated_next;
    // we should have the same for the root....

    // TODO: use
    Traffic unicast_traffic;
    Traffic broadcast_traffic;

    UT_hash_handle hh;
} Neighbor;

static Root g_root = {0};

typedef struct Peer {
    char hostname[64];
    Address address;
    struct Peer *next;
} Peer;

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
} IFState;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t payload_length;
    uint8_t payload_data[];
} DATA;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
} RREQ;

// response to a RREQ from destination node
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
    uint8_t req_age_exp; // age of routing information in seconds
} RREP2;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num;
    uint8_t hop_count;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t unreachable_id;
} RERR;

// used to probe a neighbor is still alive
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num;
} PING;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num;
} PONG;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t root_seq_num;
    // uint8_t neighbor_count;
    // uint8_t stored_nodes;
    // uint8_t has_public_address_ip; // the direct neighbors can verify this
    uint32_t root_id; // use a random id?
    // for 
    uint32_t sender;
    uint32_t prev_sender;
} ROOT_CREATE;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t data[1500 - 1];
} ROOT_STORE;

// TODO: use
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num;
    uint8_t address[4];
} NETWORK_SHORTCUT_IPV4;

// TODO: use
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num;
    uint8_t address[16];
} NETWORK_SHORTCUT_IPV6;

static Peer *g_peers = NULL;
static uint16_t g_sequence_number = 0;
static IFState *g_ifstates = NULL;
static Node *g_nodes = NULL;
static Neighbor *g_neighbors = NULL;

// forward declaration
static void send_ucast_wrapper(const Address *next_hop_addr, const void* data, size_t data_len);

static IFState *ifstate_find(const uint32_t ifindex)
{
    IFState *ifstate = NULL;
    HASH_FIND(hh, g_ifstates, &ifindex, sizeof(uint32_t), ifstate);
    return ifstate;
}

static void ifstate_remove(const uint32_t ifindex)
{
    IFState *ifstate = ifstate_find(ifindex);
    if (ifstate != NULL) {
        // remove entry
        HASH_DEL(g_ifstates, ifstate);
        free(ifstate);
    }
}

static IFState *ifstate_create(const uint32_t ifindex)
{
    IFState *ifstate = ifstate_find(ifindex);
    if (ifstate == NULL) {
        // add new entry
        ifstate = (IFState*) calloc(1, sizeof(IFState));
        ifstate->ifindex = ifindex;
        HASH_ADD(hh, g_ifstates, ifindex, sizeof(uint32_t), ifstate);
    } else {
        log_warning("ifstate_create() %s/%zu entry already exists", str_ifindex(ifindex), ifindex);
    }
    return ifstate;
}

// create non-existing entries
static IFState *ifstate_get(const uint32_t ifindex)
{
    IFState *ifstate = ifstate_find(ifindex);
    return ifstate ? ifstate : ifstate_create(ifindex);
}

static IFState *ifstate_get_by_address(const Address *address)
{
    uint32_t ifindex = address_ifindex(address);
    return ifstate_get(ifindex);
}

static void neighbors_added(const Neighbor *neighbor)
{
}

/*
static void reset_root(Root *root)
{
    memset(root, 0, sizeof(Root));
    root->root_seq_num = 0; // only use when we are root
    root->root_id = gstate.own_id;
    root->parent_id = gstate.own_id;
    root->time_created = 0;
    root->store_send_time = 0;
    root->store_send_counter = 0;
}*/

static void nodes_remove_next_hop_addr(const Address *addr);

static void neighbors_removed(const Neighbor *neighbor)
{
    log_debug("neighbors_removed() %s", str_addr(&neighbor->address));

    // make sure that the node is removed as well
    nodes_remove_next_hop_addr(&neighbor->address);
}

static void nodes_added(const Node *node)
{
}

static void nodes_removed(const Node *node)
{

}

/*
static void root_init(Root *root)
{
    memset(root, 0, sizeof(Root));
}

static void root_clear(Root *root)
{
    root_init(root);
}*/

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
        //root_init(&neighbor->root);
        //ranges_init(&neighbor->ranges, 0);
        neighbor->time_created = gstate.time_now;
        memcpy(&neighbor->address, addr, sizeof(Address));
        HASH_ADD(hh, g_neighbors, address, sizeof(Address), neighbor);
        neighbors_added(neighbor);
    }
    return neighbor;
}

static void nodes_remove_next_hop_addr(const Address *addr)
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
            nodes_removed(node);
            HASH_DEL(g_nodes, node);
            free(node);
        }
    }
}

static void neighbor_free(Neighbor *neighbor)
{
    free(neighbor->ranges.data);
    free(neighbor);
}

// ping neighbors
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
        if ((neighbor->time_updated < gstate.time_now)
                && (gstate.time_now - neighbor->time_updated) > HOP_TIMEOUT_MS) {
            // we have send a DATA packet and have not seen a DATA back or PONG back => send PING
            if (neighbor->pinged > 2) {
                log_debug("neighbors_periodic() remove neighbor %s", str_addr(&neighbor->address));
                neighbors_removed(neighbor);
                HASH_DEL(g_neighbors, neighbor);
                neighbor_free(neighbor);
            } else {
                // A response PONG will update the entry in g_neighbors and g_nodes.
                PING ping = {
                    .type = TYPE_PING,
                    .seq_num = g_sequence_number++,
                };
                log_debug("neighbors_periodic() ping neighbor %s", str_addr(&neighbor->address));
                send_ucast_wrapper(&neighbor->address, &ping, sizeof(ping));
                neighbor->pinged += 1;
            }
        }
    }
}

static void clear_old_traffic_counters(Traffic *traffic)
{
    assert(traffic != NULL);

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
    IFState *ifstate = ifstate_get_by_address(src);
    if (address_is_broadcast(src)) {
        record_traffic(&ifstate->broadcast_traffic, out_bytes, in_bytes);
        //Neighbor *neighbor = neighbors_get(src);
        //record_traffic(&neighbor->broadcast_traffic, out_bytes, in_bytes);
    } else {
        record_traffic(&ifstate->unicast_traffic, out_bytes, in_bytes);
        Neighbor *neighbor = neighbors_get(src);
        record_traffic(&neighbor->unicast_traffic, out_bytes, in_bytes);
    }
}

static bool get_is_needed(const IFState *ifstate)
{
    return true;

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

// send and count outgoing unicast traffic
static void send_ucast_wrapper(const Address *next_hop_addr, const void* data, size_t data_len)
{
    if (next_hop_addr->family == AF_MAC) {
        send_ucast_l2(next_hop_addr, data, data_len);
    } else {
        send_ucast_l3(next_hop_addr, data, data_len);
    }

    record_traffic_by_addr(next_hop_addr, data_len, 0);

    //neighbors_send_packet(next_hop_addr, ((const uint8_t*)data)[0]);

    Neighbor *neighbor = neighbors_get(next_hop_addr);
    neighbor->packets_send_count += 1;
    neighbor->packets_send_time = gstate.time_now;
    /*
    uint8_t type = ((const uint8_t*)data)[0];
    if (type == TYPE_DATA) {
        neighbor->time_send_DATA = gstate.time_now;
        //log_debug("set time_send_DATA");
    }*/
}

static Node *next_node_by_id(uint32_t id)
{
    Node *node;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    return node;
}

static bool packet_is_duplicate(uint32_t id, uint32_t seq_num)
{
    if (id == gstate.own_id) {
        return true;
    }

    if (seq_num == UNKNOWN_SEQUENCE_NUMBER) {
        return false;
    }

    Node *node = next_node_by_id(id);
    if (node) {
        if (is_newer_seqnum((uint16_t) node->seq_num, (uint16_t) seq_num)) {
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
static bool nodes_update(uint32_t id, const Address *addr, uint16_t hop_count, uint32_t seq_num, uint16_t age_bias)
{
    bool is_new_packet = packet_is_duplicate(id, seq_num);

    if (id != gstate.own_id) {
        //log_debug("nodes_update() id: 0x%08x, addr: %s, hop_count: %d, seq_num: %d, age_bias: %d",
        //    id, str_addr(addr), (int) hop_count, (int) seq_num, (int) age_bias);
        Node *node;
        Hop *hop;

        HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);
        if (node == NULL) {
            // add new entry
            node = (Node*) malloc(sizeof(Node));
            node->time_created = gstate.time_now;
            node->id = id;
            if (seq_num != UNKNOWN_SEQUENCE_NUMBER) {
                node->seq_num = seq_num;
            } else {
                node->seq_num = 0;
            }
            node->hops = NULL;
            HASH_ADD(hh, g_nodes, id, sizeof(uint32_t), node);
            nodes_added(node);
        }

        HASH_FIND(hh, node->hops, addr, sizeof(Address), hop);
        if (hop == NULL) {
            // add new entry
            hop = (Hop*) malloc(sizeof(Hop));
            hop->time_created = gstate.time_now - age_bias;
            hop->next_hop_addr = *addr;
            HASH_ADD(hh, node->hops, next_hop_addr, sizeof(Address), hop);
        }

        //node->time_seen = gstate.time_now;

        hop->hop_count = hop_count;
        hop->time_updated = gstate.time_now;

        node->time_updated = gstate.time_now;
    }

    return is_new_packet;
}

static bool neighbor_is_child(const Neighbor *neighbor)
{
    const uint64_t us = neighbor->root_store_to_us_received_time;
    const uint64_t others = neighbor->root_store_to_others_received_time;
    const uint64_t now = gstate.time_now;

    if (us == 0) {
        return false;
    }

    if (us < others) {
        return false;
    }

    // needed?
    if (us <= now && ((now - us) > HOP_TIMEOUT_MS)) {
        // child timed out
        return false;
    }

    return true;
}

static Neighbor *get_parent()
{
    Neighbor *cur = NULL;
    Neighbor *new;
    Neighbor *tmp;

    //log_debug("get_parent()");

    HASH_ITER(hh, g_neighbors, new, tmp) {
        if (!new->root_set) {
            // ignore
            continue;
        }

        //log_debug("get_parent() iter: %s root_id: 0x%08x, root_seq_num: %d",
        //    str_addr(&new->address), new->root.root_id, (int) new->root.root_seq_num);

        if (cur == NULL) {
            cur = new;
            continue;
        }

        bool is_neighbor_overdue = (new->root.root_recv_time + 1200) < gstate.time_now;
        bool is_parent_overdue = (cur->root.root_recv_time + 1200) < gstate.time_now;

//log_debug("cur: is_overdue: %s, new: is_overdue: %s", str_bool(is_parent_overdue), str_bool(is_neighbor_overdue));

        if (is_neighbor_overdue != is_parent_overdue) {
            if (is_parent_overdue) {
                cur = new;
            } else {
                // neighbor is overdue => ignore
                continue;
            }
        } else {
            if (new->root.root_id > cur->root.root_id) {
                cur = new;
            } else if (new->root.root_id == cur->root.root_id) {
                uint16_t neighbor_scope = address_scope(&new->address);
                uint16_t parent_scope = address_scope(&cur->address);

                if (neighbor_scope != parent_scope) {
                    if (neighbor_scope > parent_scope) {
                        log_debug("choose by address scope");
                        cur = new;
                    } else {
                        continue;
                    }
                }

                if (new->root.hop_count < cur->root.hop_count) {
                    cur = new;
                } else if (new->root.hop_count == cur->root.hop_count) {
                    int cmp = memcmp(&new->address, &cur->address, sizeof(Address));
                    if (cmp > 0) {
                        cur = new;
                    }
                } else {
                    continue;
                }
            }
        }
    }

    if (cur) {
        // see if we are root (return NULL)
        if (cur->root_set) {
            bool is_parent_overdue = (cur->root.root_recv_time + 1200) < gstate.time_now;
            if (is_parent_overdue) {
                // we are root
                cur = NULL;
            } else {
                if (g_root.root_id > cur->root.root_id) {
                    //log_debug("get_parent() => 0x%08x > 0x%08x we are root", g_root.root_id, cur->root.root_id);
                    // we are root
                    cur = NULL;
                }
            }
        } else {
            // we are root
            cur = NULL;
        }
    }

    return cur;
}

static bool we_are_root()
{
    return get_parent() == NULL;
}

// timeout nodes
static void nodes_periodic()
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            if ((gstate.time_now - hop->time_updated) > HOP_TIMEOUT_MS) {
                HASH_DEL(node->hops, hop);
                free(hop);
            }
        }

        if (node->hops == NULL) {
            HASH_DEL(g_nodes, node);
            nodes_removed(node);
            free(node);
        }
    }
}

static bool is_better_hop(const Hop *cur, const Hop *new)
{
    if (cur == NULL) {
        // take "new" one
        return true;
    }

/*
    if (new->time_updated > cur->time_updated) {
        return true;
    }
*/

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

static size_t get_size_ROOT_CREATE(const ROOT_CREATE *p)
{
    return sizeof(ROOT_CREATE);
}

static size_t get_size_PING(const PING *p)
{
    return sizeof(PING);
}

static size_t get_size_PONG(const PONG *p)
{
    return sizeof(PONG);
}

static size_t get_size_RREP2(const RREP2 *p)
{
    return sizeof(RREP2);
}

static size_t get_size_DATA(const DATA *p)
{
    return (offsetof(DATA, payload_data) + p->payload_length);
}

static size_t get_size_RREQ(const RREQ *p)
{
    return sizeof(RREQ);
}

static size_t get_size_RREP(const RREP *p)
{
    return sizeof(RREP);
}

static uint8_t* get_payload_DATA(DATA *p)
{
    return ((uint8_t*) p) + offsetof(DATA, payload_data);
}

static bool is_valid_address(const Address *addr)
 {
    static const Address zero_address = {0};
    return 0 != memcmp(addr, &zero_address, sizeof(Address));
}

// return node behind an address (only possible if neighbor)
// beware: slow - only for debugging
static Node *find_neighbor_node_by_address(const Address *addr)
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

/*
static uint32_t get_neighbor_id(const Neighbor *neighbor)
{
    Node *node = find_neighbor_node_by_address(&neighbor->address);
    return node ? node->id : 0;
}
*/

static void send_cached_packet(uint32_t dst_id)
{
    uint8_t buffer[ETH_FRAME_LEN - offsetof(DATA, payload_data)];

    Node *node = next_node_by_id(dst_id);
    Hop *hop = next_hop_by_node(node);
    if (node && hop) {
        DATA *p = (DATA*) &buffer[0];
        uint8_t* data_payload = get_payload_DATA(p);
        size_t data_payload_length = 0;
        packet_cache_get_and_remove(data_payload, &data_payload_length, dst_id);

        if (data_payload_length > 0) {
            //decrease_ip_ttl(data_payload, data_payload_length);

            p->type = TYPE_DATA;
            p->hop_count = 1,
            p->seq_num = g_sequence_number++;
            p->src_id = gstate.own_id;
            p->dst_id = dst_id;
            p->payload_length = data_payload_length;

            log_debug("send_cached_packet() send DATA (0x%08x => 0x%08x) via next hop %s, hop_count: %d",
                p->src_id, p->dst_id, str_addr(&hop->next_hop_addr), (int) hop->hop_count);

            send_ucast_wrapper(&hop->next_hop_addr, p, get_size_DATA(p));
        } else {
            // no cached packet found
            log_debug("send_cached_packet() no cached packet found for destination 0x%08x => ignore", dst_id);
        }
    } else {
        log_warning("send_cached_packet() no next hop found for destination 0x%08x => ignore", dst_id);
    }
}

// send a broadcast on an interface
static void send_bcast_l2_wrapper_interface(const char *context, IFState *ifstate, void *packet, size_t packet_size)
{
    bool is_needed = get_is_needed(ifstate);
    if (is_needed) {
        //log_debug("%s: is_needed: %s => send", context, str_bool(is_needed));

        ifstate->send_broadcast_time = gstate.time_now;

        send_bcast_l2(ifstate->ifindex, packet, packet_size);
        record_traffic(&ifstate->broadcast_traffic, packet_size, 0);
    } else {
        log_debug("%s: is not needed => drop", context);
    }
}

// used for ROOT packet
static void send_bcast_wrapper(const char *context, void *packet, size_t packet_size)
{
    {
        Neighbor *neighbor;
        Neighbor *tmp;
        HASH_ITER(hh, g_neighbors, neighbor, tmp) {
            int af = neighbor->address.family;
            if (af == AF_INET || af == AF_INET6) {
                //if (is_lan_address(&neighbor->address)) {
                    send_ucast_l3(&neighbor->address, packet, packet_size);
                //} else {
                    //send_bcast_l3(&neighbor->address, packet, packet_size);
                //}
            }
        }
    }

    {
        IFState *ifstate;
        IFState *tmp;
        HASH_ITER(hh, g_ifstates, ifstate, tmp) {
            send_bcast_l2_wrapper_interface(context, ifstate, packet, packet_size);
        }
    }
}

static void send_ROOT_CREATE_periodic()
{
    if (we_are_root()) {
        if (g_root.root_send_time == 0 || (g_root.root_send_time + 1000) <= gstate.time_now) {
            g_root.root_send_time = gstate.time_now;

            ROOT_CREATE p = {
                .type = TYPE_ROOT_CREATE,
                .root_id = gstate.own_id,
                .root_seq_num = g_root.root_seq_num++,
                .hop_count = 1,
                .sender = gstate.own_id,
                .prev_sender = gstate.own_id
            };

            log_debug("send_ROOT_CREATE_periodic send ROOT_CREATE (root_id: 0x%08x, seq_num: %d, hop_count: %u)",
                p.root_id, p.root_seq_num, p.hop_count);
            send_bcast_wrapper("send_ROOT_CREATE_periodic", &p, get_size_ROOT_CREATE(&p));
        }
    }
}

static uint64_t next_ROOT_STORE_periodic()
{
    Neighbor *parent = get_parent();

    if (parent) {

    //#define END_INTERVAL (60 * 60)

#define START_INTERVAL_MS 100

        uint32_t intervals = parent->root.store_send_counter / 3;
        uint64_t span = START_INTERVAL_MS * (1 << intervals);
        uint32_t rest = parent->root.store_send_counter - (intervals * 3);
        return parent->root.time_created + span + ((span * rest) / 3);
    } else {
        log_error("next_ROOT_STORE_periodic() => we are root");
        return 0;
    }
}

/*
// get an upper limit count of ranges
static size_t count_ranges(const Neighbor *parent)
{
    size_t max_ranges = 0;
    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        if (neighbor_is_child(neighbor)) {
            max_ranges += neighbor->ranges.data_count;
        }
    }
    return max_ranges;
}*/

static void send_ROOT_STORE_periodic()
{
    Neighbor *parent = get_parent();

    //log_debug("send_ROOT_STORE_periodic check");
    if (parent) {
        // we have a parent => we are not root
        if (parent->root.store_send_time == 0
                || (parent->root.store_send_time + (HOP_TIMEOUT_MS / 2)) < gstate.time_now) {
            parent->root.store_send_time = gstate.time_now;

            ROOT_STORE p = {
                .type = TYPE_ROOT_STORE,
            };

            Ranges ranges;
            ranges_init(&ranges, 0);

            // add own id
            ranges_add(&ranges, gstate.own_id, 0);

            int i = 0;
            Neighbor *neighbor;
            Neighbor *tmp;
            HASH_ITER(hh, g_neighbors, neighbor, tmp) {
                // only include children
                if (neighbor_is_child(neighbor)) {
                    log_debug("send_ROOT_STORE_periodic: [%d] neighbor ranges: %s", i, ranges_str(&neighbor->ranges));
                    ranges_add_all(&ranges, &neighbor->ranges);
                    i += 1;
                }
            }
/*
{
    log_debug("ranges out: %s", ranges_str(&ranges));
}
*/
            // bytes available for ranges
            size_t data_size_max = FIELD_SIZEOF(ROOT_STORE, data);
            int bytes = ranges_compress(&p.data[0], data_size_max, &ranges);
/*
{
    Ranges out;
    ranges_init(&out, 0);

    int rc2 = ranges_decompress(&out, &p.data[0], bytes);
    log_debug("ranges out/in: rc2: %d, out: %s", rc2, ranges_str(&out));

    ranges_free(&out);
}
*/

            if (bytes != -1) {
                assert(bytes > 0 && bytes <= data_size_max);
                log_debug("send_ROOT_STORE_periodic: send to %s, bytes: %d (all: %d), spans: %d, ranges: %s",
                    str_addr(&parent->address), (int) bytes, (int) (offsetof(ROOT_STORE, data) + bytes), (int) ranges_span(&ranges), ranges_str(&ranges));
                send_ucast_wrapper(&parent->address, &p, offsetof(ROOT_STORE, data) + bytes);
            } else {
                log_error("failed to compress ranges");
            }
            ranges_free(&ranges);

            parent->root.store_send_counter += 1;
        }
    }
}

// add static peers 
static void peers_periodic()
{
    static uint64_t last_check_ms = 0;
    static uint32_t check_interval_ms = 200; // start value milliseconds

    if (g_peers && (last_check_ms == 0 || (gstate.time_now - last_check_ms) > check_interval_ms)) {
        last_check_ms = gstate.time_now;
        if (check_interval_ms < (24 * 60 * 60 * 1000)) {
            check_interval_ms *= 2;
        }

        log_debug("peers_periodic() do now, next peer ping in %s", str_time(check_interval_ms));

        PING ping = {
            .type = TYPE_PING,
            .seq_num = g_sequence_number++,
        };

        uint32_t pings_send = 0;
        Peer *peer = g_peers;
        while (peer) {
            if (!is_valid_address(&peer->address) && !neighbors_find(&peer->address)) {
                // peer not resolved and not connected
                bool resolved = false;
                int af = gstate.af;
                if (af == AF_UNSPEC || af == AF_INET6) {
                    if (addr_parse((struct sockaddr *) &peer->address, &peer->hostname[0], STR(UNICAST_UDP_PORT), AF_INET6)) {
                        log_debug("peer: send ping to %s", str_addr(&peer->address));
                        send_ucast_wrapper(&peer->address, &ping, get_size_PING(&ping));
                        resolved = true;
                        pings_send += 1;
                    }
                }

                if (af == AF_UNSPEC || af == AF_INET) {
                    if (addr_parse((struct sockaddr *) &peer->address, &peer->hostname[0], STR(UNICAST_UDP_PORT), AF_INET)) {
                        log_debug("peer: send ping to %s", str_addr(&peer->address));
                        send_ucast_wrapper(&peer->address, &ping, get_size_PING(&ping));
                        resolved = true;
                        pings_send += 1;
                    }
                }

                if (!resolved) {
                    log_warning("peer: failed to resolve %s", &peer->hostname[0]);
                }
            }
            peer = peer->next;
        }
    }
}

static void periodic_handler()
{
    neighbors_periodic();
    nodes_periodic();
    send_ROOT_CREATE_periodic();
    send_ROOT_STORE_periodic();
    peers_periodic();
}

static void handle_PING(const Neighbor *from_neighbor, const Address *src, uint8_t flags, PING *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    // we expect (unicast) packets for us only
    if (is_broadcast || !is_destination) {
        log_trace("PING: unexpected destination => drop");
        return;
    }

    if (length != sizeof(PING)) {
        log_debug("PING: invalid packet size => drop");
        return;
    }

    /*
    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_trace("PING: packet is old => drop");
        return;
    }*/

    log_debug("PING: got packet from %s, seq_num: %d => send pong", str_addr(src), p->seq_num);

    PONG pong = {
        .type = TYPE_PONG,
        .seq_num = g_sequence_number++,
    };

    send_ucast_wrapper(src, &pong, get_size_PONG(&pong));
}

static void handle_PONG(const Neighbor *from_neighbor, const Address *src, uint8_t flags, PONG *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    // we expect (unicast) packets for us only
    if (is_broadcast || !is_destination) {
        log_trace("PONG: unexpected destination => drop");
        return;
    }

    if (length != get_size_PONG(p)) {
        log_debug("PONG: invalid packet size => drop");
        return;
    }

    // packet has done its job (neighbor timeone postponed)
    log_debug("PONG: got packet from %s, seq_num: %d => accept", str_addr(src), p->seq_num);
}

static void log_RREP2(const char* context, const RREP2 *p, const char *action)
{
    log_debug("%s 0x%08x => 0x%08x, hop_count: %d, seq_num: %d,"
            " req_id: 0x%08x, req_seq_num: %d, req_hops: %d, req_age_exp: %d) => %s",
            context, p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num,
            p->req_id, (int) p->req_seq_num, (int) p->req_hops, (int) p->req_age_exp, action);
}

static void handle_RREP2(const Address *src, uint8_t flags, RREP2 *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    // we expect (unicast) packets for us only
    if (is_broadcast || !is_destination) {
        log_trace("RREP2: unexpected destination => drop");
        return;
    }

    if (length != sizeof(RREP2)) {
        log_debug("RREP2: invalid packet size => drop");
        return;
    }

    if (p->hop_count == 0 || p->hop_count >= UINT8_MAX) {
        log_debug("RREP2: invalid hop count => drop");
        return;
    }

    if (packet_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("RREP2: packet is old => drop (src_id: 0x%08x, seq_num: %d)", p->src_id, (int) p->seq_num);
        return;
    }

    // add information about originator node
    nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0);
    // add information from originator node about requested node
    nodes_update(p->req_id, src, p->hop_count + p->req_hops, p->req_seq_num, (1UL << p->req_age_exp));

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->req_id);
        log_RREP2("RREP2: destination reached", p, "send cached packet");
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            p->hop_count += 1;
            send_ucast_wrapper(&hop->next_hop_addr, p, get_size_RREP2(p));

            log_RREP2("RREP2: next hop found", p, "forward");
        } else {
            log_RREP2("RREP2: no next hop found", p, "drop");
        }
    }
}

static void handle_DATA(const Address *src, uint8_t flags, DATA *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast || !is_destination) {
        log_trace("DATA: unexpected destination => drop");
        return;
    }

    if (length < offsetof(DATA, payload_data) || length != get_size_DATA(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (p->hop_count == 0 || p->hop_count >= UINT8_MAX) {
        log_debug("DATA: invalid hop count => drop");
        return;
    }

    if (nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0)) {
        log_trace("DATA: packet is old => drop");
        return;
    }

    uint8_t *payload = get_payload_DATA(p);

    packet_trace_set("FORWARD", payload, p->payload_length);

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: got packet 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, destination reached => accept",
            p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);
        //decrease_ip_ttl(payload, p->payload_length);
        tun_write(payload, p->payload_length);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("DATA: got packet 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, send to next hop %s %d hops away => forward",
                p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num, str_addr(&hop->next_hop_addr), (int) hop->hop_count);
            // forward
            p->hop_count += 1;
            send_ucast_wrapper(&hop->next_hop_addr, p, get_size_DATA(p));
        } else {
            log_debug("DATA: got packet 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, no next hop known => drop and send RERR",
                p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);

            RERR ur = {
                .type = TYPE_RERR,
                .seq_num = g_sequence_number++,
                .hop_count = 1,
                .src_id = gstate.own_id,
                .dst_id = p->src_id,
                .unreachable_id = p->dst_id,
            };

            send_ucast_wrapper(src, &ur, sizeof(ur));
        }
    }
}

static void handle_RREP(const Address *src, uint8_t flags, RREP *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast || !is_destination) {
        log_trace("RREP: unexpected destination => drop");
        return;
    }

    if (length != get_size_RREP(p)) {
        log_debug("RREP: invalid packet size => drop");
        return;
    }

    if (p->hop_count == 0 || p->hop_count >= UINT8_MAX) {
        log_debug("RREP: invalid hop count => drop");
        return;
    }

    if (nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0)) {
        log_trace("RREP: packet is old => drop");
        return;
    }

    if (p->dst_id == gstate.own_id) {
        log_debug("RREP: got packet 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, destination reached => accept",
            p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);

        send_cached_packet(p->src_id);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RREP: got packet 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, next hop known, send to %s => forward",
                p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num, str_addr(&hop->next_hop_addr));

            p->hop_count += 1;
            send_ucast_wrapper(&hop->next_hop_addr, p, sizeof(RREP));
        } else {
            log_debug("RREP: got packet 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, no next hop known => drop",
                p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);
        }
    }
}

static void send_RREQ(const char *context, const Neighbor *from, const RREQ *p)
{
    uint32_t counter = 0;
    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        if (neighbor != from && ranges_includes(&neighbor->ranges, p->dst_id)) {
            log_debug("[%d] %s: 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, found routing hint, send to %s => forward",
                counter, context, p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num, str_addr(&neighbor->address));
            send_ucast_wrapper(&neighbor->address, p, get_size_RREQ(p));
            counter += 1;
        }
    }

/*
how do we handle false positives?
*/

    if (counter == 0) {
        // route towards parent as well
        Neighbor *parent = get_parent();
        if (parent) {
            if (parent != neighbor) {
                log_debug("[0] %s: 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, send to parent %s => forward",
                    context, p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num, str_addr(&parent->address));
                send_ucast_wrapper(&parent->address, p, get_size_RREQ(p));
            } else {
                log_warning("[0] %s: 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, do not route back to sender => ignore",
                    context, p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);
            }
        } else {
            log_warning("[0] %s: 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, no parent - we are root  => ignore",
                context, p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);
        }
    }
}

static uint8_t highest_bit(uint64_t v)
{
    uint8_t r = 0;
    while (v >>= 1) {
        r++;
    }
    return r;
}

static void handle_RREQ(Neighbor *neighbor, const Address *src, uint8_t flags, RREQ *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast || !is_destination) {
        log_trace("RREQ: unexpected destination => drop");
        return;
    }

    if (length != get_size_RREQ(p)) {
        log_debug("RREQ: invalid packet size (%d != %d) => drop", (int) length, (int) get_size_RREQ(p));
        return;
    }

    if (p->hop_count == 0 || p->hop_count >= UINT8_MAX) {
        log_debug("RREQ: invalid hop count => drop");
        return;
    }

    if (nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0)) {
        log_debug("RREQ: packet is old, 0x%08x => 0x%08x, seq_num: %d => drop",
            p->src_id, p->dst_id, (int) p->seq_num);
        return;
    }

    if (p->dst_id == gstate.own_id) {
        RREP rrep = {
            .type = TYPE_RREP,
            .hop_count = 1,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
        };

        // send back unicast
        send_ucast_wrapper(src, &rrep, get_size_RREP(&rrep));

        log_debug("RREQ: 0x%08x => 0x%08x, seq_num: %d, destination reached => send back RREP (0x%08x => 0x%08x, seq_num: %d, hop_count: %d)",
            p->src_id, p->dst_id, (int) p->seq_num, rrep.src_id, rrep.dst_id, (int) rrep.seq_num, (int) rrep.hop_count);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (ENABLE_SEND_RREP2
                && node
                && hop
                // is combined hop count small enough
                && (1UL + p->hop_count + hop->hop_count) <= UINT8_MAX
                // is the route still be viable? Hop must be at least half the lifetime ahead
                && (gstate.time_now - hop->time_updated) <= (HOP_TIMEOUT_MS / 2)) {
            // get exponent for the age of the hop as an estimate, round up
            uint8_t milli_seconds_exponent = 1 + highest_bit(gstate.time_now - hop->time_updated);
            RREP2 rrep2 = {
                .type = TYPE_RREP2,
                .hop_count = 1,
                .seq_num = g_sequence_number++,
                .src_id = gstate.own_id,
                .dst_id = p->src_id,
                .req_id = p->dst_id,
                .req_seq_num = node->seq_num,
                .req_hops = hop->hop_count + 1, // or use hop_count from RREQ?
                .req_age_exp = milli_seconds_exponent,
            };

            send_ucast_wrapper(src, &rrep2, get_size_RREP2(&rrep2));

            log_debug("RREQ: 0x%08x => 0x%08x, seq_num: %d destination known => send RREP2 (0x%08x => 0x%08x, seq_num: %d, hop_count: %d)",
                p->src_id, p->dst_id, (int) p->seq_num, (int) rrep2.src_id, rrep2.dst_id, (int) rrep2.seq_num, (int) rrep2.hop_count);
        } else {
            p->hop_count += 1;
            send_RREQ("RREQ", neighbor, p);
        }
    }
}

static void handle_RERR(const Address *src, uint8_t flags, RERR *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast && !is_destination) {
        log_trace("RERR: unexpected destination => drop");
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
        log_debug("RERR: remove hops for 0x%08x", unreachable_node->id);

        // remove entry (what about RouteItems?)
        Hop *htmp;
        Hop *hop;
        HASH_ITER(hh, unreachable_node->hops, hop, htmp) {
            if (0 == memcmp(src, &hop->next_hop_addr, sizeof(Address))) {
                log_debug("RERR: remove next hop %s for 0x%08x => delete", str_addr(src), unreachable_node->id);
                HASH_DEL(unreachable_node->hops, hop);
                free(hop);
                if (unreachable_node->hops == NULL) {
                    log_debug("RERR: node 0x%08x has no further hops => delete", unreachable_node->id);
                    nodes_removed(unreachable_node);
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
        log_debug("RERR: 0x%08x => 0x%08x, seq_num: %d, destination reached => drop",
            p->src_id, p->dst_id, p->seq_num);
    } else {
        // forward
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RERR: 0x%08x => 0x%08x, seq_num: %d, send to next hop %s => forward",
                p->src_id, p->dst_id, p->seq_num, str_addr(&hop->next_hop_addr));
            // forward
            p->hop_count += 1;

            send_ucast_wrapper(&hop->next_hop_addr, p, length);
        } else {
            log_debug("RERR: 0x%08x => 0x%08x, seq_num: %d, no next hop found => drop",
                p->src_id, p->dst_id, p->seq_num);
        }
    }
}

static void handle_ROOT_STORE(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, ROOT_STORE *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast) {
        log_trace("ROOT_STORE: broadcast destination => ignore");
        return;
    }

    ranges_clear(&neighbor->ranges);

    int data_size = length - offsetof(ROOT_STORE, data);
/*
    char buf[200];
    hex_dump(buf, sizeof(buf), &p->data[0], data_size);
    log_debug(buf);
*/
    int rc = ranges_decompress(&neighbor->ranges, &p->data[0], data_size);
    if (rc == -1) {
        neighbor->ranges_set = false;
        log_warning("ROOT_STORE: failed to decompress ranges from %s", str_addr(src));
    } else {
        neighbor->ranges_set = true;
        if (is_destination) {
            neighbor->root_store_to_us_received_time = gstate.time_now;
        } else {
            // => neighbor is not our child node
            neighbor->root_store_to_others_received_time = gstate.time_now;
        }
        //store entries, this is the important part
        log_debug("ROOT_STORE: got packet from %s, is_destination: %s, bytes: %d, span: %d, ranges: %s",
            str_addr(src), str_bool(is_destination), data_size, (int) ranges_span(&neighbor->ranges),
            ranges_str(&neighbor->ranges));
    }
}

static void handle_ROOT_CREATE(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, ROOT_CREATE *p, size_t length)
{
    // might be broadcast or unicast packet (e.g. per Internet)
    if (length != get_size_ROOT_CREATE(p)) {
        log_trace("ROOT_CREATE: invalid packet size => drop");
        return;
    }

    if (p->hop_count == 0 || p->hop_count >= UINT8_MAX) {
        log_trace("ROOT_CREATE: invalid hop count => drop");
        return;
    }

    if (p->sender != p->prev_sender && p->prev_sender == gstate.own_id) {
        // we are the previous sender => that neighbor relies on our broadcasts
        ifstate->recv_own_broadcast_time = gstate.time_now;
    }

    Neighbor *old_parent = get_parent();

{
    // check sequence number for the current root
    uint32_t cur_root_id;
    uint16_t cur_root_seq_num;

    if (old_parent) {
        assert(old_parent->root_set);
        cur_root_id = old_parent->root.root_id;
        cur_root_seq_num = old_parent->root.root_seq_num;
    } else {
        // we are root
        cur_root_id = g_root.root_id;
        cur_root_seq_num = g_root.root_seq_num;
    }

    if (cur_root_id == p->root_id && !is_newer_seqnum(cur_root_seq_num, p->root_seq_num)) {
        return;
    }
}

    // check sequence number for the neighbor
    if (neighbor->root_set && neighbor->root.root_id == p->root_id
            && !is_newer_seqnum(neighbor->root.root_seq_num, p->root_seq_num)) {
        // duplicate packet
        log_debug("handle_ROOT_CREATE: duplicate packet from %s root_id: 0x%08x, seq_num: %d",
            str_addr(&neighbor->address), p->root_id, p->root_seq_num);
        return;
    }

    if (neighbor->root.root_id != p->root_id || !neighbor->root_set) {
        neighbor->root.time_created = gstate.own_id;
    }

    neighbor->root_set = true;
    neighbor->root.root_id = p->root_id;
    neighbor->root.hop_count = p->hop_count;
    neighbor->root.root_seq_num = p->root_seq_num;
    neighbor->root.root_recv_time = gstate.time_now;
    neighbor->root.parent_id = p->sender; // for debugging?

    Neighbor* new_parent = get_parent();

    if (old_parent != new_parent) {
        log_debug("handle_ROOT_CREATE: parent changed");
    }

    // only forward root packet from parent
    if (new_parent && new_parent == neighbor) {
        log_debug("handle_ROOT_CREATE: got packet from %s root_id: 0x%08x, root_seq_num: %d => forward",
            str_addr(&neighbor->address), p->root_id, (int) p->root_seq_num);

        // neighbor is parent in tree => forward
        neighbor->root.root_send_time = gstate.time_now;

        p->hop_count += 1;
        p->prev_sender = p->sender;
        p->sender = gstate.own_id;
        send_bcast_wrapper("handle_ROOT_CREATE", p, get_size_ROOT_CREATE(p));
    } else {
        log_trace("handle_ROOT_CREATE: got packet from %s root_id: 0x%08x, root_seq_num: %d => drop",
            str_addr(&neighbor->address), p->root_id, (int) p->root_seq_num);
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    Node *node = next_node_by_id(dst_id);
    Hop *hop = next_hop_by_node(node);

    if (node && hop && (gstate.time_now - hop->time_updated) <= (HOP_TIMEOUT_MS / 2)) {
        // packet pointer points into an allocated chunk to fit some added header
        DATA *p = (DATA*) (packet - offsetof(DATA, payload_data));

        p->type = TYPE_DATA;
        p->hop_count = 1;
        p->seq_num = g_sequence_number++;
        p->src_id = gstate.own_id;
        p->dst_id = dst_id;
        p->payload_length = packet_length;

        log_debug("tun_handler() send DATA packet (0x%08x => 0x%08x, hop_count: %d, seq_num: %d) to %s, %d hops away",
            p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num, str_addr(&hop->next_hop_addr), (int) hop->hop_count);

        send_ucast_wrapper(&hop->next_hop_addr, p, get_size_DATA(p));
    } else {
        packet_cache_add(dst_id, packet, packet_length);

        RREQ p = {
            .type = TYPE_RREQ,
            .hop_count = 1,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = dst_id
        };

        send_RREQ("tun_handler() send RREQ", NULL, &p);
    }
}

// called once for added/removed interfaces
static bool interface_handler(uint32_t ifindex, const char *ifname, bool added)
{
    //log_info("interface_handler: %s ifname %s", added ? "add" : "remove", ifname);

    if (added) {
        IFState *ifstate = ifstate_get(ifindex);

        PING p = {
            .type = TYPE_PING,
            .seq_num = g_sequence_number++,
        };

        log_debug("interface_handler() ping neighbor");
        send_bcast_l2_wrapper_interface("PING", ifstate, &p, get_size_PING(&p));
    } else {
        ifstate_remove(ifindex);
    }

    return true;
}

static void peers_add(const char *hostname)
{
    Peer *peer = g_peers;
    Peer *prev = NULL;

    if (hostname == NULL || strlen(hostname) >= 64) {
        return;
    }

    // check for duplicate
    while (peer) {
        if (0 == strcmp(hostname, &peer->hostname[0])) {
            return;
        }
        prev = peer;
        peer = peer->next;
    }

    peer = (Peer*) calloc(1, sizeof(Peer));
    memcpy(&peer->hostname[0], hostname, strlen(hostname));

    if (g_peers == NULL) {
        g_peers = peer;
    } else {
        prev->next = peer;
    }
}

static void peers_del(const char *hostname)
{
    Peer *peer = g_peers;
    Peer *prev = NULL;

    // check for duplicate
    while (peer) {
        if (0 == strcmp(hostname, &peer->hostname[0])) {
            if (prev) {
                prev->next = peer->next;
            } else {
                g_peers = peer->next;
            }

            free(peer);
            return;
        }
        prev = peer;
        peer = peer->next;
    }
}

static void ext_handler(const Address *src, uint8_t flags, uint8_t *packet, size_t packet_length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;
    //log_debug("ext_handler: is_broadcast: %s, is_destination: %s", str_bool(is_broadcast), str_bool(is_destination));

    uint32_t ifindex = address_ifindex(src); // is src correct? shouldn't it be dst?
    IFState *ifstate = ifstate_get(ifindex);

    // also make sure we know of any neighbor that runs this protocol
    Neighbor *neighbor = neighbors_get(src);
    if (is_destination || is_broadcast) {
        // packet is for us or (unicast or broadcast)
        neighbor->pinged = 0;
    }
        //neighbor->packets_received_count += 1;
        //neighbor->packets_received_time = gstate.time_now;
        neighbor->time_updated = gstate.time_now;
    //}

    //log_debug("node_count: %d", (int) HASH_COUNT(g_nodes));

    // count incoming traffic
    record_traffic_by_addr(src, 0, packet_length);

    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(src, flags, (DATA*) packet, packet_length);
        break;
    case TYPE_RREQ:
        handle_RREQ(neighbor, src, flags, (RREQ*) packet, packet_length);
        break;
    case TYPE_RREP:
        handle_RREP(src, flags, (RREP*) packet, packet_length);
        break;
    case TYPE_RREP2:
        handle_RREP2(src, flags, (RREP2*) packet, packet_length);
        break;
    case TYPE_RERR:
        handle_RERR(src, flags, (RERR*) packet, packet_length);
        break;
    case TYPE_PING:
        handle_PING(neighbor, src, flags, (PING*) packet, packet_length);
        break;
    case TYPE_PONG:
        handle_PONG(neighbor, src, flags, (PONG*) packet, packet_length);
        break;
    case TYPE_ROOT_CREATE:
        handle_ROOT_CREATE(ifstate, neighbor, src, flags, (ROOT_CREATE*) packet, packet_length);
        break;
    case TYPE_ROOT_STORE:
        handle_ROOT_STORE(ifstate, neighbor, src, flags, (ROOT_STORE*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x of size %zu from %s", packet[0], packet_length, str_addr(src));
        break;
    }
}

static void ext_handler_l3(const Address *src, uint8_t *packet, size_t packet_length)
{
    if (address_is_broadcast(src)) {
        // packet from broadcast source address => invalid
        return;
    }

    uint8_t flags = FLAG_IS_UNICAST | FLAG_IS_DESTINATION;
    ext_handler(src, flags, packet, packet_length);
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    if (address_equal(rcv, src)) {
        // own unicast packet => ignore
        return;
    }

    if (address_is_broadcast(src)) {
        // packet from broadcast source address => invalid
        return;
    }

    //log_debug("rcv: %s, src: %s, dst: %s", str_addr(rcv), str_addr(src), str_addr(dst));

    uint8_t flags = 0;
    if (address_is_broadcast(dst)) {
        flags |= FLAG_IS_BROADCAST;
        flags |= FLAG_IS_DESTINATION;
    } else {
        flags |= FLAG_IS_UNICAST;
        if (address_equal(dst, rcv)) {
            flags |= FLAG_IS_DESTINATION;
        }
    }

    ext_handler(src, flags, packet, packet_length);
}

static bool console_handler(FILE* fp, int argc, const char *argv[])
{
   if (match(argv, "h")) {
        fprintf(fp, "r                       print routing table\n");
    } else if (match(argv, "i")) {
        fprintf(fp, "node_count:      %d\n", (int) HASH_COUNT(g_nodes));
        fprintf(fp, "neighbor_count:  %d\n", (int) HASH_COUNT(g_neighbors));
        fprintf(fp, "next_root_store: %s until\n", str_until(next_ROOT_STORE_periodic()));

        fprintf(fp, "ifstates:\n");
        IFState *ifstate;
        IFState *tmp;
        HASH_ITER(hh, g_ifstates, ifstate, tmp) {
            fprintf(fp, "  recv_own_broadcast_time:     %s ago\n", str_since(ifstate->recv_own_broadcast_time));
            fprintf(fp, "  recv_foreign_broadcast_time: %s ago\n", str_since(ifstate->recv_foreign_broadcast_time));
            fprintf(fp, "  send_broadcast_time:         %s ago\n", str_since(ifstate->send_broadcast_time));
        }

        interfaces_debug(fp);

        Neighbor *parent = get_parent();

        if (parent) {
            fprintf(fp, "tree_root:\n");
            fprintf(fp, "  root_id:        0x%08x\n", parent->root.root_id);
            fprintf(fp, "  hop_count:      %d\n", (int) parent->root.hop_count);
            fprintf(fp, "  seq_num:        %d\n", (int) parent->root.root_seq_num);
            fprintf(fp, "  parent_id:      0x%08x\n", parent->root.parent_id);
        } else {
            fprintf(fp, "tree_root:\n");
            fprintf(fp, "  root_id:        0x%08x\n", g_root.root_id);
            fprintf(fp, "  hop_count:      %d\n", (int) 0);
            fprintf(fp, "  seq_num:        %d\n", (int) g_root.root_seq_num);
            //fprintf(fp, "  parent_id: 0x%08x\n", g_root.parent_id);
        }
    } else if (match(argv, "r")) {
        Node *node;
        Node *ntmp;
        Hop *hop;
        Hop *htmp;
        uint32_t node_count = 0;
        uint32_t neighbor_count = 0;

        HASH_ITER(hh, g_nodes, node, ntmp) {
            node_count += 1;
            fprintf(fp, " 0x%08x:\n", node->id);
            bool is_neighbor = false;
            HASH_ITER(hh, node->hops, hop, htmp) {
                if (hop->hop_count == 1) {
                    is_neighbor = true;
                }
                //Node *neighbor = find_neighbor_node_by_address(&hop->next_hop_addr);
                fprintf(fp, "  next-hop-address: %s, hops: %d, last-updated: %s ago\n",
                    str_addr(&hop->next_hop_addr),
                    (int) hop->hop_count,
                    //(neighbor ? neighbor->id : 0),
                    str_since(hop->time_updated)
                );
            }

            if (is_neighbor) {
                neighbor_count += 1;
            }
        }
        fprintf(fp, "%d nodes, %d neighbors\n", (int) node_count, (int) neighbor_count);
    } else if (match(argv, "n")) {
        Neighbor *neighbor;
        Neighbor *tmp;
        uint32_t count = 0;

        HASH_ITER(hh, g_neighbors, neighbor, tmp) {
            fprintf(fp, "address: %s\n",
                str_addr(&neighbor->address)
            );
            if (neighbor->ranges_set) {
                fprintf(fp,     "  ranges_span:    %"PRIu64"\n", ranges_span(&neighbor->ranges));
                fprintf(fp,     "  ranges_count:   %d\n", (int) neighbor->ranges.data_count);
                fprintf(fp,     "  ranges_data:    %s\n", ranges_str(&neighbor->ranges));
            }
            if (neighbor->root_set) {
                fprintf(fp, "  root_id:        0x%08x\n", neighbor->root.root_id);
                fprintf(fp, "  root_hop_count: %d\n", (int) neighbor->root.hop_count);
                fprintf(fp, "  root_parent_id: 0x%08x\n", neighbor->root.parent_id);
                fprintf(fp, "  time_created:   %s\n", str_since(neighbor->root.time_created));
            }
            count += 1;
        }
        fprintf(fp, "%d neighbors\n", (int) count);
    } else if (match(argv, "peers")) {
        Peer *peer = g_peers;
        uint32_t count = 0;
        while (peer) {
            fprintf(fp, "peer: %s\n", peer->hostname);
            peer = peer->next;
            count += 1;
        }
        fprintf(fp, "%d peers\n", (int) count);
    } else if (argc == 2 && 0 == strcmp(argv[0], "peer-add")) {
        peers_add(argv[1]);
        fprintf(fp, "done\n");
    } else if (argc == 2 && 0 == strcmp(argv[0], "peer-add")) {
        peers_del(argv[1]);
        fprintf(fp, "done\n");
    } else if (match(argv, "json")) {
        Neighbor *parent = get_parent();
        fprintf(fp, "{\n");

        fprintf(fp, "\"own_id\": \"0x%08x\",\n", gstate.own_id);
        fprintf(fp, "\"node_count\": %d,\n", (int) HASH_COUNT(g_nodes));

        if (parent) {
            fprintf(fp, "\"root_id\": \"0x%08x\",\n", parent->root.root_id);
            fprintf(fp, "\"root_address\": \"%s\",\n", str_addr(&parent->address));
            fprintf(fp, "\"root_hop_count\": %d,\n", (int) parent->root.hop_count);
            fprintf(fp, "\"root_parent_id\": \"0x%08x\",\n", parent->root.parent_id);
        } else {
            fprintf(fp, "\"root_id\": \"0x%08x\",\n", g_root.root_id);
            fprintf(fp, "\"root_address\": \"%s\",\n", "");
            fprintf(fp, "\"root_hop_count\": %d,\n", (int) 0);
            fprintf(fp, "\"root_parent_id\": \"0x%08x\",\n", g_root.root_id);
        }

        fprintf(fp, "\"next_root_store\": \"%s until\",\n", str_until(next_ROOT_STORE_periodic()));
        //root->time_root_store_send

        //fprintf(fp, "\"time_updated\": \"%s\",", str_until(root->time_updated));

        {
            fprintf(fp, "\"neighbors\": [");
            Neighbor *neighbor;
            Neighbor *tmp;
            int neighbor_count = 0;
            HASH_ITER(hh, g_neighbors, neighbor, tmp) {
                if (neighbor_count > 0) {
                    fprintf(fp, ", ");
                }
                neighbor_count += 1;

                fprintf(fp, "{");
                fprintf(fp, "\"is_child\": \"%s\",", str_bool(neighbor_is_child(neighbor)));
                if (neighbor->ranges_set) {
                    fprintf(fp, "\"ranges_span\": %"PRIu64",", ranges_span(&neighbor->ranges));
                    fprintf(fp, "\"ranges_count\": %d,", (int) neighbor->ranges.data_count);
                    fprintf(fp, "\"ranges_data\": \"%s\",", ranges_str(&neighbor->ranges));
                }
                if (neighbor->root_set) {
                    fprintf(fp, "\"root_id\": \"0x%08x\",", neighbor->root.root_id);
                    fprintf(fp, "\"root_hop_count\": %d,", (int) neighbor->root.hop_count);
                    fprintf(fp, "\"root_parent_id\": \"0x%08x\",", neighbor->root.parent_id);
                    fprintf(fp, "\"time_created\": \"%s\",", str_since(neighbor->root.time_created));
                    fprintf(fp, "\"is_parent\": \"%s\",", str_bool(neighbor == parent));
                }
                fprintf(fp, "\"address\": \"%s\"", str_addr(&neighbor->address));
                fprintf(fp, "}");
            }
            fprintf(fp, "],\n");
        }

        fprintf(fp, "\"interfaces\": ");
        interfaces_debug_json(fp);
        fprintf(fp, ",\n");

        {
            fprintf(fp, "\"ifstates\": [");
            IFState *ifstate;
            IFState *tmp;
            uint32_t ifstate_count = 0;
            HASH_ITER(hh, g_ifstates, ifstate, tmp) {
                if (ifstate_count > 0) {
                    fprintf(fp, ", ");
                }
                ifstate_count += 1;

                fprintf(fp, "{\"ifname\": \"%s\", \"flood_needed\": \"%s\"}",
                    str_ifindex(ifstate->ifindex), str_bool(get_is_needed(ifstate)));
            }
            fprintf(fp, "],\n");
        }

        {
            fprintf(fp, "\"packet_trace\": ");
            packet_trace_json(fp);
            fprintf(fp, "\n");
        }

        fprintf(fp, "}\n");
    } else {
        return false;
    }

    return true;
}

static void init_handler()
{
    if (!ranges_sanity_test()) {
        log_error("Ranges sanity test failed!");
        exit(1);
    }

    g_root.root_id = gstate.own_id;

    //roots_add(gstate.own_id);

    net_add_handler(-1, &periodic_handler);
    packet_cache_init(20);
}

static void exit_handler()
{
    // nothing to do yet
}

static bool config_handler(const char *option, const char *value)
{
    if (strcmp(option, "peer") && value != NULL) {
        peers_add(value);
        return true;
    }

    return false;
}

void root_storage_0_register()
{
    static const Protocol p = {
        .name = "root-storage-0",
        .init_handler = &init_handler,
        .exit_handler = &exit_handler,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .ext_handler_l3 = &ext_handler_l3,
        .interface_handler = &interface_handler,
        .config_handler = &config_handler,
        .console_handler = &console_handler,
    };

    protocols_register(&p);
}
