#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <assert.h>

#include "../ext/bloom.h"
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

    TYPE_ROOT_CREATE,
    TYPE_ROOT_STORE,
    //TYPE_BLOOM,

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

#define DHT_PORT 6881
//#define DEFAULT_PEER_PORT 25872
#define HOP_TIMEOUT_MIN_SECONDS 30
#define HOP_TIMEOUT_MAX_SECONDS (60 * 60 * 24)
#define NODE_MIN_AGE_SECONDS 30
#define NODE_MAX_AGE_SECONDS (60 * 60 * 24)
#define TRAFFIC_DURATION_SECONDS 8
#define UNKNOWN_SEQUENCE_NUMBER UINT32_MAX
//#define UNKNOWN_HOP_COUNT UINT16_MAX
//#define INITIAL_ROOT_STORE_SEND_INTERVAL_MS 100

#define BLOOM_M 8
#define BLOOM_K 2

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
    uint64_t time_dht_last_announcement;
    uint32_t seq_num; // sequence numbers are 16bit!, UINT32_MAX => not set
    Hop *hops;
    UT_hash_handle hh;
} Node;

typedef struct {
    uint64_t updated_time;
    uint32_t out_bytes[TRAFFIC_DURATION_SECONDS];
    uint32_t in_bytes[TRAFFIC_DURATION_SECONDS];
} Traffic;

typedef struct {
    bool root_set;
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

/*
typedef struct {
    uint8_t bloom_data[BLOOM_M];
    uint64_t bloom_received;
    uint64_t bloom_send; // only set for parent
    uint64_t bloom_changed;
} Bloom;
*/

enum RouteType {
    RouteTypeId,
    RouteTypeNet,
    RouteTypeBloom,
};

/*
typedef struct __attribute__((__packed__)) {
    uint8_t min_hop_count;
    uint8_t max_hop_count;
    uint16_t id_prefix;
} ROOT_STORE_NET;
*/

typedef struct {
    uint8_t hop_count;
    uint32_t src_id;
} RouteById;

typedef struct {
    enum RouteType type;
    bool was_forwarded;
    uint64_t received_time; // not used
    union {
        RouteById route_by_id;
    };
} RouteHint;

typedef struct {
    size_t data_capacity;
    size_t data_size;
    RouteHint *data;
} Storage;

// for detecting connection breaks
typedef struct {
    Address address;

    // needed?
    uint64_t packets_send_count;
    uint64_t packets_send_time;

    uint8_t pinged;
    uint64_t time_created;
    uint64_t last_updated;

    Root root;
    //Bloom bloom;
    Storage storage;

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
    uint8_t req_age; // age of routing information in seconds
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
    uint8_t hop_count;
    uint32_t src_id;
} ROOT_STORE_ID;

#define MAX_ROOT_STORE_ENTRIES 200

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    //uint16_t seq_num;
    uint8_t entry_count; // also acts as hop count
    ROOT_STORE_ID entries[MAX_ROOT_STORE_ENTRIES];
} ROOT_STORE;

// synchronize to we minimize send time
typedef struct __attribute__((__packed__)) {
    uint8_t type;
//    uint16_t seq_num;
    uint8_t hop_count;
    uint8_t bloom_data[BLOOM_M];
} BLOOM;

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
static bool g_enable_dht = false;
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

static void reset_root(Root *root)
{
    memset(root, 0, sizeof(Root));
    root->root_seq_num = 0; // only use when we are root
    root->root_id = gstate.own_id;
    root->parent_id = gstate.own_id;
    root->time_created = 0;
    root->store_send_time = 0;
    root->store_send_counter = 0;
}

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

#ifdef DHT 
const char *g_dht_peers[] = {"bttracker.debian.org:6881"};

static void dht_periodic()
{
    static uint64_t last_announcement = 0;
    static uint64_t last_check = 0;
    static uint8_t info_hash[SHA1_BIN_LENGTH] = {20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

    if (last_check == 0 || (gstate.time_now - last_check) > 10000) {
        last_check = gstate.time_now;

        if (dht_count_nodes() > 10) {
            if (last_announcement == 0 || (gstate.time_now - last_announcement) > (DHT_ANNOUNCEMENT_INTERVAL * 1000 - 1000)) {
                dht_announce(info_hash, DHT_PORT);
                //dht_lookup(info_hash);
                last_announcement = gstate.time_now;
            }
        } else {
            last_announcement = 0;

            // choose random peer
            size_t peer_count = ARRAY_SIZE(g_dht_peers);
            const char *peer = g_dht_peers[((size_t) rand()) % peer_count];

            struct sockaddr_storage address_storage;
            struct sockaddr* address = (struct sockaddr*) &address_storage;

            log_debug("DHT: Ping %s", peer);

            bool resolved = false;
            int af = gstate.af;
            if (af == AF_UNSPEC || af == AF_INET6) {
                if (addr_parse(address, peer, STR(DHT_PORT), AF_INET6)) {
                    dht_ping(address);
                    resolved = true;
                }
            }

            if (af == AF_UNSPEC || af == AF_INET) {
                if (addr_parse(address, peer, STR(DHT_PORT), AF_INET)) {
                    dht_ping(address);
                    resolved = true;
                }
            }

            if (!resolved) {
                log_warning("DHT: Failed to resolve %s", peer);
            }
        }
    }

    /*
    // announce all the ids we know on the DHT
    uint8_t info_hash[SHA1_BIN_LENGTH] = {0};
    Node *node;
    Node *ntmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        uint64_t last = node->time_dht_last_announcement;
        if (last == 0 || (gstate.time_now - last) > (DHT_ANNOUNCEMENT_INTERVAL * 1000 - 5000)) {
            node->time_dht_last_announcement = gstate.time_now;
            memset(info_hash, 0, sizeof(info_hash));
            memcpy(info_hash, &node->id, sizeof(uint32_t));
            log_debug("dht_announce: announce 0x%08x on the DHT", node->id);
            dht_announce(info_hash, DHT_PORT);
        }
    }*/
}
#endif

static void neighbor_free(Neighbor *neighbor)
{
    free(neighbor->storage.data);
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
    // TODO: expect presence detection on root
    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        if (
            //((neighbor->time_last_recv - neighbor->time_created) <= (gstate.time_now - neighbor->time_last_recv))
            //||
            //(neighbor->time_send_DATA != 0) // is set
            (neighbor->last_updated < gstate.time_now) && (gstate.time_now - neighbor->last_updated) > 8000 // is set
            //&& ((neighbor->time_send_DATA + 1000) < gstate.time_now) // data packet >1s ago
            //&& (neighbor->time_send_DATA > (neighbor->packets_received_time + 2 * gstate.time_resolution))) // no response for last data packet
        )
        {
            //log_debug("time_send_DATA: %d, packets_received_time: %d", (int) neighbor->time_send_DATA, (int) neighbor->packets_received_time);

            // we have send a DATA packet and have not seen a DATA back or PONG back => send PING
            if (neighbor->pinged > 2) { //} MIN(2, neighbor->packets_received_count)) {
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

bool is_better_storage_item(const RouteById *cur, const RouteById *new)
{
    return new->hop_count < cur->hop_count;
}

static Neighbor *get_next_hop(uint32_t dst_id)
{
    Neighbor *found_ne = NULL;
    const RouteHint *found_si = NULL;

    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        const Storage *s = &neighbor->storage;
        for (size_t i = 0; i < s->data_size; ++i) {
            const RouteHint *r = &s->data[i];
            switch (r->type) {
                case RouteTypeId:
                    if (r->route_by_id.src_id == dst_id) {
                        if (found_si == NULL || is_better_storage_item(&found_si->route_by_id, &r->route_by_id)) {
                            found_ne = neighbor;
                            found_si = r;
                        }
                    }
                    break;
            }
        }
    }

    return found_ne;
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

static Neighbor *get_parent()
{
    Neighbor *cur = NULL;
    Neighbor *new;
    Neighbor *tmp;

    //log_debug("get_parent()");

    HASH_ITER(hh, g_neighbors, new, tmp) {
        if (!new->root.root_set) {
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
        if (cur->root.root_set) {
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
        uint64_t first_heard_node_age = gstate.time_now - node->time_created;
        uint64_t last_heard_node_age = gstate.time_now - node->time_updated;

        /*
        * - at least NODE_MIN_AGE_SECONDS old
        * - last seen in futher in past as the the age of the node
        */
        //if (first_heard_node_age > (NODE_MIN_AGE_SECONDS * 1000U) && last_heard_node_age > (first_heard_node_age + 1000U)) {
        if (last_heard_node_age > (NODE_MAX_AGE_SECONDS * 1000U)) {
            // remove all hops
            HASH_ITER(hh, node->hops, hop, htmp) {
                HASH_DEL(node->hops, hop);
                free(hop);
            }

            log_debug("nodes_periodic() remove node 0x%08x (node timed out)", node->id);
        } else {
            // remove worst hop if there more than one
            // TODO: only remove old entries (twi), always leave at least one hop here
            //uint64_t oldest_updated = 0;
            //uint64_t latest_updated = UINT64_MAX;
            //Hop *oldest_hop = NULL;
            if (!we_are_root()) {
                HASH_ITER(hh, node->hops, hop, htmp) {
                    uint64_t last_heard_hop_age = gstate.time_now - hop->time_updated;
                    if (hop->time_updated < node->time_updated || last_heard_hop_age > (8000)) {
                        HASH_DEL(node->hops, hop);
                        free(hop);
                    }
                }
            }
/*
                uint64_t span1 = hop->time_updated - hop->time_created;
                uint64_t span2 = gstate.time_now - hop->time_updated;

                if (((span2 / 1000) > HOP_TIMEOUT_MIN_SECONDS) && (((span2 / 1000) > HOP_TIMEOUT_MAX_SECONDS) || (span1 < span2))) {
                    log_debug("nodes_periodic() timeout hop %s for node 0x%08x (span1: %s, span2: %s)",
                        str_addr(&hop->next_hop_addr), node->id, str_time(span1), str_time(span2));
                    HASH_DEL(node->hops, hop);
                    free(hop);
                }
*/

            if (node->hops == NULL) {
                log_debug("nodes_periodic() remove node 0x%08x (all hops timed out)", node->id);
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

    if (new->time_updated > cur->time_updated) {
        return true;
    }
/*
    // choose
    if (new->time_updated > (cur->time_updated + 4)) {
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

static size_t get_size_ROOT_STORE(const ROOT_STORE *p)
{
    return (offsetof(ROOT_STORE, entries) + p->entry_count * sizeof(ROOT_STORE_ID));
}

static size_t get_size_BLOOM(const BLOOM *p)
{
    return sizeof(BLOOM);
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

static uint32_t get_neighbor_id(const Neighbor *neighbor)
{
    Node *node = find_neighbor_node_by_address(&neighbor->address);
    return node ? node->id : 0;
}

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
/*
    uint64_t interval = root->time_root_store_send_interval;
    interval -= (interval / 10); // 10% earlier
    return root->time_root_store_send + interval;
    */
}

#if 0
static void send_BLOOM_periodic()
{
    static uint64_t last = 0;

/*
    neighbor->bloom_received
    neighbor->bloom_changed

    1. send a new bloom packet when any of the neighbors filter changes
*/

    if (last == 0 || (last - gstate.time_now) > 1000) {
        last = gstate.time_now;

        Neighbor *parent = get_parent();

        if (parent && !we_are_root()) {
            BLOOM p = {
                .type = TYPE_BLOOM
            };

            bloom_init(&p.bloom_data, gstate.own_id, BLOOM_M, BLOOM_K);

            Neighbor *neighbor;
            Neighbor *tmp;
            HASH_ITER(hh, g_neighbors, neighbor, tmp) {
                bloom_merge(&p.bloom_data, &neighbor->bloom.bloom_data, BLOOM_M);
            }

            log_debug("send_BLOOM_periodic: %s to %s",
                str_bloom(&p.bloom_data, BLOOM_M), str_addr(&parent->address));

            send_ucast_wrapper(&parent->address, &p, get_size_BLOOM(&p));
            parent->bloom.bloom_send = gstate.time_now;
        }
    }
}
#endif

static const char *str_storage(const RouteHint *es, uint32_t count, bool was_forwarded)
{
    static char strdurationbuf[4][256];
    static size_t strdurationbuf_i = 0;
    char *buf = strdurationbuf[++strdurationbuf_i % 4];

    buf[0] = 0;
    for (size_t i = 0, written = 0; i < count; ++i) {
        const RouteHint *r = &es[i];
        switch (r->type) {
        case RouteTypeId:
        //if (es[i].was_forwarded == was_forwarded) { // filter
            const char *fmt = (written > 0) ? ", 0x%x/%d%c" : "0x%x/%d%c";
            int rc = snprintf(&buf[written], sizeof(strdurationbuf[0]) - written, fmt,
                r->route_by_id.src_id, (int) r->route_by_id.hop_count, (r->was_forwarded ? '!' : '?'));
            if (rc > 0) {
                written += rc;
            } else {
                i = count; // break
            }
        }
        //}
    }

    return buf;
}

static const char *str_entries(const ROOT_STORE_ID *es, uint32_t count)
{
    static char strdurationbuf[4][256];
    static size_t strdurationbuf_i = 0;
    char *buf = strdurationbuf[++strdurationbuf_i % 4];

    buf[0] = 0;
    for (size_t i = 0, written = 0; i < count; ++i) {
        const char *fmt = (written > 0) ? ", 0x%x/%d" : "0x%x/%d";
        int rc = snprintf(&buf[written], sizeof(strdurationbuf[0]) - written, fmt, es[i].src_id, (int) es[i].hop_count);
        if (rc > 0) {
            written += rc;
        } else {
            break;
        }
    }

    return buf;
}

// add item, ignore duplciates
static void root_store_add(ROOT_STORE *rs, uint32_t src_id, uint8_t hop_count)
{
    assert(rs->entry_count < MAX_ROOT_STORE_ENTRIES);

    for (size_t i = 0; i < rs->entry_count; ++i) {
        ROOT_STORE_ID *e = &rs->entries[i];
        if (e->src_id == src_id) {
            if (hop_count < e->hop_count) {
                e->hop_count = hop_count;
            }
            return;
        }
    }

    rs->entries[rs->entry_count] = (ROOT_STORE_ID) {
        .src_id = src_id,
        .hop_count = hop_count,
    };
    rs->entry_count += 1;
}

static void print_storage()
{
    Neighbor *parent = get_parent();
    Neighbor *neighbor;
    Neighbor *tmp;

    int x = 0;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        // sort storage by hop count?
        log_debug("[%d, %p] print_storage: %s [%s] (is_parent: %s, data_size: %d)",
            x++, neighbor,
            str_addr(&neighbor->address),
            str_storage(&neighbor->storage.data[0], neighbor->storage.data_size, false),
            str_bool(parent == neighbor),
            (int) neighbor->storage.data_size);
    }
}

#if 0
find biggest common prefix

find most compact bloom

#endif

static void send_ROOT_STORE_periodic()
{
    Neighbor *parent = get_parent();

    if (parent) {
        // root node has no parent!
        // merge all storage items and try to fit them in on packet

        //if (next_ROOT_STORE_periodic() <= gstate.time_now) {
        if (parent->root.store_send_time == 0 || (parent->root.store_send_time + 1000) < gstate.time_now) {
            parent->root.store_send_time = gstate.time_now;

            ROOT_STORE p = {
                .type = TYPE_ROOT_STORE,
                //.seq_num = g_sequence_number++,
                .entry_count = 1,
                .entries = {(ROOT_STORE_ID) {
                    .hop_count = 1,
                    .src_id = gstate.own_id,
                }},
            };

            Neighbor *neighbor;
            Neighbor *tmp;

            log_debug("send_ROOT_STORE_periodic: storage");
            print_storage();

            // pick nearest neighbors
            size_t index = 0;
            bool done = true;
            do {
                done = true;
                HASH_ITER(hh, g_neighbors, neighbor, tmp) {
                    if (neighbor != parent
                            && index < neighbor->storage.data_size
                            && p.entry_count < MAX_ROOT_STORE_ENTRIES) {
                        RouteHint *si = &neighbor->storage.data[index];
                        switch (si->type) {
                        case RouteTypeId:
                            //log_debug("consider 0x%x/%d%c", si->src_id, si->hop_count, si->was_forwarded ? '!' : '?');
                            if (!si->was_forwarded && si->route_by_id.hop_count < UINT8_MAX) {
                                si->was_forwarded = true;
                                root_store_add(&p, si->route_by_id.src_id, si->route_by_id.hop_count + 1);
                            }
                        }
                        done = false;
                    }
                }
                index += 1;
            } while (!done);

            // clear all storages (parent too)
            //HASH_ITER(hh, g_neighbors, neighbor, tmp) {
            //    neighbor->storage.data_size = 0;
            //}

            //log_debug("send_ROOT_STORE_periodic: after");
            //print_storage();

            log_debug("send_ROOT_STORE_periodic: entries: [%s] to parent %s",
                str_entries(&p.entries[0], p.entry_count),
                str_addr(&parent->address));

            send_ucast_wrapper(&parent->address, &p, get_size_ROOT_STORE(&p));

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
    //send_BLOOM_periodic();
    peers_periodic();
    if (g_enable_dht) {
        dht_periodic();
    }
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

    log_debug("RREP2: got packet 0x%08x => 0x%08x / hop_count: %d, seq_num: %d,"
              " req_id: 0x%08x, req_seq_num: %d, req_hops: %d, req_age: %d)",
        p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num,
        p->req_id, (int) p->req_seq_num, (int) p->req_hops, (int) p->req_age);

    // add information about originator node
    nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0);
    // add information from originator node about requested node
    nodes_update(p->req_id, src, p->hop_count + p->req_hops, p->req_seq_num, p->req_age);

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->req_id);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RREP2: send to %s => forward", str_addr(&hop->next_hop_addr));
            p->hop_count += 1;
            send_ucast_wrapper(&hop->next_hop_addr, p, get_size_RREP2(p));
        } else {
            log_debug("RREP2: no next hop found => drop");
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

    log_debug("DATA: got packet 0x%08x => 0x%08x / hop_count: %d", p->src_id, p->dst_id, (int) p->hop_count);

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: 0x%08x => 0x%08x, hop_count: %d, destination reached => accept",
            p->src_id, p->dst_id, (int) p->hop_count);
        //decrease_ip_ttl(payload, p->payload_length);
        tun_write(payload, p->payload_length);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("DATA: 0x%08x => 0x%08x, send to next hop %s %d hops away => forward",
                p->src_id, p->dst_id, str_addr(&hop->next_hop_addr), (int) hop->hop_count);
            // forward
            p->hop_count += 1;
            send_ucast_wrapper(&hop->next_hop_addr, p, get_size_DATA(p));
        } else {
            log_debug("DATA: no next hop found => drop and send RERR");

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

    log_debug("RREP: got packet 0x%08x => 0x%08x / hop_count: %d, seq_num: %d",
        p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->src_id);
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RREP: send to %s => forward", str_addr(&hop->next_hop_addr));
            p->hop_count += 1;
            send_ucast_wrapper(&hop->next_hop_addr, p, sizeof(RREP));
        } else {
            log_debug("RREP: no next hop found => drop");
        }
    }
}

/*
typedef struct {
    uint64_t time_created;
    RREQ rreq;
    UT_hash_handle hh;

} DHTPendingLookup;

static *dht_lookups = NULL;

void DHTPendingLookup_add(const RREQ *p)
{
    DHTPendingLookup *e = NULL;
    HASH_FIND(hh, dht_lookups, id, sizeof(uint32_t), e);

    if (e) {
        // e->
    } else {
        e = (DHTPendingLookup*) malloc(sizeof(DHTPendingLookup));
        e->time_created = gstate.time_now;
        memcpy(&e->rreq, p, sizeof(RREQ));
        HASH_ADD(hh, dht_lookups, id, sizeof(uint32_t), e);
    }
}

// TODO: move to dht_periodic
void dht_lookups_periodic()
{
    DHTPendingLookup *tmp;
    DHTPendingLookup *entry;
    HASH_ITER(hh, dht_lookups, entry, tmp) {
        if ((gstate->time_now - entry->time_created) > 16000) {
            // remove after 16 seconds
            HASH_DEL(dht_lookups, entry);
            free(entry);
        }
    }
}
*/

static void send_RREQ(const char *context, const Neighbor *neighbor, const RREQ *p)
{
    // lookup route hints
    Neighbor *next = get_next_hop(p->dst_id);
    if (next) {
        /*
        if (g_enable_dht) {
            log_debug("RREQ: lookup on DHT => lookup");
            uint8_t info_hash[SHA1_BIN_LENGTH] = {0};
            memcpy(info_hash, &p->dst_id, sizeof(uint32_t));
            dht_lookup(info_hash);
            // TODO: store from the request came from
        } else {
        */
        if (next != neighbor) {
            log_debug("%s: 0x%08x => 0x%08x, found routing hint, send to %s => forward",
                context, p->src_id, p->dst_id, str_addr(&next->address));
            send_ucast_wrapper(&next->address, p, get_size_RREQ(p));
        } else {
            log_warning("%s: 0x%08x => 0x%08x, do not route back to sender => ignore",
                context, p->src_id, p->dst_id);
        }
    } else {
        // route towards too
        Neighbor *parent = get_parent();
        if (parent) {
            if (parent != neighbor) {
                log_debug("%s: 0x%08x => 0x%08x, send to parent %s => forward",
                    context, p->src_id, p->dst_id, str_addr(&parent->address));
                send_ucast_wrapper(&parent->address, p, get_size_RREQ(p));
            } else {
                log_warning("%s: 0x%08x => 0x%08x, do not route back to sender => ignore",
                    context, p->src_id, p->dst_id);
            }
        } else {
            log_warning("%s: 0x%08x => 0x%08x, no parent - we are root  => ignore",
                context, p->src_id, p->dst_id);
        }
    }
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
        log_debug("RREQ: invalid packet size (%u != %u) => drop", length, get_size_RREQ(p));
        return;
    }

    if (p->hop_count == 0 || p->hop_count >= UINT8_MAX) {
        log_debug("RREQ: invalid hop count => drop");
        return;
    }

    if (nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0)) {
        log_trace("RREQ: packet is old => drop");
        return;
    }

    if (p->dst_id == gstate.own_id) {
        log_debug("RREQ: 0x%08x => 0x%08x, destination reached => send RREP", p->src_id, p->dst_id);

        RREP rrep = {
            .type = TYPE_RREP,
            .hop_count = 1,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
        };

        // send back unicast
        send_ucast_wrapper(src, &rrep, get_size_RREP(&rrep));
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop && (1UL + p->hop_count + hop->hop_count) <= UINT16_MAX) {
            log_debug("RREQ: 0x%08x => 0x%08x, destination known => send RREP2", p->src_id, p->dst_id);
            uint8_t age = MIN(gstate.time_now - hop->time_updated, UINT8_MAX);
            RREP2 rrep2 = {
                .type = TYPE_RREP2,
                .hop_count = 1,
                .seq_num = g_sequence_number++,
                .src_id = gstate.own_id,
                .dst_id = p->src_id,
                .req_id = p->dst_id,
                .req_seq_num = node->seq_num,
                .req_hops = hop->hop_count + 1, // or use hop_count from RREQ?
                .req_age = age,
            };

            send_ucast_wrapper(src, &rrep2, get_size_RREP2(&rrep2));
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
        log_debug("RERR: destination reached => drop");
    } else {
        // forward
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("RERR: send to next hop %s => forward", str_addr(&hop->next_hop_addr));
            // forward
            p->hop_count += 1;

            send_ucast_wrapper(&hop->next_hop_addr, p, length);
        } else {
            log_debug("RERR: no next hop found => drop");
        }
    }
}

static void storage_add(Storage *storage, uint32_t src_id, uint16_t hop_count)
{
    //log_debug("storage_add: data_size: %d, data_capacity: %d",
    //    (int) storage->data_size, (int) storage->data_capacity);

    if (storage->data_size >= 262144) {
        // prevent out of memory
        log_warning("storage_add: out of memory");
        return;
    }

    for (size_t i = 0; i < storage->data_size; ++i) {
        RouteHint *e = &storage->data[i];
        switch (e->type) {
        case RouteTypeId:
            if (e->route_by_id.src_id == src_id) {
                e->was_forwarded = false;
                e->received_time = 0;
                e->route_by_id.hop_count = hop_count;
                return;
            }
        }
    }

    if (storage->data) {
        if (storage->data_capacity <= storage->data_size) {
            storage->data_capacity *= 2;
            storage->data = (RouteHint*) realloc(storage->data, sizeof(RouteHint) * storage->data_capacity);
        }
    } else {
        storage->data_size = 0;
        storage->data_capacity = 1;
        storage->data = (RouteHint*) calloc(1, sizeof(RouteHint) * storage->data_capacity);
    }

    storage->data[storage->data_size] = (RouteHint) {
        .was_forwarded = false,
        .received_time = 0,
        .route_by_id = (RouteById) {
            .src_id = src_id,
            .hop_count = hop_count,
        }
    };
    storage->data_size += 1;
}

static void handle_ROOT_STORE(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, ROOT_STORE *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast || !is_destination) {
        log_trace("ROOT_STORE: unexpected destination => drop");
        return;
    }

    if (length != get_size_ROOT_STORE(p)) {
        log_trace("ROOT_STORE: invalid packet size => drop");
        return;
    }

    if (p->entry_count == 0 || p->entry_count > MAX_ROOT_STORE_ENTRIES) {
        log_trace("ROOT_STORE: entry_count == 0 => drop");
        return;
    }

/*
    const ROOT_STORE_ID *first = &p->entries[0];

    // good? do we need seq_nums here?
    if (packet_is_duplicate(first->src_id, p->seq_num)) {
        log_debug("ROOT_STORE: packet is old => drop (src_id: 0x%08x, seq_num: %d)", first->src_id, (int) p->seq_num);
        return;
    }
*/
    //bool is_root = we_are_root();
    // store entries, this is the important part
    log_debug("ROOT_STORE: got packet (entry_count: %d, entries: [%s]) from %s",
        (int) p->entry_count, str_entries(&p->entries[0], p->entry_count), str_addr(&neighbor->address));
    
    //log_debug("ROOT_STORE: before");
    //print_storage();
    for (size_t i = 0; i < p->entry_count; ++i) {
        const ROOT_STORE_ID *e = &p->entries[i];
        //nodes_update(e->src_id, src, e->hop_count, (i == 0) ? p->seq_num : UNKNOWN_SEQUENCE_NUMBER, 0);
        //if (!is_root) {
            //log_debug("ROOT_STORE: add [0x%x/%d]", e->src_id, (int) e->hop_count);
            storage_add(&neighbor->storage, e->src_id, e->hop_count);
        //}
    }
    //log_debug("ROOT_STORE: after");
    //print_storage();
    //nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0);
}

#if 0
static void send_ROOT_STORE()
{
    if (we_are_root()) {
        return;
    }

    ROOT_STORE p = {
        .type = TYPE_ROOT_STORE,
        .seq_num = g_sequence_number++,
        .entry_count = 0,
    };

    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        StorageList *sl = neighbor->storage;
        // insert oldest first?
        while (sl) {
            // insert
            sl = sl->next;
        }
    }
    // send to parent

    Neighbor *parent = get_parent();
    if (we_are_root()) {
        log_debug("ROOT_STORE: got packet (0x%08x => parent) from neighbor %s, hop_count/entries: %d => accept",
            first->src_id, str_addr(src), (int) p->entry_count);
    } else {
        if (is_destination) {
            if (parent && !address_is_null(&parent->address)) {
                log_debug("ROOT_STORE: got packet (0x%08x => parent) from neighbor %s, hop_count/entries: %d => forward",
                    first->src_id, str_addr(src), (int) p->entry_count);

                p->entries[p->entry_count] = (ROOT_STORE_ID) { .src_id = gstate.own_id };
                p->entry_count += 1;

                // forward to parent
                p->hop_count += 1;
                send_ucast_wrapper(&parent->address, p, get_size_ROOT_STORE(p));
            } else {
                log_trace("ROOT_STORE: got packet (0x%08x => parent) from neighbor %s, hop_count/entries: %d, no root => drop",
                    first->src_id, str_addr(src), (int) p->entry_count);
            }
        } else {
            log_trace("ROOT_STORE: overheard packet (0x%08x => parent) from neighbor %s, hop_count/entries: %d => drop",
                first->src_id, str_addr(src), (int) p->entry_count);
        }
        /*
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("ROOT_STORE: got packet (0x%08x => 0x%08x), hop_count: %d, from %s, send to %s, %d hops away => forward",
                p->src_id, p->dst_id, p->hop_count, str_addr(src), str_addr(&hop->next_hop_addr), (int) hop->hop_count);

            p->hop_count += 1;
            send_ucast_wrapper(&hop->next_hop_addr, p, get_size_ROOT_STORE(p));
        } else {
            log_debug("ROOT_STORE: no next hop known => drop");
        }
        */
    }
}
#endif

/*
static void handle_BLOOM(IFState *ifstate, Neighbor *neighbor, const Address *src, uint8_t flags, BLOOM *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast || !is_destination) {
        log_trace("BLOOM: unexpected destination => drop");
        return;
    }

    if (length != get_size_BLOOM(p)) {
        log_debug("BLOOM: invalid packet size => drop");
        return;
    }

    if (0 != memcmp(&neighbor->bloom.bloom_data, &p->bloom_data, BLOOM_M)) {
        neighbor->bloom.bloom_changed = gstate.time_now;
    }

    neighbor->bloom.bloom_received = gstate.time_now;
    memcpy(&neighbor->bloom.bloom_data, &p->bloom_data, BLOOM_M);
}
*/

static bool is_latest_seqnum(uint32_t root_id, uint16_t seq_num)
{
    //bool cur_seq_num_set = false;
    //uint16_t cur_seq_num;

    Neighbor *neighbor;
    Neighbor *tmp;
    HASH_ITER(hh, g_neighbors, neighbor, tmp) {
        if (neighbor->root.root_set && neighbor->root.root_id == root_id) {
            //log_debug("is_latest_seqnum: %d %d", (int) neighbor->root.root_seq_num, (int) seq_num);
            if (!is_newer_seqnum(neighbor->root.root_seq_num, seq_num)) {
                //log_debug("is old seq_num");
                return false;
            } else {
                //log_debug("is new seq_num");
            }
        }
    }

    return true;
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

    //nodes_update(p->root_id, src, p->hop_count, UNKNOWN_SEQUENCE_NUMBER, 0);
    //nodes_update(p->sender, src, 1, UNKNOWN_SEQUENCE_NUMBER, 0);
    //nodes_update(p->prev_sender, src, 2, UNKNOWN_SEQUENCE_NUMBER, 0);

    Neighbor *old_parent = get_parent();

{
    // check sequence number for the current root
    uint32_t cur_root_id;
    uint16_t cur_root_seq_num;

    if (old_parent) {
        assert(old_parent->root.root_set);
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
    if (neighbor->root.root_set && neighbor->root.root_id == p->root_id
            && !is_newer_seqnum(neighbor->root.root_seq_num, p->root_seq_num)) {
        // duplicate packet
        log_debug("handle_ROOT_CREATE: duplicate packet from %s root_id: 0x%08x, seq_num: %d",
            str_addr(&neighbor->address), p->root_id, p->root_seq_num);
        return;
    }

    if (neighbor->root.root_id != p->root_id || !neighbor->root.root_set) {
        neighbor->root.time_created = gstate.own_id;
    }

    neighbor->root.root_set = true;
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
        log_debug("handle_ROOT_CREATE: got packet from %s root_id: 0x%08x, root_seq_num: %d => drop",
            str_addr(&neighbor->address), p->root_id, (int) p->root_seq_num);
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    Node *node = next_node_by_id(dst_id);
    Hop *hop = next_hop_by_node(node);
    if (node && hop) {
        // packet pointer points into an allocated chunk to fit some added header
        DATA *p = (DATA*) (packet - offsetof(DATA, payload_data));

        p->type = TYPE_DATA;
        p->hop_count = 1;
        p->seq_num = g_sequence_number++;
        p->src_id = gstate.own_id;
        p->dst_id = dst_id;
        p->payload_length = packet_length;

        log_debug("tun_handler() send DATA packet (0x%08x => 0x%08x) to %s, %d hops away",
            p->src_id, p->dst_id, str_addr(&hop->next_hop_addr), (int) hop->hop_count);

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

        send_RREQ("tun_handler()", NULL, &p);
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
        neighbor->last_updated = gstate.time_now;
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
    //case TYPE_BLOOM:
    //    handle_BLOOM(ifstate, neighbor, src, flags, (BLOOM*) packet, packet_length);
    //    break;
    default:
        log_warning("unknown packet type 0x%02x of size %zu from %s", packet[0], packet_length, str_addr(src));
        break;
    }
}

static void ext_handler_l3(const Address *src, uint8_t *packet, size_t packet_length)
{
    if (address_is_broadcast(src)) {
        // broadcast source is invalid => ignore
        log_warning("ext_handler_l3: source address is broadcast: %s", str_addr(src));
        return;
    }

    uint8_t flags = FLAG_IS_UNICAST | FLAG_IS_DESTINATION;
    ext_handler(src, flags, packet, packet_length);
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    log_debug("rcv: %s, src: %s, dst: %s", str_addr(rcv), str_addr(src), str_addr(dst));

    if (address_is_broadcast(src)) {
        log_warning("ext_handler_l2: source address is invalid (broadcast): %s", str_addr(src));
        return;
    }

    if (address_equal(rcv, src)) {
        // own unicast packet => ignore
        return;
    }

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

#ifdef DHT
        if (g_enable_dht) {
            dht_status(fp);
        }
#endif

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

        //fprintf(fp, "neighbors of [%s]:\n", str_coords(&g_root.coords));
        //fprintf(fp, " address root_id root_hop_count bloom_data bloom_node_count is_parent\n"); // time_created time_packets_send time_last_recv\n");
        HASH_ITER(hh, g_neighbors, neighbor, tmp) {
            fprintf(fp, "address: %s\n",
                str_addr(&neighbor->address)
            );
            if (neighbor->root.root_set) {
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
                fprintf(fp, "\"address\": \"%s\"", str_addr(&neighbor->address));
                if (neighbor->root.root_set) {
                    fprintf(fp, ",");
                    fprintf(fp, "\"root_id\": \"0x%08x\",", neighbor->root.root_id);
                    fprintf(fp, "\"root_hop_count\": %d,", (int) neighbor->root.hop_count);
                    fprintf(fp, "\"root_parent_id\": \"0x%08x\",", neighbor->root.parent_id);
                    fprintf(fp, "\"time_created\": \"%s\",", str_since(neighbor->root.time_created));
                    fprintf(fp, "\"is_parent\": \"%s\"", str_bool(neighbor == parent));
                }
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

/*
static void dht_forward_rreq()
{
    DHTPendingLookup *tmp;
    DHTPendingLookup *entry;
    HASH_ITER(hh, dht_lookups, entry, tmp) {
        if ((gstate->time_now - entry->time_created) > 16000) {
            // remove after 16 seconds
            HASH_DEL(dht_lookups, entry);
            free(entry);
        }
    }
}*/

#ifdef DHT
static void dht_result_callback(const uint8_t info_hash[], int af, const void *data, size_t data_len)
{
    log_debug("dht_result_callback");

    // map info_hash to node id
    //Address address;
    uint32_t id = 0;
    memcpy(&id, info_hash, sizeof(uint32_t));

    PING ping = {
        .type = TYPE_PING,
        .seq_num = g_sequence_number++,
    };

    switch (af) {
        case AF_INET: {
            size_t numresults = (data_len / sizeof(struct dht_addr4_t));
            struct dht_addr4_t *data4 = (struct dht_addr4_t *) data;
            for (size_t i = 0; i < numresults; ++i) {
                /*
                struct sockaddr_in address = {0};
                address.sin_family = AF_INET;
                address.sin_port = htons(data4->port);
                memcpy(&address.sin_addr, &data4->addr, 4);
                */

                Address address = {0};
                address.family = AF_INET;
                ((struct sockaddr_in *)&address)->sin_port = htons(data4->port);
                memcpy(&((struct sockaddr_in *)&address)->sin_addr, &data4->addr, 4);

                log_debug("send PING over network to %s", str_addr(&address));
                dht_send_packet((struct sockaddr *) &address, &ping, get_size_PING(&ping));

                //nodes_update(id, &address, 1, UNKNOWN_SEQUENCE_NUMBER, 0); // TODO: hop count is actually wrong
            }
            break;
        }
        case AF_INET6: {
            size_t numresults = (data_len / sizeof(struct dht_addr6_t));
            struct dht_addr6_t *data6 = (struct dht_addr6_t *) data;
            for (size_t i = 0; i < numresults; ++i) {
                Address address = {0};
                address.family = AF_INET6;
                ((struct sockaddr_in6 *)&address)->sin6_port = htons(data6->port);
                memcpy(&((struct sockaddr_in6 *)&address)->sin6_addr, &data6->addr, 16);

                log_debug("send PING over network to %s", str_addr(&address));
                dht_send_packet((struct sockaddr *) &address, &ping, get_size_PING(&ping));
            }
            break;
        }
    }
}

static bool dht_socket_callback(const Address* src, void *packet, size_t packet_length)
{
    return false;
/*
    if (packet_length > 0 && packet[0] == 'magic') {
        uint8_t flags = FLAG_IS_DESTINATION;
        ext_handler(src, flags, packet, packet_length);
        return true;
    } else {
        // DHT traffic - not for us here
        return false;
    }
*/
}
#endif

static void init_handler()
{
    g_root.root_set = true;
    g_root.root_id = gstate.own_id;

    //roots_add(gstate.own_id);

    net_add_handler(-1, &periodic_handler);
    packet_cache_init(20);

#ifdef DHT
    if (g_enable_dht) {
        // DHT setup
        uint8_t node_id[SHA1_BIN_LENGTH];
        bytes_random(node_id, SHA1_BIN_LENGTH);

        dht_setup(AF_UNSPEC, node_id, DHT_PORT, NULL, &dht_result_callback, &dht_socket_callback);
    }
#endif
}

static void exit_handler()
{
#ifdef DHT
    if (g_enable_dht) {
        dht_shutdown();
    }
#endif
}

static bool config_handler(const char *option, const char *value)
{
    /*if (0 == strcmp(option, "enable-dht")) {
        g_enable_dht = true;
        return true;
    } else*/ if (strcmp(option, "peer") && value != NULL) {
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
