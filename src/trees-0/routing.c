#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#include "../ext/seqnum_cache.h"
#include "../ext/packet_cache.h"
#include "../ext/packet_trace.h"
#include "../ext/uthash.h"
#include "../log.h"
#include "../utils.h"
#include "../tun.h"
#include "../net.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

#include "routing.h"

#define ROOT_MAX_PATH_COUNT 32
#define ROOT_SEND_INTERVAL_SECONDS 8
#define NODE_TIMEOUT (4 * ROOT_SEND_INTERVAL_SECONDS)
#define SEQNUM_CACHE_TIMEOUT_SECONDS  60

enum {
    TYPE_DATA, // data send via distance vector
    TYPE_ROOT,
    TYPE_ROUTE_REQUEST, // send as broadcast
    TYPE_ROUTE_REPLY,
    TYPE_DHT_REQUEST, // keep a DHT entry alive
    TYPE_DHT_RESPONSE,
    TYPE_PATH_REQUEST,
    TYPE_PATH_RESPONSE, // get path based on root
};

typedef struct {
    Address next_hop_addr;      // use neighbor object with id and address?
    uint64_t last_updated;
    uint16_t hop_count;
    UT_hash_handle hh;
} Hop;

typedef struct {
    uint32_t id;
    Hop *hops;
    UT_hash_handle hh;
} Node;

typedef struct Root {
    Address parent_addr;
    uint32_t root_id;
    uint16_t seq_num;
    uint16_t updated_count;
    uint64_t last_updated;
    uint32_t path_length;
    uint32_t path[ROOT_MAX_PATH_COUNT];
} Root;

static const char *str_path(const void *_path, const size_t path_length)
{
    static char buf[ROOT_MAX_PATH_COUNT * 25];
    uint32_t path[ROOT_MAX_PATH_COUNT];
    memcpy(path, _path, path_length * sizeof(uint32_t));

    char *cur = buf;
    cur[0] = 0;
    for (size_t i = 0; i < path_length; i += 1) {
        ssize_t left = (buf + sizeof(buf)) - cur;
        cur += snprintf(cur, left, i ? ", 0x%08x" : "0x%08x", path[i]);
    }
    return buf;
}

// packet to create span the tree
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t root_id;
    uint16_t seq_num;
    uint16_t path_length; // might not be needed
    uint32_t path[ROOT_MAX_PATH_COUNT];
} ROOT;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t seq_num;
    uint32_t path_length;
    uint32_t path[ROOT_MAX_PATH_COUNT];
} PATH_REQUEST;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t seq_num;
    uint32_t path_length;
    uint32_t path[ROOT_MAX_PATH_COUNT];
} PATH_RESPONSE;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t seq_num;
    uint16_t hop_count;
    uint16_t payload_size;
    uint8_t payload_data[ETH_FRAME_LEN];
} DATA;

// broadcast
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t seq_num;
    uint16_t hop_count;
} ROUTE_REQUEST;

// try
// TODO: add path?
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t seq_num;
    uint16_t hop_count;
} DHT_REQUEST;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t seq_num;
    uint16_t hop_count;
} DHT_RESPONSE;


static size_t get_dht_request_size(const DHT_REQUEST *r)
{
    return sizeof(DHT_REQUEST);
}

static size_t get_dht_response_size(const DHT_RESPONSE *r)
{
    return sizeof(DHT_RESPONSE);
}

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t seq_num;
    uint16_t hop_count;
} ROUTE_REPLY;

static size_t get_data_size(const DATA *p)
{
    return offsetof(DATA, payload_data) + p->payload_size;
}

static size_t get_data_min_size()
{
    return offsetof(DATA, payload_data);
}

static size_t get_root_size(ROOT *p)
{
    return offsetof(ROOT, path) + p->path_length * sizeof(uint32_t);
}

static uint32_t* get_root_path(ROOT *p)
{
    return (uint32_t*) (((uint8_t*) p) + offsetof(ROOT, path));
}

static size_t get_path_request_size(const PATH_REQUEST *p)
{
    return offsetof(PATH_REQUEST, path) + p->path_length * sizeof(uint32_t);
}

static size_t is_path_request_valid(const PATH_REQUEST *p, size_t length)
{
    return (length >= offsetof(PATH_REQUEST, path))
        && (get_path_request_size(p) == length);
}

static size_t get_path_response_size(const PATH_RESPONSE *p)
{
    return offsetof(PATH_RESPONSE, path) + p->path_length * sizeof(uint32_t);
}

static size_t is_path_response_valid(const PATH_RESPONSE *p, size_t length)
{
    return (length >= offsetof(PATH_RESPONSE, path))
        && (get_path_response_size(p) == length);
}

static uint16_t g_sequence_number = 0;
static bool g_is_critical = true; // rename to relay_broadcasts?
static uint64_t g_is_critical_time = 0; // for timeout
static Node *g_nodes = NULL;
static Root g_root = {0};


static void dht_del(uint32_t id);

static void nodes_timeout()
{
    Node *node;
    Node *ntmp;
    Hop *hop;
    Hop *htmp;

    HASH_ITER(hh, g_nodes, node, ntmp) {
        HASH_ITER(hh, node->hops, hop, htmp) {
            if ((hop->last_updated + NODE_TIMEOUT) < gstate.time_now) {
                log_debug("timeout hop %s", str_addr(&hop->next_hop_addr));
                HASH_DEL(node->hops, hop);

                free(hop);
            }
        }

        // not paths left, remove entry
        if (node->hops == NULL) {
            log_debug("timeout node 0x%08x", node->id);
            HASH_DEL(g_nodes, node);

            // remove from DHT
            dht_del(node->id);

            free(node);
        }
    }
}

static Node *next_node_by_id(uint32_t id)
{
    Node *node;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    return node;
}

static Hop *next_hop_by_node(Node *node)
{
    if (node == NULL) {
        return NULL;
    }

    Hop *hop;
    Hop *htmp;
    Hop *hbest = NULL;
    HASH_ITER(hh, node->hops, hop, htmp) {
        if (hbest == NULL || (hop->hop_count < hbest->hop_count)) {
            hbest = hop;
        }
    }
    return hbest;
}

static Hop *next_hop_by_id(uint32_t id)
{
    Node *node = next_node_by_id(id);
    // find best next hop
    return next_hop_by_node(node);
}

static void dht_send_path_request(uint32_t dst_id, bool force)
{
    Hop *hop = next_hop_by_id(dst_id);
    if (hop == NULL) {
        // the node should not have timed out.
        // (unless there is a timeout of 1 second configured...)
        log_error("dht_send_path_request() missing hop for 0x%08x, should never happen!", dst_id);
        exit(1);
    }

    if (force || (gstate.time_now - hop->last_updated) > (NODE_TIMEOUT / 2)) {
        PATH_REQUEST request = {
            .type = TYPE_PATH_REQUEST,
            .src_id = gstate.own_id,
            .dst_id = dst_id,
            .seq_num = g_sequence_number++,
            .path_length = 0,
        };

        log_debug("dht_send_path_request(0x%08x, %s, %zu)",
            dst_id, str_addr(&hop->next_hop_addr), (size_t) get_path_request_size(&request));

        send_ucast_l2(&hop->next_hop_addr, &request, get_path_request_size(&request));
    }
}

static bool g_dht_prev_set = false;
static bool g_dht_next_set = false;
static bool g_dht_prev_force = false;
static bool g_dht_next_force = false;
static uint32_t g_dht_prev = 0;
static uint32_t g_dht_next = 0;

static bool is_ordered(uint32_t id1, uint32_t id2, uint32_t id3)
{
    return (id1 < id2) && (id2 < id3);
}

static void dht_maintenance()
{
    // TODO: only one direction maintainance should be enough
    if (g_dht_prev_set) {
        dht_send_path_request(g_dht_prev, g_dht_prev_force);
        g_dht_prev_force = false;
    }

    if (g_dht_next_set && g_dht_next_force) {
        dht_send_path_request(g_dht_next, g_dht_next_force);
        g_dht_next_force = false;
    }
}

// id, but we do not have a tree path for it
static void dht_update(uint32_t id)
{
    log_trace("dht_update()");

    if ((g_dht_prev_set && is_ordered(g_dht_prev, id, gstate.own_id))
            || (!g_dht_prev_set && id < gstate.own_id)) {
        // id changes
        g_dht_prev = id;
        g_dht_prev_set = true;
        g_dht_prev_force = true;
    }

    if ((g_dht_next_set && is_ordered(gstate.own_id, id, g_dht_next))
            || (!g_dht_next_set && id > gstate.own_id)) {
        // id changes
        g_dht_next = id;
        g_dht_next_set = true;
        g_dht_next_force = true;
    }
}

static void _nodes_update(uint32_t id, const Address *addr, uint16_t hop_count)
{
    // ignore own id
    if (id == gstate.own_id) {
        // should not happen (atm. it can)
        log_error("got own id");
        return;
    }

    //log_trace("_nodes_update() id: 0x%08x, addr: %s, hop_count: %zu",
    //    id, str_addr(addr), (size_t) hop_count);

    Node *cur;
    Hop *hop;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), cur);
    if (cur == NULL) {
        cur = (Node*) malloc(sizeof(Node));
        cur->id = id;
        cur->hops = NULL;
        HASH_ADD(hh, g_nodes, id, sizeof(uint32_t), cur);
    }

    HASH_FIND(hh, cur->hops, addr, sizeof(Address), hop);
    if (hop == NULL) {
        hop = (Hop*) malloc(sizeof(Hop));
        hop->next_hop_addr = *addr;
        HASH_ADD(hh, cur->hops, next_hop_addr, sizeof(Address), hop);
    }

    hop->hop_count = hop_count;
    hop->last_updated = gstate.time_now;

    dht_update(id);
}

static void nodes_update_node(uint32_t id, const Address *addr, uint16_t hop_count)
{
    log_debug("nodes_update_node() id: 0x%08x, addr: %s, hop_count: %zu",
        id, str_addr(addr), (size_t) hop_count);

    _nodes_update(id, addr, hop_count);

    //dht_send_notify();
}

static void nodes_update_path(uint32_t id, const Address *next_hop_addr, const uint32_t *path, size_t path_length)
{
    log_debug("nodes_update_path() path: %p, path_length: %zu", path, (size_t) path_length);

    _nodes_update(id, next_hop_addr, path_length + 1);

    for (size_t i = 0; i < path_length; i += 1) {
        _nodes_update(path[i], next_hop_addr, path_length - i);
    }

    //dht_send_notify();
}

static void dht_del(uint32_t id)
{
    if (g_dht_prev_set && id == g_dht_prev) {
        g_dht_prev_set = false;
        g_dht_prev_force = false;
    }

    if (g_dht_next_set && id == g_dht_next) {
        g_dht_next_set = false;
        g_dht_next_force = false;
    }

    if (!g_dht_prev_set || !g_dht_next_set) {
        // find new id
        Node *cur;
        Node *tmp;
        HASH_ITER(hh, g_nodes, cur, tmp) {
            dht_update(cur->id);
        }
    }
}

void handle_PATH_RESPONSE(const Address *rcv, const Address *src, const Address *dst, PATH_RESPONSE *p, size_t length)
{
    if (!is_path_response_valid(p, length)) {
        log_debug("PATH_RESPONSE: invalid packet => drop");
        return;
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("PATH_RESPONSE: packet already seen => drop");
        return;
    }

    uint32_t path[ROOT_MAX_PATH_COUNT];
    memcpy(path, &p->path, p->path_length * sizeof(uint32_t));

    log_debug("PATH_RESPONSE: got packet: %s / 0x%08x => 0x%08x / seq_num: %zu / path: [%s]",
        str_addr(dst), p->src_id, p->dst_id, (size_t) p->seq_num, str_path(path, p->path_length));

    nodes_update_path(p->src_id, src, path, p->path_length);

    if (p->dst_id == gstate.own_id) {
        // TODO: some action? Why did we send out the request in the first place...
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            if (p->path_length >= ROOT_MAX_PATH_COUNT) {
                log_debug("PATH_RESPONSE: max path count reached => drop");
            } else {
                log_debug("PATH_RESPONSE: next node found => forward");
                PATH_RESPONSE pnew = {
                    .type = TYPE_PATH_RESPONSE,
                    .src_id = p->src_id,
                    .dst_id = p->dst_id,
                    .seq_num = p->seq_num,
                    .path_length = p->path_length,
                };
                memcpy(&pnew.path[0], path, p->path_length * sizeof(uint32_t));
                // append to path
                pnew.path[pnew.path_length] = gstate.own_id;
                pnew.path_length += 1;
                send_ucast_l2(&hop->next_hop_addr, &pnew, get_path_response_size(&pnew));
            }
        } else {
            log_debug("PATH_RESPONSE: no next hop found => drop");
        }
    }
}

void handle_PATH_REQUEST(const Address *rcv, const Address *src, const Address *dst, PATH_REQUEST *p, size_t length)
{
    if (!is_path_request_valid(p, length)) {
        log_debug("PATH_REQUEST: invalid packet => drop");
        return;
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("PATH_REQUEST: packet already seen => drop");
        return;
    }

    uint32_t path[ROOT_MAX_PATH_COUNT];
    memcpy(path, &p->path, p->path_length * sizeof(uint32_t));

    log_debug("PATH_REQUEST: got packet: %s / 0x%08x => 0x%08x / seq_num: %zu / path: [%s]",
        str_addr(dst), p->src_id, p->dst_id, (size_t) p->seq_num, str_path(path, p->path_length));

    nodes_update_path(p->src_id, src, path, p->path_length);

    if (p->dst_id == gstate.own_id) {
        PATH_RESPONSE pnew = {
            .type = TYPE_PATH_RESPONSE,
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
            .seq_num = g_sequence_number++,
            .path_length = 0,
        };
        send_ucast_l2(src, &pnew, get_path_response_size(&pnew));
    } else {
        Hop *hop = next_hop_by_id(p->dst_id);
        if (hop) {
            if (p->path_length >= ROOT_MAX_PATH_COUNT) {
                log_debug("PATH_REQUEST: max path count reached => drop");
            } else {
                log_debug("PATH_REQUEST: next node found => forward");
                PATH_REQUEST pnew = *p;
                pnew.path[pnew.path_length] = gstate.own_id;
                pnew.path_length += 1;
                send_ucast_l2(&hop->next_hop_addr, &pnew, get_path_request_size(&pnew));
            }
        } else {
            log_debug("PATH_REQUEST: no next hop found => drop");
        }
    }
}

static void send_cached_packet(uint32_t dst_id, const Address *next_hop_addr)
{
    uint8_t buffer[ETH_FRAME_LEN];
    DATA *p = (DATA*) &buffer[0];

    size_t data_payload_length = 0; // offsetof(DATA, data_size)
    packet_cache_get_and_remove(&p->payload_data, &data_payload_length, dst_id);

    if (data_payload_length == 0) {
        // no cached packet found
        return;
    }

    p->type = TYPE_DATA;
    p->seq_num = g_sequence_number++;
    p->src_id = gstate.own_id;
    p->dst_id = dst_id;
    p->hop_count = 0;
    p->payload_size = data_payload_length;

    // avoid processing of this packet again
    seqnum_cache_update(p->src_id, p->seq_num);

    log_debug("DATA: send (0x%08x => 0x%08x) to %s via next hop %s",
        p->src_id, p->dst_id, str_addr(next_hop_addr));

    send_ucast_l2(next_hop_addr, p, get_data_size(p));
}

static size_t dht_distance(uint32_t id1, uint32_t id2)
{
    return (id1 > id2) ? (id1 - id2) : (id2 - id1);
}

/*
This is broken
*/
static Node *dht_next(uint32_t id)
{
    Node *cur;
    Node *tmp;

    // populate from dht_prev and dht_next
    Node *nearest_prev = NULL;
    Node *nearest_next = NULL;

    // look for node that is nearest numerically
    HASH_ITER(hh, g_nodes, cur, tmp) {
        if (nearest_prev) {
            if (is_ordered(nearest_prev->id, cur->id, id)) {
                nearest_prev = cur;
            }
        } else if (cur->id <= id) {
            nearest_prev = cur;
        }

        if (nearest_next) {
            if (is_ordered(id, cur->id, nearest_next->id)) {
                nearest_next = cur;
            }
        } else if (id <= cur->id) {
            nearest_next = cur;
        }
    }

    size_t d = dht_distance(gstate.own_id, id);
    size_t d_prev = dht_distance(nearest_prev->id, id);
    size_t d_next = dht_distance(nearest_next->id, id);
    if (d_next < d_prev) {
        if (d_next < d) {
            log_debug("dht_next: next dst is 0x%08x towards 0x%08x (distance: %zu => %zu)",
                nearest_next->id, id, d, d_next);
            return nearest_next;
        }
    } else {
        if (d_prev < d) {
            log_debug("dht_next: next dst is 0x%08x towards 0x%08x (distance: %zu => %zu)",
                nearest_prev->id, id, d, d_next);
            return nearest_prev;
        }
    }

    log_debug("dht_next: no next hop found that is nearer towards 0x%08x", id);

    return NULL;
}

static void handle_DHT_RESPONSE(const Address *rcv, const Address *src, const Address *dst, DHT_RESPONSE *p, size_t length)
{
    if (get_dht_response_size(p) != length) {
        log_debug("DHT_RESPONSE: invalid packet size => drop");
        return;
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("DHT_RESPONSE: packet already seen => drop");
        return;
    }

    log_debug("DHT_RESPONSE: got packet: %s / 0x%08x => 0x%08x / seq_num: %zu / hop_count: %zu",
        str_addr(dst), p->src_id, p->dst_id, (size_t) p->seq_num, (size_t) p->hop_count);

    nodes_update_node(p->src_id, src, p->hop_count);

    if (p->dst_id == gstate.own_id) {
        // send packet
        log_debug("DHT_RESPONSE: destination reached => respond");
        send_cached_packet(p->src_id, src);
    } else {
        // forward
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("DHT_RESPONSE: next hop is 0x%08x => forward", node->id);
            p->hop_count += 1;
            send_ucast_l2(&hop->next_hop_addr, p, get_dht_response_size(p));
        } else {
            log_debug("DHT_RESPONSE: no next hop => drop");
        }
    }
}

static void handle_DHT_REQUEST(const Address *rcv, const Address *src, const Address *dst, DHT_REQUEST *p, size_t length)
{
    if (get_dht_request_size(p) != length) {
        log_debug("DHT_REQUEST: invalid packet size => drop");
        return;
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("DHT_REQUEST: packet already seen => drop");
        return;
    }

    log_debug("DHT_REQUEST: got packet: %s / 0x%08x => 0x%08x / seq_num: %zu / hop_count: %zu",
        str_addr(dst), p->src_id, p->dst_id, (size_t) p->seq_num, (size_t) p->hop_count);

    nodes_update_node(p->src_id, src, p->hop_count);

    if (p->dst_id == gstate.own_id) {
        log_debug("DHT_REQUEST: destination reached => send reply");

        DHT_RESPONSE r = {
            .type = TYPE_DHT_RESPONSE,
            .src_id = p->dst_id,
            .dst_id = p->src_id,
            .hop_count = 0,
        };

        // we could just send the packet back,
        // but maybe we already know a better path
        Node *node = next_node_by_id(r.dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            log_debug("DHT_REQUEST: next hop is 0x%08x => forward", node->id);
            send_ucast_l2(&hop->next_hop_addr, &r, get_dht_response_size(&r));
        } else {
            log_error("DHT_REQUEST: no next hop found for 0x%08x. should not happen => abort", r.dst_id);
            exit(1);
        }
    } else {
        Node *node = dht_next(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            p->hop_count += 1;
            send_ucast_l2(&hop->next_hop_addr, p, length);
        } else {
            log_debug("DHT_REQUEST: no next hop found => drop");
        }
    }
}

static void handle_DATA(const Address *rcv, const Address *src, const Address *dst, DATA *p, size_t length)
{
    if (length <= get_data_min_size() || length != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("DATA: packet already seen => drop");
        return;
    }

    log_debug("DATA: got packet: %s / 0x%08x => 0x%08x / seq_num: %zu",
        str_addr(dst), p->src_id, p->dst_id, (size_t) p->seq_num);

    nodes_update_node(p->src_id, src, p->hop_count);

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: write %zu bytes to %s => accept", (size_t) p->payload_size, gstate.tun_name);

        packet_trace_set("ACCEPT", &p->payload_data, p->payload_size);

        // destination is the local tun0 interface => write packet to tun0
        tun_write(&p->payload_data, p->payload_size);
    } else {
        Hop *hop = next_hop_by_id(p->dst_id);
        if (hop) {
            packet_trace_set("FORWARD", &p->payload_data, p->payload_size);
            log_debug("DATA: next node found (%zu hops) => forward", (size_t) hop->hop_count);
            p->hop_count += 1;
            send_ucast_l2(&hop->next_hop_addr, p, length);
        } else {
            packet_trace_set("DROP", &p->payload_data, p->payload_size);
            log_debug("DATA: not at destination => drop");
        }
    }
}

static int path_contains_own(const ROOT *p)
{
    if (p->root_id == gstate.own_id) {
        return 1;
    }

    for (size_t i = 0; i < p->path_length; i += 1) {
        if (p->path[i] == gstate.own_id) {
            return 1;
        }
    }

    return 0;
}

static void set_critical(bool is_critical)
{
    log_debug("set critical: %s => %s", str_bool(g_is_critical), str_bool(is_critical));
    g_is_critical = is_critical;
    g_is_critical_time = gstate.time_now;
}

// TODO
static void handle_ROUTE_REQUEST(const Address *rcv, const Address *src, const Address *dst, ROUTE_REQUEST *p, size_t length)
{
    /*
    // we expect broadcasts or packets for us
    if (!address_is_unicast(dst)) {
        log_trace("ROUTE_REQUEST: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }
    */

    log_debug("ROUTE_REQUEST: %s => %s", str_addr(src), str_addr(dst));

    if (length != sizeof(ROUTE_REQUEST)) {
        log_debug("ROUTE_REQUEST: invalid packet size => drop");
        return;
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("ROUTE_REQUEST: packet already seen => drop");
        return;
    }

    nodes_update_node(p->src_id, src, p->hop_count);

    if (p->dst_id == gstate.own_id) {
        log_debug("ROUTE_REQUEST: destination reached => send ROUTE_REPLY", str_addr(src));

        // send route response
        ROUTE_REPLY rrep = {
            .type = TYPE_ROUTE_REPLY,
            .src_id = p->dst_id,
            .dst_id = p->src_id,
            .seq_num = g_sequence_number++,
            .hop_count = 0,
        };

        seqnum_cache_update(p->src_id, p->seq_num);

        send_ucast_l2(src, &rrep, sizeof(ROUTE_REPLY));
    } else {
        Hop *hop = next_hop_by_id(p->dst_id);
        if (hop) {
            log_debug("ROUTE_REQUEST: next node found => forward");
            p->hop_count += 1;
            send_ucast_l2(&hop->next_hop_addr, p, length);
        } else {
            log_debug("ROUTE_REQUEST: not at destination => forward");
            p->hop_count += 1;
            send_bcast_l2(0, p, length);
        }
    }
}

static void handle_ROUTE_REPLY(const Address *rcv, const Address *src, const Address *dst, ROUTE_REPLY *p, size_t length)
{
    // we expect (unicast) packets for us only
    if (!address_equal(rcv, dst)) {
        log_trace("ROUTE_REPLY: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(ROUTE_REPLY)) {
        log_debug("ROUTE_REPLY: invalid packet size => drop");
        return;
    }

    log_debug("ROUTE_REPLY: %s => %s", str_addr(src), str_addr(dst));

    nodes_update_node(p->src_id, src, p->hop_count);

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("ROUTE_REPLY: packet already seen => drop");
        return;
    }

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->src_id, src);
    } else {
        Hop *hop = next_hop_by_id(p->dst_id);
        if (hop) {
            log_debug("ROUTE_REPLY: a next node found => forward");
            p->hop_count += 1;
            send_ucast_l2(&hop->next_hop_addr, p, sizeof(ROUTE_REPLY));
        } else {
            log_debug("ROUTE_REPLY: no next node known => drop");
        }
    }
}

static bool is_valid_ROOT(ROOT *p, size_t length)
{
    return length >= offsetof(ROOT, path)
            && length == get_root_size(p)
            && p->path_length < ROOT_MAX_PATH_COUNT;
}

static void handle_ROOT(const Address *rcv, const Address *src, const Address *dst, ROOT *p, size_t length)
{
    // we expect broadcasts only
    if (!address_is_broadcast(dst)) {
        log_trace("ROOT: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (!is_valid_ROOT(p, length)) {
        log_debug("ROOT: invalid packet size => drop");
        return;
    }

    uint32_t path[ROOT_MAX_PATH_COUNT];
    memcpy(path, get_root_path(p), p->path_length * sizeof(uint32_t));

    uint8_t is_echo = path_contains_own(p);

    log_debug("ROOT: got packet from %s, seq_num: %zu, path: 0x%08x:[%s], is_echo: %s",
        str_addr(src), (size_t) p->seq_num, p->root_id,
        str_path(path, p->path_length), str_onoff(is_echo));

    Root *root = &g_root;

    log_debug("root_id: 0x%08x 0x%08x, seq_num: %zu (root: %zu), critical: %s",
        p->root_id, root->root_id, (size_t) p->seq_num, (size_t) root->seq_num, str_onoff(g_is_critical));

    nodes_update_path(p->root_id, src, path, p->path_length);

    if (p->root_id == root->root_id) {
        if (p->seq_num <= root->seq_num) {
            if (is_echo) {
                log_trace("ROOT: old sequence number and full flood echo => critical");
                set_critical(true);
            } else {
                log_trace("ROOT: old sequence number => ignore");
            }
        } else if (p->path_length <= root->path_length) {
            log_debug("ROOT: shorter or equal path => update");
            //set_critical(true);

            if (0 == memcmp(&root->parent_addr, src, sizeof(Address))) {
                root->updated_count += 1;
            } else {
                root->parent_addr = *src;
            }
            root->seq_num = p->seq_num;
            root->last_updated = gstate.time_now;
            root->path_length = p->path_length;
            memcpy(&root->path, path, p->path_length * sizeof(uint32_t));

            // append own id
            root->path[root->path_length] = gstate.own_id;
            root->path_length += 1;
        } else {
            log_trace("ROOT: got longer path => ignore");
        }
    } else if (p->root_id < root->root_id) {
        log_debug("ROOT: got smaller root id => take");

        root->parent_addr = *src;
        root->root_id = p->root_id;
        root->updated_count = 0;
        root->seq_num = p->seq_num;
        root->last_updated = gstate.time_now;
        root->path_length = p->path_length;
        memcpy(&root->path, path, p->path_length * sizeof(uint32_t));

        // append own id
        root->path[root->path_length] = gstate.own_id;
        root->path_length += 1;

        /*
        forward a new root immediately
        forward a update
        */
    } else {
        log_debug("ROOT: got bigger root id => ignore");
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    if (packet_length > ETH_FRAME_LEN) {
        log_warning("packet too big (% Bytes) => ignore", packet_length);
        return;
    }

    Hop *hop = next_hop_by_id(dst_id);
    if (hop) {
        // we know that the packet buffer starts with a padding
        DATA *p = (DATA*) (packet - offsetof(DATA, payload_size));
        p->type = TYPE_DATA;
        p->src_id = gstate.own_id;
        p->dst_id = dst_id;
        p->hop_count = 0;
        p->seq_num = g_sequence_number++;
        p->payload_size = packet_length;

        log_debug("tun_handler: send DATA to %s", str_addr(&hop->next_hop_addr));

        send_ucast_l2(&hop->next_hop_addr, p, get_data_size(p));
    } else {
        Node *node = dht_next(dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            DHT_REQUEST dreq = {
                .type = TYPE_DHT_REQUEST,
                .src_id = gstate.own_id,
                .dst_id = dst_id,
                .seq_num = g_sequence_number++,
                .hop_count = 0,
            };

            // avoid processing of our own packet again
            seqnum_cache_update(dreq.src_id, dreq.seq_num);

            // cache packet
            packet_cache_add(dst_id, packet, packet_length);

            log_debug("tun_handler: send DHT_REQUEST packet (0x%08x => 0x%08x)", dreq.src_id, dreq.dst_id);

            send_ucast_l2(&hop->next_hop_addr, &dreq, sizeof(DHT_REQUEST));
        } else {
            ROUTE_REQUEST rreq = {
                .type = TYPE_ROUTE_REQUEST,
                .seq_num = g_sequence_number++,
                .src_id = gstate.own_id,
                .dst_id = dst_id,
                .hop_count = 0,
            };

            // avoid processing of our own packet again
            seqnum_cache_update(rreq.src_id, rreq.seq_num);

            // cache packet
            packet_cache_add(dst_id, packet, packet_length);

            log_debug("tun_handler: send ROUTE_REQUEST packet (0x%08x => 0x%08x)", rreq.src_id, rreq.dst_id);

            send_bcast_l2(0, &rreq, sizeof(ROUTE_REQUEST));
        }
    }
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    if (!address_is_broadcast(dst) && !address_equal(dst, rcv)) {
        // packet is not for us (possible e.g. when device is in monitor mode)
        return;
    }

    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(rcv, src, dst, (DATA*) packet, packet_length);
        break;
    case TYPE_ROOT:
        handle_ROOT(rcv, src, dst, (ROOT*) packet, packet_length);
        break;
    case TYPE_PATH_REQUEST: // unicast only
        handle_PATH_REQUEST(rcv, src, dst, (PATH_REQUEST*) packet, packet_length);
        break;
    case TYPE_PATH_RESPONSE: // unicast only
        handle_PATH_RESPONSE(rcv, src, dst, (PATH_RESPONSE*) packet, packet_length);
        break;
    case TYPE_ROUTE_REQUEST: // broadcast/unicast
        handle_ROUTE_REQUEST(rcv, src, dst, (ROUTE_REQUEST*) packet, packet_length);
        break;
    case TYPE_ROUTE_REPLY: // unicast only
        handle_ROUTE_REPLY(rcv, src, dst, (ROUTE_REPLY*) packet, packet_length);
        break;
    case TYPE_DHT_REQUEST: // unicast only
        handle_DHT_REQUEST(rcv, src, dst, (DHT_REQUEST*) packet, packet_length);
        break;
    case TYPE_DHT_RESPONSE: // unicast only
        handle_DHT_RESPONSE(rcv, src, dst, (DHT_RESPONSE*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src));
    }
}

static void reset_root()
{
    log_debug("reset_root");

    g_root = (Root) {
        .root_id = gstate.own_id,
        .last_updated = gstate.time_now,
    };
}

static const char *is_root_str()
{
    return (g_root.root_id == gstate.own_id) ? "true" : "false";
}

static void send_root()
{
    ROOT root = {
        .type = TYPE_ROOT,
        .root_id = g_root.root_id,
        .seq_num = g_root.seq_num,
        .path_length = g_root.path_length,
    };

    memcpy(get_root_path(&root), &g_root.path, g_root.path_length * sizeof(uint32_t));

    log_debug("send_root: path 0x%08x:[%s] (is own: %s)",
        g_root.root_id, str_path(&g_root.path, g_root.path_length), is_root_str());

    send_bcast_l2(0, &root, get_root_size(&root));
}

static bool g_initial_root_send = false;

// return node behind an address
// slow - only for debugging
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

// TODO: do not send root via periodic handler.
// how about root should also send the promise when to send the next one
static void periodic_handler()
{
    nodes_timeout();
    dht_maintenance();

    if ((gstate.time_now / 1000) % ROOT_SEND_INTERVAL_SECONDS == 0 || !g_initial_root_send) {
        g_initial_root_send = true;

        if (g_root.root_id == gstate.own_id) {
            // we are the root
            send_root();

            set_critical(true);

            // pretend we received our own announcement (needed?)
            g_root.updated_count += 1;
            g_root.last_updated = gstate.time_now;

            // change sequence number (only for our own root!)
            g_root.seq_num += 1;
        } else {
            // forward flood if we are critical or this is a full_flood

            // make sure we are critical after 30 seconds of no update
            if ((g_is_critical_time + 2 * ROOT_SEND_INTERVAL_SECONDS) < gstate.time_now) {
                log_debug("timeout for critical");
                set_critical(false);
            }

            // reset root if we have not heard from the current root for some time 
            if ((g_root.last_updated + (2 * ROOT_SEND_INTERVAL_SECONDS)) < gstate.time_now) {
                log_debug("timeout for root");
                reset_root();
            }

            // forward other root
            send_root();
        }
    }
}

static bool console_handler(FILE* fp, int argc, const char* argv[])
{
    if (match(argv, "h")) {
        fprintf(fp, "a                       custom action\n");
        fprintf(fp, "r                       print current root\n");
        fprintf(fp, "n                       print node tables\n");
    } else if (match(argv, "r")) {
        Root *r = &g_root;
        fprintf(fp, "general:\n");
        fprintf(fp, " own id:   0x%08x (is root: %s)\n", gstate.own_id, is_root_str());
        fprintf(fp, "dht:\n");
        if (g_dht_prev_set) {
            fprintf(fp, " prev:     0x%08x (d: %zu)\n", g_dht_prev, dht_distance(gstate.own_id, g_dht_prev));
        } else {
            fprintf(fp, " prev:     not set\n");
        }
        if (g_dht_next_set) {
            fprintf(fp, " next:     0x%08x (d: %zu)\n", g_dht_next, dht_distance(gstate.own_id, g_dht_next));
        } else {
            fprintf(fp, " next:     not set\n");
        }
        fprintf(fp, "tree root\n");
        fprintf(fp, " path:     0x%08x:[%s]\n", r->root_id, str_path(&r->path, r->path_length));
        fprintf(fp, " parent:   %s\n", str_addr(&r->parent_addr));
        fprintf(fp, " updated:  %s\n", str_since(r->last_updated));
        fprintf(fp, " count:    %zu\n", (size_t) r->updated_count);
        fprintf(fp, " critical: %s (%s ago)\n", str_onoff(g_is_critical), str_since(g_is_critical_time));
    } else if (match(argv, "n")) {
        Node *node;
        Node *ntmp;
        Hop *hop;
        Hop *htmp;
        size_t node_count = 0;
        size_t hop_count = 0;
        size_t neighbor_count = 0;

        fprintf(fp, "hop-nodes:\n");
        fprintf(fp, " id          hop-count  next-hop-id   next-hop-address   last-updated\n");
        HASH_ITER(hh, g_nodes, node, ntmp) {
            node_count += 1;
            fprintf(fp, " 0x%08x\n", node->id);
            HASH_ITER(hh, node->hops, hop, htmp) {
                hop_count += 1;
                neighbor_count += (hop->hop_count == 1);
                Node *neighbor = find_neighbor_by_address(&hop->next_hop_addr);
                fprintf(fp, "             %-9zu  0x%08x    %-18s %-8s ago\n",
                    (size_t) hop->hop_count,
                    neighbor ? neighbor->id : 0,
                    str_addr(&hop->next_hop_addr),
                    str_since(hop->last_updated)
                );
            }
        }
        fprintf(fp, "nodes: %zu, hops: %zu, neighbors: %zu\n",
            node_count, hop_count, neighbor_count);
    } else if (match(argv, "json")) {
        // JSON output
        Root *r = &g_root;

        fprintf(fp, "{\n");
        fprintf(fp, "\"own_id\": \"0x%08x\",\n", gstate.own_id);

        fprintf(fp, "\"dht\": {");
        if (g_dht_prev_set) {
            fprintf(fp, "\"prev\": \"0x%08x\", \"prev_d\": %zu,",
                g_dht_prev, dht_distance(gstate.own_id, g_dht_prev));
        } else {
            fprintf(fp, "\"prev\": null, \"prev_d\": null,");
        }

        if (g_dht_next_set) {
            fprintf(fp, "\"next\": \"0x%08x\", \"next_d\": %zu",
                g_dht_next, dht_distance(gstate.own_id, g_dht_next));
        } else {
            fprintf(fp, "\"next\": null, \"next_d\": null");
        }
        fprintf(fp, "},\n");
        fprintf(fp, "\"root\": {");
        //fprintf(fp, "\"path\": \"0x%08x:[%s]\",", r->root_id, str_path(&r->path, r->path_length));
        fprintf(fp, "\"root_id\": \"0x%08x\", ", r->root_id);
        fprintf(fp, "\"path\": \"%zu\", ", (size_t) r->path_length);
        fprintf(fp, "\"parent\": \"%s\", ", str_addr(&r->parent_addr));
        fprintf(fp, "\"updated\": \"%s\", ", str_since(r->last_updated));
        fprintf(fp, "\"count\": %zu, ", (size_t) r->updated_count);
        fprintf(fp, "\"is_critical\": %s, ", str_bool(g_is_critical));
        fprintf(fp, "\"critical_ago\": \"%s\"", str_since(g_is_critical_time));
        fprintf(fp, "},\n");

        fprintf(fp, "\"packet_trace\": ");
        packet_trace_json(fp);
        fprintf(fp, "\n}");
    } else {
        return false;
    }

    return true;
}

static void init()
{
    uint32_t tms = (uint32_t) rand();
    usleep(tms % 1000);

    set_critical(false);
    reset_root();

    seqnum_cache_init(SEQNUM_CACHE_TIMEOUT_SECONDS);

    // call at least every second
    net_add_handler(-1, &periodic_handler);
}

void trees_0_register()
{
    static const Protocol p = {
        .name = "trees-0",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
    };

    protocols_register(&p);
}
