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

enum {
    TYPE_DATA,
    TYPE_RREQ,
    TYPE_RREP
};

#define HOP_TIMEOUT_MIN_SECONDS (10)
#define HOP_TIMEOUT_MAX_SECONDS (60 * 60 * 24)
#define TRAFFIC_TIMEOUT_MAX_SECONDS (60 * 60 * 24)
#define TRAFFIC_DEGRADE_SECONDS (10)
#define MIN_BROADCAST_PACKETS_PER_SECONDS (1)
#define MIN_BROADCAST_PACKETS_PERCENT (5)

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

// per interface
typedef struct {
    uint32_t ifindex;
    uint16_t received_broadcast_packets;
    uint16_t received_unicast_packets;
    uint16_t send_broadcast_packets;
    uint16_t send_unicast_packets;
    time_t time_broadcast_send;
    time_t time_updated;
    UT_hash_handle hh;
} TrafficByIfindex;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
} RREQ;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
} RREP;

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
static TrafficByIfindex *g_traffic = NULL;
static Node *g_nodes = NULL;

// called once per seond
static void traffic_timeout()
{
    static time_t g_traffic_last_degraded = 0;
    const time_t time_now = gstate.time_now;

    bool degrade = ((time_now - g_traffic_last_degraded) > TRAFFIC_DEGRADE_SECONDS);

    TrafficByIfindex *cur;
    TrafficByIfindex *tmp;
    HASH_ITER(hh, g_traffic, cur, tmp) {
        if ((time_now - cur->time_updated) > TRAFFIC_TIMEOUT_MAX_SECONDS) {
            HASH_DEL(g_traffic, cur);
            free(cur);
        } else if (degrade) {
            cur->received_broadcast_packets /= 2;
            cur->received_unicast_packets /= 2;
            cur->send_broadcast_packets /= 2;
            cur->send_unicast_packets /= 2;
        }
    }

    if (degrade) {
        g_traffic_last_degraded = time_now;
    }
}

static TrafficByIfindex *traffic_find(const uint32_t ifindex)
{
    TrafficByIfindex *traffic = NULL;
    HASH_FIND(hh, g_traffic, &ifindex, sizeof(uint32_t), traffic);
    return traffic;
}

static void traffic_remove(const uint32_t ifindex)
{
    TrafficByIfindex *traffic = traffic_find(ifindex);
    if (traffic != NULL) {
        // remove entry
        HASH_DEL(g_traffic, traffic);
        free(traffic);
    }
}

static TrafficByIfindex *traffic_create(const uint32_t ifindex)
{
    TrafficByIfindex *traffic = traffic_find(ifindex);
    if (traffic == NULL) {
        // add new entry
        traffic = (TrafficByIfindex*) calloc(1, sizeof(TrafficByIfindex));
        traffic->ifindex = ifindex;
        traffic->time_updated = gstate.time_now;
        HASH_ADD(hh, g_traffic, ifindex, sizeof(uint32_t), traffic);
    }
    return traffic;
}

// create non-existing entries
static TrafficByIfindex *traffic_get(const uint32_t ifindex)
{
    TrafficByIfindex *traffic = traffic_find(ifindex);
    return traffic ? traffic : traffic_create(ifindex);
}

static void count_broadcast_traffic(TrafficByIfindex *traffic, uint32_t send_bytes, uint32_t received_bytes)
{
    // send bytes
    if (send_bytes > 0) {
        const uint32_t n = 1 + send_bytes / 512;
        traffic->send_broadcast_packets += n;
        traffic->time_updated = gstate.time_now;
        traffic->time_broadcast_send = gstate.time_now;
    }

    // received bytes
    if (received_bytes > 0) {
        const uint32_t n = 1 + received_bytes / 512;
        traffic->received_broadcast_packets += n;
        traffic->time_updated = gstate.time_now;
    }
}

static void count_unicast_traffic(TrafficByIfindex *traffic, uint32_t send_bytes, uint32_t received_bytes)
{
    // send bytes
    if (send_bytes > 0) {
        const uint32_t n = 1 + send_bytes / 512;
        traffic->send_unicast_packets += n;
    }

    // received bytes
    if (received_bytes > 0) {
        const uint32_t n = 1 + received_bytes / 512;
        traffic->received_unicast_packets += n;
    }

    if (send_bytes > 0 || received_bytes > 0) {
        traffic->time_updated = gstate.time_now;
    }
}

// send and count outgoing broadcast traffic
static void send_bcast_l2_wrapper(const void* data, size_t data_len)
{
    if (g_traffic == NULL) {
        // we create entries only on received broadcast
        // TODO: add interfaces via callback?
        send_bcast_l2(0, data, data_len);
        // we do not count this one as we already add 1 in the other branch
        // for statistics only
        g_broadcast_send_counter += 1;
    } else {
        TrafficByIfindex *cur;
        TrafficByIfindex *tmp;
        HASH_ITER(hh, g_traffic, cur, tmp) {
            uint32_t bpackets = cur->received_broadcast_packets;
            uint32_t upackets = cur->received_unicast_packets;

            size_t pc = (100 * (1 + bpackets)) / (1 + bpackets + upackets);
            time_t last_broadcast = (gstate.time_now - cur->time_broadcast_send);

            if (pc <= MIN_BROADCAST_PACKETS_PERCENT
                    || last_broadcast > MIN_BROADCAST_PACKETS_PER_SECONDS) {
                log_debug("send_bcast_l2_wrapper() ifname: %s, bpackets: %zu (%zu%%), upackets: %zu, last_broadcast: %s ago => send",
                        str_ifindex(cur->ifindex), (size_t) bpackets, pc, (size_t) upackets, str_time(last_broadcast));

                send_bcast_l2(cur->ifindex, data, data_len);
                count_broadcast_traffic(cur, data_len, 0);

                // for statistics only
                g_broadcast_send_counter += 1;
            } else {
                log_debug("send_bcast_l2_wrapper() ifname: %s, bpackets: %zu (%zu%%), upackets: %zu, last_broadcast: %s ago => drop",
                        str_ifindex(cur->ifindex), (size_t) bpackets, pc, (size_t) upackets, str_time(last_broadcast));

                // for statistics only
                g_broadcast_dropped_counter += 1;
            }
        }
    }
}

// send and count outgoing unicast traffic
static void send_ucast_l2_wrapper(const Address *next_hop_addr, const void* data, size_t data_len)
{
    send_ucast_l2(next_hop_addr, data, data_len);

    uint32_t ifindex = address_ifindex(next_hop_addr);
    TrafficByIfindex *traffic = traffic_get(ifindex);
    count_unicast_traffic(traffic, data_len, 0);
}

static int is_newer_seqnum(uint16_t cur, uint16_t new)
{
    if (cur >= new) {
        return (cur - new) > 0x7fff;
    } else {
        return (new - cur) < 0x7fff;
    }
}

static bool seqnum_check(uint32_t id, uint16_t seq_num)
{
    Node *node;

    HASH_FIND(hh, g_nodes, &id, sizeof(uint32_t), node);

    if (node) {
        if (is_newer_seqnum(node->seq_num, seq_num)) {
            node->seq_num = seq_num;
            return true; // new sequence number
        } else {
            return false; // old sequence number, packet is a duplicate
        }
    } else {
        return true;
    }
}

static void nodes_update(uint32_t id, const Address *addr, uint16_t hop_count, uint16_t seq_num)
{
    log_debug("nodes_update() id: 0x%08x, addr: %s, hop_count: %zu, seq_num: %zu",
        id, str_addr(addr), (size_t) hop_count, (size_t) seq_num);

    // ignore own id
    if (id == gstate.own_id) {
        // should not happen (atm. it can)
        log_error("nodes_update() got own id => ignore");
        return;
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
        hop->time_created = gstate.time_now;
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
        // timeout hops
        HASH_ITER(hh, ncur->hops, hcur, htmp) {
            /*
             * Dynamic Timeout - The longer a hop is used, the longer the timeout.
            */
            const uint32_t age1 = hcur->time_updated - hcur->time_created;
            const uint32_t age2 = time_now - hcur->time_updated;
            if (age2 > HOP_TIMEOUT_MIN_SECONDS
                && ((age2 > HOP_TIMEOUT_MAX_SECONDS) || (age1 < age2))) {
                log_debug("timeout hop %s (age1: %s, age2: %s)",
                    str_addr(&hcur->next_hop_addr), str_time(age1), str_time(age2));
                HASH_DEL(ncur->hops, hcur);

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
    traffic_timeout();
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

            // avoid processing of this packet again
            seqnum_check(data->src_id, data->seq_num);

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

static void handle_RREQ(const Address *rcv, const Address *src, const Address *dst, RREQ *p, size_t length)
{
    // we expect broadcasts or packets for us
    if (!(address_is_broadcast(dst) || address_equal(rcv, dst))) {
        log_trace("RREP: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(RREQ)) {
        log_debug("RREQ: invalid packet size => drop");
        return;
    }

    if (!seqnum_check(p->src_id, p->seq_num)) {
        log_debug("RREQ: packet already seen => drop");
        return;
    }

    log_debug("RREQ: got packet: %s / 0x%08x => 0x%08x / hop_count: %zu, seq_num: %zu",
        str_addr(dst), p->src_id, p->dst_id, (size_t) p->hop_count, (size_t) p->seq_num);

    nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num);

    if (p->dst_id == gstate.own_id) {
        log_debug("RREQ: destination reached => send RREP");
        RREP rrep = {
            .type = TYPE_RREP,
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
        };

        seqnum_check(rrep.src_id, rrep.seq_num);

        // send back unicast
        send_ucast_l2_wrapper(src, &rrep, sizeof(rrep));
    } else {
        p->hop_count += 1;
        send_bcast_l2_wrapper(p, length);
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

    if (!seqnum_check(p->src_id, p->seq_num)) {
        log_debug("RREP: packet already seen => drop");
        return;
    }

    log_debug("RREP: got packet: %s / 0x%08x => 0x%08x / hop_count: %zu, seq_num: %zu",
        str_addr(src), p->src_id, p->dst_id, (size_t) p->hop_count, (size_t) p->seq_num);

    nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num);

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

    if (!seqnum_check(p->src_id, p->seq_num)) {
        log_debug("DATA: packet already seen => drop");
        return;
    }

    if (p->src_id == gstate.own_id) {
        log_debug("DATA: got packet from own source id => drop");
        return;
    }

    uint8_t *payload = get_data_payload(p);

    packet_trace_set("FORWARD", payload, p->payload_length);

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x / hop_count: %zu",
        str_addr(src), p->src_id, p->dst_id, (size_t) p->hop_count);

    nodes_update(p->src_id, src, p->hop_count + 1, p->seq_num);

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

        // avoid processing of this packet again (stores sequence number)
        seqnum_check(data->src_id, data->seq_num);

        log_debug("tun_handler: send DATA packet (0x%08x => 0x%08x) to %s, hop_count: %zu",
            data->src_id, data->dst_id, str_addr(&hop->next_hop_addr), (size_t) hop->hop_count);

        send_ucast_l2_wrapper(&hop->next_hop_addr, data, get_data_size(data));
    } else {
        RREQ rreq = {
            .type = TYPE_RREQ,
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = dst_id,
        };

        // avoid processing of this packet again
        seqnum_check(rreq.src_id, rreq.seq_num);

        packet_cache_add(dst_id, packet, packet_length);

        log_debug("tun_handler: send RREQ packet (0x%08x => 0x%08x)", rreq.src_id, rreq.dst_id);

        send_bcast_l2_wrapper(&rreq, sizeof(RREQ));
    }
}

static bool interface_handler(uint32_t ifindex, bool added)
{
    if (added) {
        traffic_create(ifindex);
    } else {
        traffic_remove(ifindex);
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
    uint32_t ifindex = address_ifindex(src); // TODO: check if we get the ifindex or just 0!
    TrafficByIfindex *traffic = traffic_get(ifindex);
    if (is_broadcast) {
        count_broadcast_traffic(traffic, 0, packet_length);
    } else {
        count_unicast_traffic(traffic, 0, packet_length);
    }

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
        fprintf(fp, "TRAFFIC_TIMEOUT_MAX: %s\n", str_time(TRAFFIC_TIMEOUT_MAX_SECONDS));
        fprintf(fp, "TRAFFIC_DEGRADE:  %s\n", str_time(TRAFFIC_DEGRADE_SECONDS));
    } else if (match(argv, "r")) {
        Node *ncur;
        Node *ntmp;
        Hop *hcur;
        Hop *htmp;
        size_t node_count = 0;
        size_t hop_count = 0;
        size_t neighbor_count = 0;

        fprintf(fp, "hop-nodes:\n");
        fprintf(fp, " id          hop-count  next-hop-id   next-hop-address   last-updated\n");
        HASH_ITER(hh, g_nodes, ncur, ntmp) {
            node_count += 1;
            fprintf(fp, " 0x%08x\n", ncur->id);
            HASH_ITER(hh, ncur->hops, hcur, htmp) {
                hop_count += 1;
                neighbor_count += (hcur->hop_count == 1);
                Node *node = find_node_by_address(&hcur->next_hop_addr);
                fprintf(fp, "             %-9zu  0x%08x    %-18s %-8s ago\n",
                    (size_t) hcur->hop_count,
                    node ? node->id : 0,
                    str_addr(&hcur->next_hop_addr),
                    str_ago(hcur->time_updated)
                );
            }
        }
        fprintf(fp, "nodes: %zu, hops: %zu, neighbors: %zu\n",
            node_count, hop_count, neighbor_count);
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

void ratelimit_0_register()
{
    static const Protocol p = {
        .name = "ratelimit-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
        .interface_handler = &interface_handler
    };

    protocols_register(&p);
}
