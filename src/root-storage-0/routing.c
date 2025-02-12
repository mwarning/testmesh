#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <assert.h>

#include "../ext/packet_cache.h"
#include "../ext/packet_trace.h"
#include "../log.h"
#include "../net.h"
#include "../tun.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"
#include "../utils.h"
#include "../address.h"

#include "routing.h"
#include "packets.h"
#include "tree.h"
#include "peers.h"
#include "ifstates.h"
#include "neighbors.h"
#include "console.h"
#include "nodes.h"


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
    Hop *hop_tmp;
    Hop *best = NULL;
    HASH_ITER(hh, node->hops, hop, hop_tmp) {
        if (is_better_hop(best, hop)) {
            best = hop;
        }
    }

    return best;
}

static size_t get_size_DATA(const DATA *p)
{
    return (offsetof(DATA, payload_data) + p->payload_length);
}

static uint8_t* get_payload_DATA(DATA *p)
{
    return ((uint8_t*) p) + offsetof(DATA, payload_data);
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
            p->seq_num = packets_next_sequence_number();
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

// called once every second!
static void periodic_handler()
{
    neighbors_periodic();
    nodes_periodic();
    tree_periodic();
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
    if (packets_is_duplicate(p->src_id, p->seq_num)) {
        log_trace("PING: packet is old => drop");
        return;
    }*/

    log_debug("PING: got packet from %s, seq_num: %d => send pong", str_addr(src), p->seq_num);

    PONG pong = {
        .type = TYPE_PONG,
        .seq_num = packets_next_sequence_number(),
    };

    send_ucast_wrapper(src, &pong, sizeof(PONG));
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

    if (length != sizeof(PONG)) {
        log_debug("PONG: invalid packet size => drop");
        return;
    }

    // packet has done its job (neighbor timeone postponed)
    log_debug("PONG: got packet from %s, seq_num: %d => accept", str_addr(src), p->seq_num);
}

static uint64_t map_exp_to_time(uint8_t exp)
{
    return (1ULL << exp);
}

static uint8_t map_time_to_exp(uint64_t value)
{
    return highest_bit(value);
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

    if (p->hop_count == 0) {
        log_debug("RREP2: invalid hop count => drop");
        return;
    }

    if (packets_is_duplicate(p->src_id, p->seq_num)) {
        log_debug("RREP2: packet is old => drop (src_id: 0x%08x, seq_num: %d)", p->src_id, (int) p->seq_num);
        return;
    }

    // add information about originator node
    nodes_update(p->src_id, src, p->hop_count, p->seq_num, 0);
    // add information from originator node about requested node
    nodes_update(p->req_id, src, p->hop_count + p->req_hops, p->req_seq_num, map_exp_to_time(p->req_age_exp));

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->req_id);
        log_RREP2("RREP2: destination reached", p, "send cached packet");
    } else {
        Node *node = next_node_by_id(p->dst_id);
        Hop *hop = next_hop_by_node(node);
        if (node && hop) {
            p->hop_count = MIN(p->hop_count + 1U, UINT8_MAX);
            send_ucast_wrapper(&hop->next_hop_addr, p, sizeof(RREP2));

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

    if (p->hop_count == 0) {
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
            p->hop_count += MIN(p->hop_count + 1U, UINT8_MAX);
            send_ucast_wrapper(&hop->next_hop_addr, p, get_size_DATA(p));
        } else {
            log_debug("DATA: got packet 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, no next hop known => drop and send RERR",
                p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num);

            RERR ur = {
                .type = TYPE_RERR,
                .seq_num = packets_next_sequence_number(),
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

    if (length != sizeof(RREP)) {
        log_debug("RREP: invalid packet size => drop");
        return;
    }

    if (p->hop_count == 0) {
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

            p->hop_count = MIN(p->hop_count + 1U, UINT8_MAX);
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
    HASH_ITER(hh, neighbors_all(), neighbor, tmp) {
        if (neighbor != from && ranges_contains_id(&neighbor->ranges, p->dst_id)) {
            log_debug("[%d] %s: 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, found routing hint, send to %s => forward",
                counter, context, p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num, str_addr(&neighbor->address));
            send_ucast_wrapper(&neighbor->address, p, sizeof(RREQ));
            counter += 1;
        }
    }

/*
how do we handle false positives?
*/

    if (counter == 0) {
        // route towards parent as well
        Neighbor *parent = tree_get_parent(neighbors_all());
        if (parent) {
            if (parent != neighbor) {
                log_debug("[0] %s: 0x%08x => 0x%08x, hop_count: %d, seq_num: %d, send to parent %s => forward",
                    context, p->src_id, p->dst_id, (int) p->hop_count, (int) p->seq_num, str_addr(&parent->address));
                send_ucast_wrapper(&parent->address, p, sizeof(RREQ));
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

static void handle_RREQ(Neighbor *neighbor, const Address *src, uint8_t flags, RREQ *p, size_t length)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    if (is_broadcast || !is_destination) {
        log_trace("RREQ: unexpected destination => drop");
        return;
    }

    if (length != sizeof(RREQ)) {
        log_debug("RREQ: invalid packet size (%d != %d) => drop", (int) length, (int) sizeof(RREQ));
        return;
    }

    if (p->hop_count == 0) {
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
            .seq_num = packets_next_sequence_number(),
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
        };

        // send back unicast
        send_ucast_wrapper(src, &rrep, sizeof(RREP));

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
            uint8_t milli_seconds_exponent = 1 + map_time_to_exp(gstate.time_now - hop->time_updated);
            RREP2 rrep2 = {
                .type = TYPE_RREP2,
                .hop_count = 1,
                .seq_num = packets_next_sequence_number(),
                .src_id = gstate.own_id,
                .dst_id = p->src_id,
                .req_id = p->dst_id,
                .req_seq_num = node->seq_num,
                .req_hops = hop->hop_count + 1U, // or use hop_count from RREQ?
                .req_age_exp = milli_seconds_exponent,
            };

            send_ucast_wrapper(src, &rrep2, sizeof(RREP2));

            log_debug("RREQ: 0x%08x => 0x%08x, seq_num: %d destination known => send RREP2 (0x%08x => 0x%08x, seq_num: %d, hop_count: %d)",
                p->src_id, p->dst_id, (int) p->seq_num, (int) rrep2.src_id, rrep2.dst_id, (int) rrep2.seq_num, (int) rrep2.hop_count);
        } else {
            p->hop_count = MIN(p->hop_count + 1U, UINT8_MAX);
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

    if (packets_is_duplicate(p->src_id, p->seq_num)) {
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
                    nodes_remove(unreachable_node);
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
            p->hop_count = MIN(p->hop_count + 1U, UINT8_MAX);

            send_ucast_wrapper(&hop->next_hop_addr, p, length);
        } else {
            log_debug("RERR: 0x%08x => 0x%08x, seq_num: %d, no next hop found => drop",
                p->src_id, p->dst_id, p->seq_num);
        }
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
        p->seq_num = packets_next_sequence_number();
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
            .seq_num = packets_next_sequence_number(),
            .src_id = gstate.own_id,
            .dst_id = dst_id
        };

        send_RREQ("tun_handler() send RREQ", NULL, &p);
    }
}

// called once for added/removed interfaces
static bool interface_handler(uint32_t ifindex, const char *ifname, bool added)
{
    //log_info("interface_handler() %s ifname %s", added ? "add" : "remove", ifname);

    if (added) {
        ifstates_create(ifindex);
        // TODO: we added a new interface, but are we root on each interface?
        // we want to send out the ROOT_CREATE packet on new interfaces
        // we need to improve awareness for send_ROOT_CREATE_periodic() of interfaces
        //send_ROOT_CREATE_periodic();
        tree_periodic(); // to call send_ROOT_CREATE();
    } else {
        ifstates_remove(ifindex);
    }

    return true;
}

static Neighbor *neighbors_access(const Address *src, uint8_t flags)
{
    bool is_broadcast = flags & FLAG_IS_BROADCAST;
    bool is_destination = flags & FLAG_IS_DESTINATION;

    Neighbor *neighbor = neighbors_get(src);
    if (is_destination || is_broadcast) {
        // packet is for us or (unicast or broadcast)
        neighbor->pinged = 0;
    }
    neighbor->time_updated = gstate.time_now;

    return neighbor;
}

static void ext_handler(const Address *src, uint8_t flags, uint8_t *packet, size_t packet_length)
{
    // check minimum packet size
    if (packet_length < 2) {
        return;
    }

    uint16_t type = *((uint16_t*) &packet[0]);

    IFState *ifstate = ifstates_get(src); // get and create
    Neighbor *neighbor = neighbors_access(src, flags);

    // count incoming traffic
    record_traffic_by_addr(src, 0, packet_length);

    switch (type) {
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
        log_warning("unknown packet type 0x%04x of size %zu from %s", type, packet_length, str_addr(src));
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

static void init_handler()
{
    if (!ranges_sanity_test()) {
        log_error("Ranges sanity test failed!");
        exit(1);
    }

    tree_init();

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
