#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#include "../ext/uthash.h"
#include "../ext/seqnum_cache.h"
#include "../ext/packet_cache.h"
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
    TYPE_RREQ, // broadcast / unicast
    TYPE_RREP
};

#define TIMEOUT_ROUTING_ENTRY_SEC 20

typedef struct {
    uint32_t dst_id;
    Address next_hop_addr;
    uint16_t hop_count;
    uint16_t seq_num;
    uint64_t last_updated;
    UT_hash_handle hh;
} RoutingEntry;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num; // sequence number
    uint32_t src_id;
    uint32_t dst_id;
} RREQ;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num; // sequence number
    uint32_t origin_id;
    uint32_t src_id;
    uint32_t dst_id;
} RREP;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num; // sequence number - needed?
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t payload_length;
    //uint8_t payload[ETH_FRAME_LEN - sizeof(DATA)];
} DATA;

static uint16_t g_sequence_number = 0;
static RoutingEntry *g_routing_entries = NULL;

static size_t get_data_size(DATA *p)
{
    return (sizeof(DATA) + p->payload_length);
}

static uint8_t* get_data_payload(DATA *p)
{
    return ((uint8_t*) p) + sizeof(DATA);
}

static void routing_entry_timeout()
{
    RoutingEntry *tmp;
    RoutingEntry *cur;

    HASH_ITER(hh, g_routing_entries, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_ROUTING_ENTRY_SEC * 1000) < gstate.time_now) {
            log_debug("timeout routing entry for id 0x%08x", cur->dst_id);
            HASH_DEL(g_routing_entries, cur);
            free(cur);
        }
    }
}

static RoutingEntry *routing_entry_find(uint32_t dst_id)
{
    RoutingEntry *cur;
    HASH_FIND(hh, g_routing_entries, &dst_id, sizeof(uint32_t), cur);
    return cur;
}

static void routing_entry_update(uint32_t dst_id, const Address *next_hop_addr,
    uint8_t hop_count, uint16_t seq_num)
{
    RoutingEntry *e;

    e = routing_entry_find(dst_id);
    if (e) {
        if (hop_count < e->hop_count) {
            e->dst_id = dst_id;
            e->next_hop_addr = *next_hop_addr;
            e->seq_num = seq_num;
            e->hop_count = hop_count;
            e->last_updated = gstate.time_now;
        }
    } else {
        e = (RoutingEntry*) malloc(sizeof(RoutingEntry));

        e->dst_id = dst_id;
        e->next_hop_addr = *next_hop_addr;
        e->seq_num = seq_num;
        e->hop_count = hop_count;
        e->last_updated = gstate.time_now;

        HASH_ADD(hh, g_routing_entries, dst_id, sizeof(uint32_t), e);
    }
}

static void send_cached_packet(uint32_t dst_id, const Address *next_hop_addr)
{
    uint8_t buffer[ETH_FRAME_LEN - sizeof(DATA)];
    DATA *data = (DATA*) &buffer[0];

    uint8_t* data_payload = get_data_payload(data);
    size_t data_payload_length = 0;
    packet_cache_get_and_remove(data_payload, &data_payload_length, dst_id);

    if (data_payload_length == 0) {
        // no cached packet found
        return;
    }

    data->type = TYPE_DATA;
    data->hop_count = 0,
    data->seq_num = g_sequence_number++;
    data->src_id = gstate.own_id;
    data->dst_id = dst_id;
    data->payload_length = data_payload_length;

    // avoid processing of this packet again
    seqnum_cache_update(data->src_id, data->seq_num);

    log_debug("send DATA (0x%08x => 0x%08x) to %s via next hop %s",
        data->src_id, data->dst_id, str_addr(next_hop_addr));

    send_ucast_l2(next_hop_addr, data, get_data_size(data));
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

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_debug("RREQ: packet already seen => drop");
        return;
    }

    log_debug("RREQ: got packet: %s / 0x%08x => 0x%08x / hop_count: %u, seq_num: %u",
        str_addr(src), p->src_id, p->dst_id, p->hop_count, p->seq_num);

    routing_entry_update(p->src_id, src, p->hop_count, p->seq_num);

    if (p->dst_id == gstate.own_id) {
        log_debug("RREQ: destination reached => send RREP");

        RREP rrep = {
            .type = TYPE_RREP,
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .origin_id = gstate.own_id,
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
        };

        seqnum_cache_update(rrep.src_id, rrep.seq_num);

        send_ucast_l2(src, &rrep, sizeof(rrep));
    } else {
        RoutingEntry *e = routing_entry_find(p->dst_id);
        if (e) {
            if (e->last_updated / 1000 == gstate.time_now / 1000) {
                log_debug("RREQ: just heard from destination => send RREP");
                RREP rrep = {
                    .type = TYPE_RREP,
                    .hop_count = e->hop_count,
                    .seq_num = g_sequence_number++,
                    .origin_id = gstate.own_id,
                    .src_id = p->dst_id,
                    .dst_id = p->src_id,
                };
                seqnum_cache_update(rrep.src_id, rrep.seq_num);

                send_ucast_l2(src, &rrep, sizeof(rrep));
            } else {
                log_debug("RREQ: found destination => unicast forward");
                p->hop_count += 1;
                send_ucast_l2(&e->next_hop_addr, p, sizeof(RREQ));
            }
        } else {
            log_debug("RREQ: found destination => broadcast forward");
            p->hop_count += 1;
            send_bcast_l2(0, p, sizeof(RREQ));
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

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_debug("RREP: packet already seen => drop");
        return;
    }

    log_debug("RREP: got packet: %s / 0x%08x (0x%08x) => 0x%08x / hop_count: %u, seq_num: %u",
        str_addr(src), p->origin_id, p->src_id, p->dst_id, p->hop_count, p->seq_num);

    routing_entry_update(p->origin_id, src, p->hop_count, p->seq_num);

    if (p->dst_id == gstate.own_id) {
        send_cached_packet(p->src_id, src);
    } else {
        RoutingEntry *e = routing_entry_find(p->dst_id);
        if (e) {
            log_debug("RREP: send to %s => forward", str_addr(&e->next_hop_addr));
            p->hop_count += 1;
            send_ucast_l2(&e->next_hop_addr, p, sizeof(RREP));
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

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_debug("DATA: packet already seen => drop");
        return;
    }

    if (p->src_id == gstate.own_id) {
        log_debug("DATA: got packet from own source id => drop");
        return;
    }

    uint8_t *payload = get_data_payload(p);

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x / hop_count: %u",
        str_addr(src), p->src_id, p->dst_id, p->hop_count);

    routing_entry_update(p->src_id, src, p->hop_count, p->seq_num);

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: reached destination => accept");
        // destination is the local tun0 interface => write packet to tun0
        tun_write(payload, p->payload_length);
    } else {
        RoutingEntry *e = routing_entry_find(p->dst_id);
        if (e) {
            p->hop_count += 1;
            log_debug("DATA: send to next hop %s => forward", str_addr(&e->next_hop_addr));
            // forward
            send_ucast_l2(&e->next_hop_addr, p, get_data_size(p));
        } else {
            log_debug("DATA: no next hop found => drop");
        }
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    RoutingEntry *e = routing_entry_find(dst_id);
    if (e) {
        DATA *data = (DATA*) (packet - sizeof(DATA));

        data->type = TYPE_DATA;
        data->seq_num = g_sequence_number++;
        data->src_id = gstate.own_id;
        data->dst_id = dst_id;
        data->payload_length = packet_length;

        // avoid processing of this packet again
        seqnum_cache_update(data->src_id, data->seq_num);

        log_debug("tun_handler: send DATA packet (0x%08x => 0x%08x) to %s",
            data->src_id, data->dst_id, str_addr(&e->next_hop_addr));

        send_ucast_l2(&e->next_hop_addr, data, get_data_size(data));
    } else {
        RREQ rreq = {
            .type = TYPE_RREQ,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = dst_id,
        };

        // avoid processing of this packet again
        seqnum_cache_update(rreq.src_id, rreq.seq_num);

        packet_cache_add(dst_id, packet, packet_length);

        log_debug("tun_handler: send RREQ packet (0x%08x => 0x%08x)", rreq.src_id, rreq.dst_id);

        send_bcast_l2(0, &rreq, sizeof(RREQ));
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

static bool console_handler(FILE* fp, int argc, const char *argv[])
{
    if (match(argv, "h")) {
        fprintf(fp, "r                       print routing table\n");
    } else if (match(argv, "i")) {
        fprintf(fp, "routing entry timeout: %us\n", TIMEOUT_ROUTING_ENTRY_SEC);
    } else if (match(argv, "r")) {
        RoutingEntry *cur;
        RoutingEntry *tmp;
        uint32_t count = 0;

        fprintf(fp, "dst_id\t\tseq_num\tnext_hop\t\tlast_updated\n");
        HASH_ITER(hh, g_routing_entries, cur, tmp) {
            fprintf(fp, "0x%08x\t%u\t%s\t%s ago\n",
                cur->dst_id,
                cur->seq_num,
                str_addr(&cur->next_hop_addr),
                str_since(cur->last_updated)
            );
            count += 1;
        }
        fprintf(fp, "%d entries\n", count);
    } else {
        return false;
    }

    return true;
}

static void init()
{
    net_add_handler(-1, &routing_entry_timeout);
    seqnum_cache_init(20);
    packet_cache_init(20);
}

void aodv_1_register()
{
    static const Protocol p = {
        .name = "aodv-1",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
    };

    protocols_register(&p);
}
