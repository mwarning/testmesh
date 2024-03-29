#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <inttypes.h>

#include "../ext/utlist.h"
#include "../ext/uthash.h"
#include "../ext/seqnum_cache.h"
#include "../ext/packet_cache.h"
#include "../ext/bloom.h"
#include "../log.h"
#include "../utils.h"
#include "../net.h"
#include "../tun.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

#include "routing.h"

#define BLOOM_M      8  // size of the bloom filter (in bytes)
#define BLOOM_K      2  // number of hash functions


enum {
    TYPE_DATA,
    TYPE_RREQ, // broadcast / unicast
    TYPE_RREP
};

#define TIMEOUT_ROUTING_ENTRY_SEC 20

typedef struct RoutingEntry_ {
    Address next_hop_addr;
    uint16_t hop_count;
    uint64_t first_updated; // == created
    uint64_t last_updated;
    uint8_t bloom[BLOOM_M];
    uint64_t bloom_first_updated;
    uint64_t bloom_last_updated;
    struct RoutingEntry_ *next;
} RoutingEntry;

typedef struct {
    uint32_t dst_id;
    uint16_t seq_num;
    RoutingEntry *entries;
    UT_hash_handle hh;
} RoutingEntries;

typedef struct {
    Address id;
    UT_hash_handle hh;
} AddressSetEntry;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num; // sequence number
    uint32_t src_id;
    uint32_t dst_id;
    uint8_t bloom[BLOOM_M];
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
// {<destiantion id> : [<next-hop-neighbor>]}
static RoutingEntries *g_routing_table = NULL;
//static uint8_t full_flood = 1;
//static uint64_t full_flood_time = 0;
static uint32_t broadcast_capacity = 1;

static size_t get_data_size(DATA *p)
{
    return (sizeof(DATA) + p->payload_length);
}

static uint8_t* get_data_payload(DATA *p)
{
    return ((uint8_t*) p) + sizeof(DATA);
}

// #######################################
// added

static void routing_entry_timeout(RoutingEntries *e)
{
    RoutingEntry *tmp;
    RoutingEntry *cur;

    LL_FOREACH_SAFE(e->entries, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_ROUTING_ENTRY_SEC * 1000) < gstate.time_now) {
            log_debug("timeout routing entry for id 0x%08x / %s", e->dst_id, str_addr(&cur->next_hop_addr));
            LL_DELETE(e->entries, cur);
            free(cur);
        }
   }
}

static void routing_entries_timeout()
{
    RoutingEntries *tmp;
    RoutingEntries *cur;

    HASH_ITER(hh, g_routing_table, cur, tmp) {
        routing_entry_timeout(cur);
        if (cur->entries == NULL) {
            HASH_DEL(g_routing_table, cur);
            free(cur);
        }
    }
}

static RoutingEntries *routing_entries_find(uint32_t dst_id)
{
    RoutingEntries *cur;
    HASH_FIND(hh, g_routing_table, &dst_id, sizeof(uint32_t), cur);
    return cur;
}

static RoutingEntry *routing_entry_find(uint32_t dst_id)
{
    RoutingEntries *es = routing_entries_find(dst_id);
    RoutingEntry *e;
    RoutingEntry *tmp;

    e = NULL;

    if (es) {
        LL_FOREACH(es->entries, tmp) {
            if (e == NULL || tmp->hop_count < e->hop_count) {
                e = tmp;
            }
        }
    }

    return e;
}

#if 0
static RoutingEntry *routing_entry_find2(uint32_t dst_id)
{
    RoutingEntry *e_tmp;
    RoutingEntry *e;
    RoutingEntries *es_tmp;
    RoutingEntries *es;

    e = routing_entry_find(dst_id);
    if (e) {
        return e;
    }

    HASH_ITER(hh, g_routing_table, es, es_tmp) {
        LL_FOREACH(es->entries, e_tmp) {
            /*
                ???
            */
            if (e == NULL || tmp->hop_count < e->hop_count) {
                e = tmp;
            }
        }
    }

    return e;
}
#endif

/*
we want to send a 
*/
static void routing_table_update(uint32_t dst_id, const Address *next_hop_addr,
    uint8_t hop_count, uint16_t seq_num, uint8_t *bloom)
{
    RoutingEntries *es;
    RoutingEntry *e;

    es = routing_entries_find(dst_id);
    if (es == NULL) {
        es = (RoutingEntries*) calloc(1, sizeof(RoutingEntries));
        es->dst_id = dst_id;
        es->seq_num = seq_num;
        HASH_ADD(hh, g_routing_table, dst_id, sizeof(uint32_t), es);
    }

    e = NULL;
    LL_FOREACH(es->entries, e) {
        if (0 == memcmp(&e->next_hop_addr, next_hop_addr, sizeof(Address))) {
            break;
        }
    }

    if (e == NULL) {
        e = (RoutingEntry*) calloc(1, sizeof(RoutingEntry));
        e->next_hop_addr = *next_hop_addr;
        e->first_updated = gstate.time_now;
        LL_PREPEND(es->entries, e);
        e->hop_count = hop_count;
        e->last_updated = gstate.time_now; // updated count more usefull?

        if (bloom) {
            memcpy(&e->bloom, bloom, BLOOM_M);
            e->bloom_first_updated = gstate.time_now;
            e->bloom_last_updated = gstate.time_now;
        }
    } else {
        if (e->hop_count >= hop_count) {
            e->hop_count = hop_count;
            e->last_updated = gstate.time_now;
            if (bloom) {
                memcpy(&e->bloom, bloom, BLOOM_M);
                e->bloom_last_updated = gstate.time_now;
            }
        }
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
        log_debug("send_cached_packet: no cached packet found");
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

static bool neighbor_check_add(AddressSetEntry **neighbors, const Address *addr)
{
    AddressSetEntry *entry = NULL;
    HASH_FIND(hh, *neighbors, addr, sizeof(Address), entry);
    if (entry == NULL) {
        entry = calloc(1, sizeof(AddressSetEntry));
        memcpy(&entry->id, addr, sizeof(Address));
        HASH_ADD(hh, *neighbors, id, sizeof(Address), entry);
        return false;
    } else {
        return true;
    }
}

static void neighbor_check_clear(AddressSetEntry *neighbors)
{
    AddressSetEntry *neighbor;
    AddressSetEntry *tmp;
    HASH_ITER(hh, neighbors, neighbor, tmp) {
        HASH_DEL(neighbors, neighbor);
        free(neighbor);
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

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_trace("RREQ: packet already seen => drop");
        return;
    }

    log_debug("RREQ: got packet: %s / 0x%08x => 0x%08x / hop_count: %u, seq_num: %u",
        str_addr(src), p->src_id, p->dst_id, p->hop_count, p->seq_num);

    routing_table_update(p->src_id, src, p->hop_count, p->seq_num, &p->bloom[0]);

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
        //RoutingEntries *es = routing_entries_find(p->dst_id);
        RoutingEntry *e = routing_entry_find(p->dst_id);
        if (e) {
            if (e->last_updated == gstate.time_now) {
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
            p->hop_count += 1;

            bloom_add(&p->bloom[0], gstate.own_id, BLOOM_M, BLOOM_K);

/*
    
*/
            /*
            * Send as ucast to each neighbor that matches.
            */
            // TODO: do better foreach neighbor
            AddressSetEntry *neighbors = NULL;
            neighbor_check_add(&neighbors, dst); // prevent packet from being send back

            RoutingEntries *es_tmp;
            RoutingEntries *es;
            RoutingEntry *e;
            uint32_t forwarded_count = 0;
            HASH_ITER(hh, g_routing_table, es, es_tmp) {
                /*
                if (bloom_test(&e->bloom[0], p->src_id)) {
                    continue; // hm?
                }
                */
                LL_FOREACH(es->entries, e) {
                    if (bloom_test(&e->bloom[0], p->dst_id, BLOOM_M, BLOOM_K)) {
                        if (!neighbor_check_add(&neighbors, &e->next_hop_addr)) {
                            log_debug("RREQ: forward to %s", str_addr(&e->next_hop_addr));
                            send_ucast_l2(&e->next_hop_addr, p, sizeof(RREQ));
                            forwarded_count += 1;
                        }
                    }
                }
            }

            neighbor_check_clear(neighbors);

            if (forwarded_count > 0) {
                log_debug("RREQ: send to "PRIu32" neighbors => forwarded", forwarded_count);
            } else if(broadcast_capacity > 0) {
                log_debug("RREQ: no next hop neighbor found => broadcast");
                send_bcast_l2(0, p, sizeof(RREQ));
                broadcast_capacity -= 1;
            } else {
                // if we are allowed to broadcast (full broadcast), then broadcast
                log_debug("RREQ: no next hop neighbor found => drop");
            }
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
        log_trace("RREP: packet already seen => drop");
        return;
    }

    log_debug("RREP: got packet: %s / 0x%08x (0x%08x) => 0x%08x / hop_count: %u, seq_num: %u",
        str_addr(src), p->origin_id, p->src_id, p->dst_id, p->hop_count, p->seq_num);

    routing_table_update(p->origin_id, src, p->hop_count, p->seq_num, NULL);

    if (p->dst_id == gstate.own_id) {
        log_debug("RREP: reached destination => send cached packet");
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
        log_trace("DATA: packet already seen => drop");
        return;
    }

    if (p->src_id == gstate.own_id) {
        log_debug("DATA: got packet from own source id => drop");
        return;
    }

    uint8_t *payload = get_data_payload(p);

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x / hop_count: %u",
        str_addr(src), p->src_id, p->dst_id, p->hop_count);

    routing_table_update(p->src_id, src, p->hop_count, p->seq_num, NULL);

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
            .bloom = {0},
        };

        bloom_add(&rreq.bloom[0], gstate.own_id, BLOOM_M, BLOOM_K);

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
        RoutingEntries *tmp;
        RoutingEntries *cur;
        RoutingEntry *e;
        uint32_t d_count;
        uint32_t e_count;

        d_count = 0;
        HASH_ITER(hh, g_routing_table, cur, tmp) {
            fprintf(fp, "destination: 0x%08x, seq_num: %u\n", cur->dst_id, cur->seq_num);
            fprintf(fp, "        [addr]      [hop-count]                            [bloom]                                [first-updated] [last-updated]\n");
            e_count = 0;
            LL_FOREACH(cur->entries, e) {
                fprintf(fp, "  %s %6u      %6s   %8s ago    %8s ago\n",
                    str_addr(&e->next_hop_addr),
                    e->hop_count,
                    str_bloom(&e->bloom[0], BLOOM_M),
                    str_since(e->bloom_first_updated),
                    str_since(e->bloom_last_updated)
                );
                e_count += 1;
            }
            fprintf(fp, "  %u entries\n", e_count);
            d_count += 1;
        }
        fprintf(fp, "%u destinations\n", d_count);
    } else {
        return true;
    }

    return false;
}

static void periodic_handler()
{
    routing_entries_timeout();
    broadcast_capacity = 1;
}

static void init()
{
    net_add_handler(-1, &periodic_handler);
    seqnum_cache_init(20);
    packet_cache_init(20);
}

void aodv_bloom_0_register()
{
    static const Protocol p = {
        .name = "aodv-bloom-0",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
    };

    protocols_register(&p);
}
