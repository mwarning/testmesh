#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#include "../ext/bloom.h"
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

#define BLOOM_M      8  // size of the bloom filter (in bytes)
#define BLOOM_K      2  // number of hash functions

#define TIMEOUT_ENTRY_SEC 60
#define BLOOM_LIMIT 50  // limit for the bloom filter (in percent)

enum {
    TYPE_DATA,
};

typedef struct {
    uint32_t sender_id; // we can use the sender address here instead
    Address addr;
    uint8_t bloom[BLOOM_M];
    uint8_t hop_cnt;
    uint64_t last_updated;
    UT_hash_handle hh;
} Entry;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t sender_id; // not needed, but useful for debugging
    uint32_t dst_id;
    uint8_t bloom[BLOOM_M];
    uint8_t hop_cnt; // we usually want a bandwidth metric here
    uint16_t seq_num; // not needed, but useful for debugging
    uint16_t payload_length;
    //uint8_t payload[ETH_FRAME_LEN]; // invisible
} DATA;

static Entry *g_neighbors = NULL;
static uint16_t g_seq_num = 0;

static uint8_t *get_data_payload(const DATA *data)
{
    return ((uint8_t*) data) + sizeof(DATA);
}

static size_t get_data_size(const DATA *data)
{
    return sizeof(DATA) + data->payload_length;
}

static const char *address_type_str(const Address *addr)
{
    if (address_is_broadcast(addr)) {
        return "broadcast";
    } else if (address_is_multicast(addr)) {
        return "multicast";
    } else {
        return "unicast";
    }
}

static void entry_timeout()
{
    Entry *tmp;
    Entry *cur;

    HASH_ITER(hh, g_neighbors, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_ENTRY_SEC * 1000) <= gstate.time_now) {
            log_debug("timeout entry 0x%08x", cur->sender_id);
            HASH_DEL(g_neighbors, cur);
            free(cur);
        }
    }
}

static Entry *entry_find(uint32_t sender_id)
{
    Entry *cur;
    HASH_FIND(hh, g_neighbors, &sender_id, sizeof(uint32_t), cur);
    return cur;
}

static Entry *entry_add(uint32_t sender_id, uint8_t hop_cnt, uint8_t *bloom, const Address *addr)
{
    Entry *e = (Entry*) malloc(sizeof(Entry));

    e->sender_id = sender_id;
    memcpy(&e->bloom, bloom, sizeof(e->bloom));
    memcpy(&e->addr, addr, sizeof(Address));
    e->hop_cnt = hop_cnt;
    e->last_updated = gstate.time_now;

    HASH_ADD(hh, g_neighbors, sender_id, sizeof(uint32_t), e);

    return e;
}

static void forward_DATA(DATA *p, size_t recv_len)
{
    // find best neighbor
    Entry *next = NULL;
    Entry *cur;
    Entry *tmp;

    // find neighbor that is nearest
    HASH_ITER(hh, g_neighbors, cur, tmp) {
        if (bloom_test(&cur->bloom[0], p->dst_id, BLOOM_M, BLOOM_K)) {
            if (next == NULL || cur->hop_cnt < next->hop_cnt) {
                next = cur;
            }
        }
    }

    if (next) {
        log_debug("DATA: send as unicast to 0x%08x (seq_num: %d, hop_cnt: %d)",
            next->sender_id, (int) p->seq_num, (int) p->hop_cnt);
        send_ucast_l2(&next->addr, p, recv_len);
    } else {
        log_debug("DATA: send as broadcast (seq_num: %d, hop_cnt: %d)",
            (int) p->seq_num, (int) p->hop_cnt);
        send_bcast_l2(0, p, recv_len);
    }
}

static void handle_DATA(const Address *src_addr, DATA *p, size_t recv_len)
{
    if (recv_len < sizeof(DATA) || recv_len != get_data_size(p)) {
        log_debug("DATA: invalid size => drop");
        return;
    }

    // reduce log noise
    if (p->sender_id == gstate.own_id) {
        return;
    }

    uint8_t *payload = get_data_payload(p);

    log_debug("DATA: got packet from neighbor 0x%08x => 0x%08x (seq_num: %d, hop_cnt: %d)",
        p->sender_id, p->dst_id, (int) p->seq_num, (int) p->hop_cnt);

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: write %u bytes to %s => accept", (unsigned) p->payload_length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        tun_write(payload, p->payload_length);
        return;
    }

    if (bloom_test(&p->bloom[0], gstate.own_id, BLOOM_M, BLOOM_K)) {
        log_debug("DATA: own id in packets bloom filter => drop");
        return;
    }

    // limit bloom filter fill rate to BLOOM_LIMIT percent
    if (bloom_ones(&p->bloom[0], BLOOM_M) > (int) ((BLOOM_M * 8) * BLOOM_LIMIT) / 100) {
        log_debug("DATA: bloom filter occupancy reached => drop");
        return;
    }

    Entry *entry = entry_find(p->sender_id);
    if (entry) {
        memcpy(&entry->addr, src_addr, sizeof(entry->addr));
        bloom_merge(&entry->bloom[0], &p->bloom[0], BLOOM_M);
    } else {
        entry_add(p->sender_id, p->hop_cnt, &p->bloom[0], src_addr);
    }

    // add own id
    bloom_add(&p->bloom[0], gstate.own_id, BLOOM_M, BLOOM_K);

    p->hop_cnt += 1;

    log_debug("DATA: not for us => forward");

    forward_DATA(p, recv_len);
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    DATA *data = (DATA*) (packet - sizeof(DATA));

    data->type = TYPE_DATA;
    data->sender_id = gstate.own_id;
    data->hop_cnt = 0;
    data->seq_num = g_seq_num++;
    data->dst_id = dst_id;
    data->payload_length = packet_length;
    bloom_init(&data->bloom[0], gstate.own_id, BLOOM_M, BLOOM_K);

    forward_DATA(data, get_data_size(data));
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    if (!address_is_broadcast(dst) && !address_equal(dst, rcv)) {
        // packet is not for us (possible e.g. when device is in monitor mode)
        return;
    }

    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(src, (DATA*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s (%s)", packet[0], str_addr(src));
    }
}

static bool console_handler(FILE *fp, int argc, const char *argv[])
{
    if (match(argv, "h")) {
        fprintf(fp, "n: print routing table\n");
    } else if (match(argv, "i")) {
        uint8_t own_bloom[BLOOM_M];
        bloom_init(&own_bloom[0], gstate.own_id, BLOOM_M, BLOOM_K);

        fprintf(fp, "id: 0x%08x\n", gstate.own_id);
        fprintf(fp, "bloom-size: %u, hash-funcs: %u\n", BLOOM_M, BLOOM_K);
        fprintf(fp, "bloom: %s\n", str_bloom(&own_bloom[0], BLOOM_M));
    } else if (match(argv, "n")) {
        unsigned counter = 0;
        Entry *cur;
        Entry *tmp;

        fprintf(fp, "sender-id addr updated bloom hop-count\n");
        HASH_ITER(hh, g_neighbors, cur, tmp) {
            fprintf(fp, "0x%08x %s %s %s %u\n",
                cur->sender_id,
                str_addr(&cur->addr),
                str_since(cur->last_updated),
                str_bloom(&cur->bloom[0], BLOOM_M),
                (unsigned) cur->hop_cnt
            );
            counter += 1;
        }
        fprintf(fp, "%u entries\n", counter);
    } else {
        return false;
    }

    return true;
}

static void init()
{
    net_add_handler(-1, &entry_timeout);
}

void dsr_bloom_1_register()
{
    static const Protocol p = {
        .name = "dsr-bloom-1",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
    };

    protocols_register(&p);
}
