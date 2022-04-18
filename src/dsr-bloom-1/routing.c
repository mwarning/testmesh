#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

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

#define TIMEOUT_ENTRY_SEC 60

// Bloom Filter
#define BLOOM_M      8  // size of the bloom filter (in bytes)
#define BLOOM_K      2  // number of hash functions
#define BLOOM_LIMIT 50  // limit for the bloom filter (in percent)

#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))

enum {
    TYPE_DATA,
};

typedef struct {
    uint32_t sender_id; // we can use the sender address here instead
    Address addr;
    uint8_t bloom[BLOOM_M];
    uint8_t hop_cnt;
    time_t last_updated;
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

// set BLOOM_K bits based on id
static void bloom_init(uint8_t *bloom, uint64_t id)
{
    memset(bloom, 0, BLOOM_M);

    // linear congruential generator
    uint64_t next = id;
    for (size_t i = 0; i < BLOOM_K; i++) {
        next = next * 1103515245 + 12345;
        uint32_t r = (next / 65536) % 32768;
        uint32_t j = r % (BLOOM_M * 8);
        BLOOM_BITSET(bloom, j);
    }
}

// count of bits set in bloom filter
static uint16_t bloom_ones(const uint8_t *bloom)
{
    uint16_t ones = 0;

    for (size_t i = 0; i < (8 * BLOOM_M); i++) {
        ones += (0 != BLOOM_BITTEST(bloom, i));
    }

    return ones;
}

static bool bloom_test(const uint8_t *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M]; 
    bloom_init(&bloom_id[0], id);

    for (size_t i = 0; i < BLOOM_M; i++) {
        if ((bloom[i] & bloom_id[i]) != bloom_id[i]) {
            return false;
        }
    }

    return true;
}

static void bloom_merge(uint8_t *bloom1, const uint8_t *bloom2)
{
    for (size_t i = 0; i < BLOOM_M; i++) {
        bloom1[i] |= bloom2[i];
    }
}

static void bloom_add(uint8_t *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M];
    bloom_init(&bloom_id[0], id);
    bloom_merge(bloom, &bloom_id[0]);
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
        if ((cur->last_updated + TIMEOUT_ENTRY_SEC) <= gstate.time_now) {
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
        if (bloom_test(&cur->bloom[0], p->dst_id)) {
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
        send_bcasts_l2(p, recv_len);
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

    if (bloom_test(&p->bloom[0], gstate.own_id)) {
        log_debug("DATA: own id in packets bloom filter => drop");
        return;
    }

    // limit bloom filter fill rate to BLOOM_LIMIT percent
    if (bloom_ones(&p->bloom[0]) > (int) ((BLOOM_M * 8) * BLOOM_LIMIT) / 100) {
        log_debug("DATA: bloom filter occupancy reached => drop");
        return;
    }

    Entry *entry = entry_find(p->sender_id);
    if (entry) {
        memcpy(&entry->addr, src_addr, sizeof(entry->addr));
        bloom_merge(&entry->bloom[0], &p->bloom[0]);
    } else {
        entry_add(p->sender_id, p->hop_cnt, &p->bloom[0], src_addr);
    }

    // add own id
    bloom_add(&p->bloom[0], gstate.own_id);

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
    bloom_init(&data->bloom[0], gstate.own_id);

    forward_DATA(data, get_data_size(data));
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(src, (DATA*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s (%s)", packet[0], str_addr(src));
    }
}

static char *str_bloom(const uint8_t *bloom)
{
    static char buf[BLOOM_M * 8 + 1];
    char *cur = buf;
    for (size_t i = 0; i < (8 * BLOOM_M); i++) {
        uint32_t bit = (0 != BLOOM_BITTEST(bloom, i));
        cur += sprintf(cur, "%u", bit);
    }
    return buf;
}

static int console_handler(FILE *fp, int argc, char *argv[])
{
    if (argc == 1 && !strcmp(argv[0], "h")) {
        fprintf(fp, "n: print routing table\n");
    } else if (argc == 1 && !strcmp(argv[0], "i")) {
        uint8_t own_bloom[BLOOM_M];
        bloom_init(&own_bloom[0], gstate.own_id);

        fprintf(fp, "id: 0x%08x\n", gstate.own_id);
        fprintf(fp, "bloom-size: %u, hash-funcs: %u\n", BLOOM_M, BLOOM_K);
        fprintf(fp, "bloom: %s\n", str_bloom(&own_bloom[0]));
    } else if (argc == 1 && !strcmp(argv[0], "n")) {
        unsigned counter = 0;
        Entry *cur;
        Entry *tmp;

        fprintf(fp, "sender-id addr updated bloom hop-count\n");
        HASH_ITER(hh, g_neighbors, cur, tmp) {
            fprintf(fp, "0x%08x %s %s %s %u\n",
                cur->sender_id,
                str_addr(&cur->addr),
                str_ago(cur->last_updated),
                str_bloom(&cur->bloom[0]),
                (unsigned) cur->hop_cnt
            );
            counter += 1;
        }
        fprintf(fp, "%u entries\n", counter);
    } else {
        return 1;
    }

    return 0;
}

static void init()
{
    net_add_handler(-1, &entry_timeout);
}

void dsr_bloom_1_register()
{
    static const Protocol p = {
        .name = "dsr-bloom-1",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console = &console_handler,
    };

    protocols_register(&p);
}
