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
#include "../interfaces.h"
#include "../main.h"


#define TIMEOUT_NEIGHBOR_SEC 5
#define COMM_SEND_INTERVAL_SEC 1

// Couting Bloom Filter
#define BLOOM_M 8   // size of the bloom filter
#define BLOOM_K 1   // number of hash functions
#define BLOOM_C 255 // maximum count

enum {
    TYPE_COMM,
    TYPE_DATA
};

typedef struct {
    uint32_t sender_id;
    Address addr;
    uint8_t bloom[BLOOM_M];
    uint64_t last_updated;
    UT_hash_handle hh;
} Neighbor;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;  // to prevent loops - might not be need
    uint32_t dst_id;
    uint32_t sender_id;  // to prevent loops - might not be need
    uint16_t length; // might not be needed
    //uint8_t payload[ETH_FRAME_LEN];
} DATA;

// only travels one hop to the neighbors
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t sender_id;
    uint8_t bloom[BLOOM_M];
} COMM;


static uint8_t g_own_id_bloom[BLOOM_M]; // does not change
static uint8_t g_own_bloom[BLOOM_M]; // changes over time
static Neighbor *g_entries = NULL;

/*
static uint8_t *get_data_payload(const DATA *data)
{
    return ((uint8_t*) data) + sizeof(DATA);
}
*/

static size_t get_data_size(const DATA *data)
{
    return sizeof(DATA) + data->length;
}

// degrade a random byte
static void bloom_degrade(uint8_t *new_bloom, const uint8_t *old_bloom)
{
    for (size_t i = 0; i < BLOOM_K; i++) {
        const int r = rand() % BLOOM_M;
        if (old_bloom[r] > 0) {
            new_bloom[r] = old_bloom[r] - 1;
        }
    }
}

// create bloom from id
static void bloom_init(uint8_t *bloom, uint32_t id)
{
    memset(bloom, 0, BLOOM_M);

    // simple linear congruential generator
    uint64_t next = id;
    for (size_t i = 0; i < BLOOM_K; i++) {
        next = next * 1103515245 + 12345;
        uint32_t r = (next / 65536) % 32768;
        bloom[r % BLOOM_M] = BLOOM_C;
    }
}

// add two bloom filters
static void bloom_add(uint8_t *bloom1, const uint8_t *bloom2)
{
    for (size_t i = 0; i < BLOOM_M; i++) {
        bloom1[i] = MAX(bloom1[i], bloom2[i]);
    }
}

// Propability to reach a destination from origin
// Devide by (BLOOM_M  *BLOOM_C) for a propability in range 0-1.
static uint32_t bloom_probability(const uint8_t *origin_bloom, const uint8_t *destination_bloom)
{
    uint32_t prob = 0;
    for (size_t i = 0; i < BLOOM_M; i++) {
        if (destination_bloom[i] > 0) {
            prob += origin_bloom[i];
        }
    }
    return prob;
}

static void neighbor_timeout()
{
    Neighbor *tmp;
    Neighbor *cur;

    HASH_ITER(hh, g_entries, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_NEIGHBOR_SEC * 1000) < gstate.time_now) {
            log_debug("timeout neighbor 0x%08x", cur->sender_id);
            HASH_DEL(g_entries, cur);
            free(cur);
        }
    }
}

static Neighbor *neighbor_find(uint32_t sender_id)
{
    Neighbor *cur;
    HASH_FIND(hh, g_entries, &sender_id, sizeof(uint32_t), cur);
    return cur;
}

static Neighbor *neighbor_add(uint32_t sender_id, uint8_t *bloom, const Address *addr)
{
    Neighbor *e = (Neighbor*) malloc(sizeof(Neighbor));

    e->sender_id = sender_id;
    memcpy(&e->bloom, bloom, sizeof(e->bloom));
    memcpy(&e->addr, addr, sizeof(Address));
    e->last_updated = gstate.time_now;

    HASH_ADD(hh, g_entries, sender_id, sizeof(uint32_t), e);

    return e;
}

static void handle_COMM(const Address *rcv, const Address *src, const Address *dst, COMM *p, size_t length)
{
    // we expect broadcasts only
    if (!address_is_broadcast(dst)) {
        log_trace("COMM: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length != sizeof(COMM)) {
        log_debug("invalid COMM packet size => drop");
        return;
    }

    log_debug("got COMM packet: %s / 0x%08x", str_addr(src), p->sender_id);

    if (p->sender_id == gstate.own_id) {
        log_debug("own COMM packet => drop");
        return;
    }

/*
only add full bloom filter if it adds zero or one more fields to be >0?
*/

    uint8_t neigh_bloom[BLOOM_M];
    bloom_degrade(&neigh_bloom[0], &p->bloom[0]);

    bloom_add(&g_own_bloom[0], &g_own_id_bloom[0]);
    bloom_add(&g_own_bloom[0], &neigh_bloom[0]);

    Neighbor *neighbor = neighbor_find(p->sender_id);
    if (neighbor) {
        memcpy(&neighbor->bloom, &p->bloom, BLOOM_M);
        memcpy(&neighbor->addr, src, sizeof(Address)); // not expected to change but update anyway
        neighbor->last_updated = gstate.time_now;
    } else {
        neighbor = neighbor_add(p->sender_id, p->bloom, src);
    }
}

static void forward_DATA(const DATA *p, size_t length)
{
    uint8_t dst_bloom[BLOOM_M];
    bloom_init(dst_bloom, p->dst_id);

    // probability to transmit from this node to destination
    const uint32_t p_own = bloom_probability(g_own_id_bloom, dst_bloom);
    unsigned send_counter = 0;

    log_warning("p_own: %u", (unsigned) p_own);

    Neighbor *tmp;
    Neighbor *cur;
    HASH_ITER(hh, g_entries, cur, tmp) {
        // probability to transmit from neighbor to destination
        const uint32_t p_neighbor = bloom_probability(&cur->bloom[0], &dst_bloom[0]);
        log_warning("p_neighbor: %u", (unsigned) p_neighbor);
        if (p_neighbor > p_own) {
            send_ucast_l2(&cur->addr, p, length);
            send_counter += 1;
        }
    }

    log_debug("forward data packet to %u neighbors", send_counter);
}

static void handle_DATA(const Address *rcv, const Address *src, const Address *dst, DATA *p, size_t recv_len)
{
    // we expect unicast to us only
    if (!address_equal(rcv, dst)) {
        log_trace("DATA: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (recv_len < sizeof(DATA) || recv_len != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (p->sender_id == gstate.own_id) {
        log_debug("DATA: received own packet => drop");
        return;
    }

    // just a precaution
    if (p->hop_count > 200) {
        log_warning("DATA: max hop count reached (200)");
        return;
    }

    p->sender_id = gstate.own_id;
    p->hop_count += 1;

    forward_DATA(p, recv_len);
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    DATA *data = (DATA*) (packet - sizeof(DATA));

    data->dst_id = dst_id;
    data->sender_id = gstate.own_id;
    data->hop_count = 0;
    data->length = packet_length;

    forward_DATA(data, get_data_size(data));
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    if (!address_is_broadcast(dst) && !address_equal(dst, rcv)) {
        // packet is not for us (possible e.g. when device is in monitor mode)
        return;
    }

    switch (packet[0]) {
    case TYPE_COMM:
        handle_COMM(rcv, src, dst, (COMM*) packet, packet_length);
        break;
    case TYPE_DATA:
        handle_DATA(rcv, src, dst, (DATA*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src));
    }
}

static void send_COMMs()
{
    static uint64_t g_last_send = 0;

    if (g_last_send != 0 && (g_last_send + COMM_SEND_INTERVAL_SEC * 1000) > gstate.time_now) {
        return;
    } else {
        g_last_send = gstate.time_now;
    }

    COMM data = {
        .type = TYPE_COMM,
        .sender_id = gstate.own_id,
    };

    memcpy(&data.bloom[0], &g_own_bloom[0], sizeof(data.bloom));

    send_bcast_l2(0, &data, sizeof(data));
}

static void periodic_handler(int _events, int _fd)
{
    static uint64_t g_every_second = 0;

    if (g_every_second != 0 && g_every_second >= gstate.time_now) {
        return;
    }
    g_every_second = gstate.time_now + 1000;

    neighbor_timeout();
    send_COMMs();
}

static char *str_bloom(char *buf, const uint8_t *bloom)
{
    char *cur = buf;
    for (size_t i = 0; i < BLOOM_M; i++) {
        if (i == 0) {
            cur += sprintf(cur, "%u", (unsigned) bloom[i]);
        } else {
            cur += sprintf(cur, " %u", (unsigned) bloom[i]);
        }
    }
    return buf;
}

static bool console_handler(FILE *fp, int argc, const char *argv[])
{
    char buf_bloom[BLOOM_M * 6];

    if (match(argv, "h")) {
        fprintf(fp, "  n: print neighbor table\n");
    } else if (match(argv, "i")) {
        fprintf(fp, "  id: 0x%08x / %s\n", gstate.own_id, str_bloom(buf_bloom, &g_own_id_bloom[0]));
        fprintf(fp, "  bloom-size: %u, bloom-capacity: %u, hash-funcs: %u\n", BLOOM_M, BLOOM_C, BLOOM_K);
        fprintf(fp, "  bloom: %s\n", str_bloom(buf_bloom, &g_own_bloom[0]));
    } else if (match(argv, "n")) {
        size_t counter = 0;
        Neighbor *cur;
        Neighbor *tmp;

        fprintf(fp, "  sender_id addr updated bloom\n");
        HASH_ITER(hh, g_entries, cur, tmp) {
            fprintf(fp, "  0x%08x %s %s %s\n",
                cur->sender_id,
                str_addr(&cur->addr),
                str_since(cur->last_updated),
                str_bloom(buf_bloom, &cur->bloom[0])
            );
            counter += 1;
        }
        fprintf(fp, "%zu entries\n", counter);
    } else {
        return true;
    }

    return false;
}

static void init()
{
    // put id into own (constant) bloom filter
    bloom_init(&g_own_id_bloom[0], gstate.own_id);

    // sleep up to 1 second
    usleep(rand() % 1000);

    net_add_handler(-1, &periodic_handler);
}

void counting_bloom_0_register()
{
    static const Protocol p = {
        .name = "counting-bloom-0",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console_handler = &console_handler,
    };

    protocols_register(&p);
}
