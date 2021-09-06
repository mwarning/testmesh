#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#include "../log.h"
#include "../utils.h"
#include "../tun.h"
#include "../net.h"
#include "../unix.h"
#include "../console.h"
#include "../interfaces.h"
#include "../uthash.h"
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
    time_t last_updated;
    UT_hash_handle hh;
} Neighbor;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;  // to prevent loops - might not be need
    uint32_t dst_id;
    uint32_t sender_id;  // to prevent loops - might not be need
    uint16_t length; // might not be needed
    uint8_t payload[2000];
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


// degrade a random byte
static void bloom_degrade(uint8_t *new_bloom, const uint8_t *old_bloom)
{
    for (int i = 0; i < BLOOM_K; i++) {
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
    for (int i = 0; i < BLOOM_K; i++) {
        next = next * 1103515245 + 12345;
        uint32_t r = (next / 65536) % 32768;
        bloom[r % BLOOM_M] = BLOOM_C;
    }
}

// add two bloom filters
static void bloom_add(uint8_t *bloom1, const uint8_t *bloom2)
{
    for (int i = 0; i < BLOOM_M; i++) {
        bloom1[i] = MAX(bloom1[i], bloom2[i]);
    }
}

// Propability to reach a destination from origin
// Devide by (BLOOM_M  *BLOOM_C) for a propability in range 0-1.
static uint32_t bloom_probability(const uint8_t *origin_bloom, const uint8_t *destination_bloom)
{
    uint32_t prob = 0;
    for (int i = 0; i < BLOOM_M; i++) {
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
        if ((cur->last_updated + TIMEOUT_NEIGHBOR_SEC) < gstate.time_now) {
            log_debug("timeout neighbor 0x%08x", cur->sender_id);
            HASH_DEL(g_entries, cur);
        }
    }
}

static Neighbor *neighbor_find(uint32_t sender_id)
{
    Neighbor *cur = NULL;
    HASH_FIND_INT(g_entries, &sender_id, cur);
    return cur;
}

static Neighbor *neighbor_add(uint32_t sender_id, uint8_t *bloom, const Address *addr)
{
    Neighbor *e = (Neighbor*) malloc(sizeof(Neighbor));

    e->sender_id = sender_id;
    memcpy(&e->bloom, bloom, sizeof(e->bloom));
    memcpy(&e->addr, addr, sizeof(Address));
    e->last_updated = gstate.time_now;

    HASH_ADD_INT(g_entries, sender_id, e);

    return e;
}

static void handle_COMM(const Address *from_addr, COMM *p, unsigned recv_len)
{
    if (recv_len != sizeof(COMM)) {
        log_debug("invalid packet size => drop");
        return;
    }

    log_debug("got comm packet: %s / 0x%08x", str_addr2(from_addr), p->sender_id);

    if (p->sender_id == gstate.own_id) {
        log_debug("own comm packet => drop");
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
        memcpy(&neighbor->bloom, &p->bloom, sizeof(neighbor->bloom));
        memcpy(&neighbor->addr, from_addr, sizeof(neighbor->addr)); // not expected to change but update anyway
        neighbor->last_updated = gstate.time_now;
    } else {
        neighbor = neighbor_add(p->sender_id, p->bloom, from_addr);
    }
}

static void forward_DATA(const DATA *p, unsigned recv_len)
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
            send_ucast_l2(&cur->addr, p, recv_len);
            send_counter += 1;
        }
    }

    log_debug("forward data packet to %u neighbors", send_counter);
}

static void handle_DATA(const Address *addr, DATA *p, unsigned recv_len)
{
    if (recv_len < offsetof(DATA, payload) || recv_len != (offsetof(DATA, payload) + p->length)) {
        log_debug("invalid packet size => drop");
        return;
    }

    if (p->sender_id == gstate.own_id) {
        log_debug("own data packet => drop");
        return;
    }

    // just a precaution
    if (p->hop_count > 200) {
        log_warning("max hop count reached (200)");
        return;
    }

    p->sender_id = gstate.own_id;
    p->hop_count += 1;

    forward_DATA(p, recv_len);
}

// read traffic from tun0 and send to peers
static void tun_handler(int events, int fd)
{
    uint32_t dst_id;

    DATA data = {
        .type = TYPE_DATA,
    };

    if (events <= 0) {
        return;
    }

    while (1) {
        ssize_t read_len = tun_read(&dst_id, &data.payload[0], sizeof(data.payload));

        if (read_len <= 0) {
            break;
        }

        data.dst_id = dst_id;
        data.sender_id = gstate.own_id;
        data.hop_count = 0;
        data.length = read_len;

        forward_DATA(&data, offsetof(DATA, payload) + read_len);
    }
}

static void ext_handler_l2(int events, int fd)
{
    if (events <= 0) {
        return;
    }

    uint8_t buffer[ETH_FRAME_LEN];
    ssize_t numbytes = recvfrom(fd, buffer, sizeof(buffer), 0, NULL, NULL);

    if (numbytes <= sizeof(struct ethhdr)) {
        return;
    }

    uint8_t *payload = &buffer[sizeof(struct ethhdr)];
    size_t payload_len = numbytes - sizeof(struct ethhdr);
    struct ethhdr *eh = (struct ethhdr *) &buffer[0];
    int ifindex = interface_get_ifindex(fd);

    Address from_addr;
    Address to_addr;
    init_macaddr(&from_addr, &eh->h_source[0], ifindex);
    init_macaddr(&to_addr, &eh->h_dest[0], ifindex);

    switch (payload[0]) {
    case TYPE_COMM:
        handle_COMM(&from_addr, (COMM*) payload, payload_len);
        break;
    case TYPE_DATA:
        handle_DATA(&from_addr, (DATA*) payload, payload_len);
        break;
    default:
        log_warning("unknown packet type %u from %s (%s)", (unsigned) payload[0], str_addr2(&from_addr), str_ifindex(ifindex));
    }
}

static void send_COMMs()
{
    static time_t g_last_send = 0;

    if (g_last_send != 0 && (g_last_send + COMM_SEND_INTERVAL_SEC) > gstate.time_now) {
        return;
    } else {
        g_last_send = gstate.time_now;
    }

    COMM data = {
        .type = TYPE_COMM,
        .sender_id = gstate.own_id,
    };

    memcpy(&data.bloom[0], &g_own_bloom[0], sizeof(data.bloom));

    send_bcasts_l2(&data, sizeof(data));
}

static void periodic_handler(int _events, int _fd)
{
    static time_t g_every_second = 0;

    if (g_every_second == gstate.time_now) {
        return;
    } else {
        g_every_second = gstate.time_now;
    }

    neighbor_timeout();
    send_COMMs();
}

static char *format_bloom(char *buf, const uint8_t *bloom)
{
    char *cur = buf;
    for (int i = 0; i < BLOOM_M; i++) {
        if (i == 0) {
            cur += sprintf(cur, "%u", (unsigned) bloom[i]);
        } else {
            cur += sprintf(cur, " %u", (unsigned) bloom[i]);
        }
    }
    return buf;
}

static int console_handler(FILE *fp, int argc, char *argv[])
{
    char buf_duration[64];
    char buf_bloom[BLOOM_M * 6];

    if (argc == 1 && !strcmp(argv[0], "h")) {
        fprintf(fp, "  n: print neighbor table\n");
    } else if (argc == 1 && !strcmp(argv[0], "i")) {
        fprintf(fp, "  id: 0x%08x / %s\n", gstate.own_id, format_bloom(buf_bloom, &g_own_id_bloom[0]));
        fprintf(fp, "  bloom-size: %u, bloom-capacity: %u, hash-funcs: %u\n", BLOOM_M, BLOOM_C, BLOOM_K);
        fprintf(fp, "  bloom: %s\n", format_bloom(buf_bloom, &g_own_bloom[0]));
    } else if (argc == 1 && !strcmp(argv[0], "n")) {
        unsigned counter = 0;
        Neighbor *cur;
        Neighbor *tmp;

        fprintf(fp, "  sender_id addr updated bloom\n");
        HASH_ITER(hh, g_entries, cur, tmp) {
            fprintf(fp, "  0x%08x %s %s %s\n",
                cur->sender_id,
                str_addr2(&cur->addr),
                format_duration(buf_duration, cur->last_updated, gstate.time_now),
                format_bloom(buf_bloom, &cur->bloom[0])
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
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console = &console_handler,
    };

    register_protocol(&p);
}
