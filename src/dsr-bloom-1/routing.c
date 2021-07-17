#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#include "../log.h"
#include "../utils.h"
#include "../net.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../uthash.h"
#include "../interfaces.h"

#include "routing.h"

#define TIMEOUT_ENTRY_SEC 60

// Bloom Filter
#define BLOOM_M 8   // size of the bloom filter (in bytes)
#define BLOOM_K 2   // number of hash functions

#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))

enum {
    TYPE_DATA,
};

typedef struct sockaddr_storage Address;

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
    uint8_t hop_cnt; // not needed, but useful for debugging
    uint16_t seq_num; // not needed, but useful for debugging
    uint16_t length;
    uint8_t payload[2000];
} DATA;

static uint32_t g_own_id = 0; // set from the fe80 addr of tun0
static Entry *g_entries = NULL;
static uint16_t g_seq_num = 0;

static void bloom_init(uint8_t *bloom, uint64_t id)
{
    memset(bloom, 0, BLOOM_M);

    uint64_t next = id;
    for (int i = 0; i < BLOOM_K; i++) {
        next = next * 1103515245 + 12345;
        uint32_t r = (next / 65536) % 32768;
        uint32_t j = r % (BLOOM_M * 8);
        BLOOM_BITSET(bloom, j);
    }
}

static int bloom_ones(const uint8_t *bloom)
{
    int ones = 0;

    for (int i = 0; i < (8 * BLOOM_M); i++) {
        ones += (0 != BLOOM_BITTEST(bloom, i));
    }

    return ones;
}

static int bloom_test(const uint8_t *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M]; 
    bloom_init(&bloom_id[0], id);

    for (int i = 0; i < BLOOM_M; i++) {
        if ((bloom[i] & bloom_id[i]) != bloom_id[i]) {
            return 0;
        }
    }

    return 1;
}

static void bloom_merge(uint8_t *bloom1, const uint8_t *bloom2)
{
    for (int i = 0; i < BLOOM_M; i++) {
        bloom1[i] |= bloom2[i];
    }
}

static void bloom_add(uint8_t *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M];
    bloom_init(&bloom_id[0], id);
    bloom_merge(bloom, &bloom_id[0]);
}

static void entry_timeout()
{
    Entry *tmp;
    Entry *cur;

    HASH_ITER(hh, g_entries, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_ENTRY_SEC) <= gstate.time_now) {
            log_debug("timeout entry %04x", cur->sender_id);
            HASH_DEL(g_entries, cur);
        }
    }
}

static Entry *entry_find(uint32_t sender_id)
{
    Entry *cur = NULL;
    HASH_FIND_INT(g_entries, &sender_id, cur);
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

    HASH_ADD_INT(g_entries, sender_id, e);

    return e;
}

static void forward_DATA(DATA *p, unsigned recv_len)
{
    // find best neighbor
    Entry *next = NULL;
    Entry *cur;
    Entry *tmp;
    HASH_ITER(hh, g_entries, cur, tmp) {
        if (bloom_test(&cur->bloom[0], p->dst_id)) {
            if (next == NULL || cur->hop_cnt < next->hop_cnt) {
                next = cur;
            }
        }
    }

    if (next) {
        log_debug("send as unicast to %04x (seq_num: %d, hop_cnt: %d)",
            next->sender_id, (int) p->seq_num, (int) p->hop_cnt);
        send_ucast(&next->addr, p, recv_len);
    } else {
        log_debug("send as multicast (seq_num: %d, hop_cnt: %d)",
            (int) p->seq_num, (int) p->hop_cnt);
        send_mcasts(p, recv_len);
    }
}

static void handle_DATA(int ifindex, const Address *addr, DATA *p, unsigned recv_len, int is_mcast)
{
    if (recv_len < offsetof(DATA, payload) || recv_len != (offsetof(DATA, payload) + p->length)) {
        log_debug("invalid packet size => drop");
        return;
    }

    // reduce log noise
    if (p->sender_id == g_own_id) {
        return;
    }

    log_debug("data packet from neighbor %04x => %04x (seq_num: %d, hop_cnt: %d, %s)",
        p->sender_id, p->dst_id, (int) p->seq_num, (int) p->hop_cnt, is_mcast ? "multicast" : "unicast");

    if (bloom_test(&p->bloom[0], g_own_id)) {
        log_debug("own id in packets bloom filter => drop");
        return;
    }

    // assume 50% is the limit
    if (bloom_ones(&p->bloom[0]) > ((BLOOM_M * 8) / 2)) {
        log_debug("bloom filter capacity reached => drop");
        return;
    }

    Entry *entry = entry_find(p->sender_id);
    if (entry) {
        memcpy(&entry->addr, addr, sizeof(entry->addr));
        bloom_merge(&entry->bloom[0], &p->bloom[0]);
    } else {
        entry_add(p->sender_id, p->hop_cnt, &p->bloom[0], addr);
    }

    if (p->dst_id == g_own_id) {
        log_debug("write %u bytes to %s", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        if (write(gstate.tun_fd, p->payload, p->length) != p->length) {
            log_error("write() %s", strerror(errno));
        }
    } else {
        // add own id
        bloom_add(&p->bloom[0], g_own_id);

        p->hop_cnt += 1;

        forward_DATA(p, recv_len);
    }
}

// read traffic from tun0 and send to peers
static void tun_handler(int events, int fd)
{
    DATA data = {
        .type = TYPE_DATA,
    };

    if (events <= 0) {
        return;
    }

    while (1) {
        int read_len = read(fd, &data.payload[0], sizeof(data.payload));
        if (read_len <= 0) {
            break;
        }

        int ip_version = (data.payload[0] >> 4) & 0x0f;

        if (ip_version != 6) {
            log_debug("unhandled packet protocol version (IPv%d) => drop", ip_version);
            continue;
        }

        if (read_len < 24) {
            log_debug("payload too small (%d) => drop", read_len);
            continue;
        }

        // IPv6 packet
        int payload_length = ntohs(*((uint16_t*) &data.payload[4]));
        struct in6_addr *saddr = (struct in6_addr *) &data.payload[8];
        struct in6_addr *daddr = (struct in6_addr *) &data.payload[24];

        if (IN6_IS_ADDR_MULTICAST(daddr)) {
            // no support for multicast traffic
            continue;
        }

        // some id we want to send data to
        uint32_t dst_id = 0;
        id_get6(&dst_id, daddr);

        log_debug("read %d from %s for %04x", read_len, gstate.tun_name, dst_id);

        if (dst_id == g_own_id) {
            log_warning("send packet to self => drop packet");
            continue;
        }

        data.sender_id = g_own_id;
        data.hop_cnt = 0;
        data.seq_num = g_seq_num++;
        data.dst_id = dst_id;
        data.length = read_len;
        bloom_init(&data.bloom[0], g_own_id);

        forward_DATA(&data, offsetof(DATA, payload) + read_len);
    }
}

static void ext_handler(int events, int fd)
{
    Address from_addr = {0};
    Address to_addr = {0};
    uint8_t buffer[sizeof(DATA)];
    ssize_t recv_len;
    int ifindex = 0;

    if (events <= 0) {
        return;
    }

    recv_len = recv6_fromto(
        fd, buffer, sizeof(buffer), 0, &ifindex, &from_addr, &to_addr);

    if (recv_len <= 0) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }

    // received from multicast socket
    int is_mcast = (fd == gstate.sock_mcast_receive);

/*
    if (fd == gstate.sock_mcast_receive) {
        log_debug("got ucast %s => %s (%s)", str_addr(&from_addr), str_addr(&to_addr), str_ifindex(ifindex));
    } else {
        log_debug("got mcast %s => %s (%s)", str_addr(&from_addr), str_addr(&to_addr), str_ifindex(ifindex));
    }
*/

    switch (buffer[0]) {
    case TYPE_DATA:
        handle_DATA(ifindex, &from_addr, (DATA*) buffer, recv_len, is_mcast);
        break;
    default:
        log_warning("unknown packet type %u from %s (%s)", (unsigned) buffer[0], str_addr(&from_addr), str_ifindex(ifindex));
    }
}

static char *format_bloom(const uint8_t *bloom)
{
    static char buf[BLOOM_M * 8  + 1];
    char *cur = buf;
    for (int i = 0; i < (8 * BLOOM_M); i++) {
        unsigned bit = (0 != BLOOM_BITTEST(bloom, i));
        cur += sprintf(cur, "%u", bit);
    }
    return buf;
}

static int console_handler(FILE *fp, const char *cmd)
{
    char buf_duration[64];
    int ret = 0;
    char d;

    if (sscanf(cmd, " h%c", &d) == 1) {
        fprintf(fp, "n: print routing table\n");
    } else if (sscanf(cmd, " i%c", &d) == 1) {
        uint8_t own_bloom[BLOOM_M];
        bloom_init(&own_bloom[0], g_own_id);

        fprintf(fp, "  id: %04x\n", g_own_id);
        fprintf(fp, "  bloom-size: %u, hash-funcs: %u\n", BLOOM_M, BLOOM_K);
        fprintf(fp, "  bloom: %s\n", format_bloom(&own_bloom[0]));
    } else if (sscanf(cmd, " n%c", &d) == 1) {
        unsigned counter = 0;
        Entry *cur;
        Entry *tmp;

        fprintf(fp, "  sender-id addr updated bloom hop-count\n");
        HASH_ITER(hh, g_entries, cur, tmp) {
            fprintf(fp, "  %04x %s %s %s %u\n",
                cur->sender_id,
                str_addr(&cur->addr),
                format_duration(buf_duration, cur->last_updated, gstate.time_now),
                format_bloom(&cur->bloom[0]),
                (unsigned) cur->hop_cnt
            );
            counter += 1;
        }
        fprintf(fp, "%u entries\n", counter);
    } else {
        ret = 1;
    }

    return ret;
}

static void periodic_handler(int _events, int _fd)
{
    static time_t g_every_second = 0;

    if (g_every_second == gstate.time_now) {
        return;
    } else {
        g_every_second = gstate.time_now;
    }

    entry_timeout();
}

static void init()
{
    // get id from IP address
    id_get6(&g_own_id, &gstate.tun_addr);

    net_add_handler(-1, &periodic_handler);
}

void dsr_bloom_1_register()
{
    static const Protocol p = {
        .name = "dsr-bloom-1",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler = &ext_handler,
        .console = &console_handler,
    };

    register_protocol(&p);
}
