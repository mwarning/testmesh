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

enum {
    TYPE_DATA
};

typedef struct sockaddr_storage Address;

#define TIMEOUT_ENTRY 20

typedef struct {
    uint32_t id;
    uint16_t seq_num;
    time_t last_updated;
    UT_hash_handle hh;
} Entry;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num; // sequence number
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t length; // might not be needed
    uint8_t payload[2000];
} DATA;

static uint32_t g_own_id = 0; // set from the fe80 addr of tun0
static uint16_t g_sequence_number = 0;
static Entry *g_entries = NULL;

// wraps around
static int is_newer_seq_num(uint16_t cur, uint16_t new)
{
    if (cur > new) {
        return (cur - new) > 0x7fff;
    } else {
        return (new - cur) < 0x7fff;
    }
}

static void entry_timeout()
{
    Entry *tmp;
    Entry *cur;

    HASH_ITER(hh, g_entries, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_ENTRY) < gstate.time_now) {
            log_debug("timeout entry %04x", cur->id);
            HASH_DEL(g_entries, cur);
        }
    }
}

static Entry *entry_find(uint32_t id)
{
    Entry *cur = NULL;
    HASH_FIND_INT(g_entries, &id, cur);
    return cur;
}

static Entry *entry_add(uint32_t id, uint16_t seq_num)
{
    Entry *e = (Entry*) malloc(sizeof(Entry));

    e->id = id;
    e->seq_num = seq_num;
    e->last_updated = gstate.time_now;

    HASH_ADD_INT(g_entries, id, e);

    return e;
}

static void handle_DATA(int ifindex, const Address *addr, DATA *p, unsigned recv_len)
{
    if (recv_len < offsetof(DATA, payload) || recv_len != (offsetof(DATA, payload) + p->length)) {
        log_debug("invalid packet size => drop");
        return;
    }

    log_debug("data packet: %s / %04x => %04x",
        str_addr(addr), p->src_id, p->dst_id);

    if (p->src_id == g_own_id) {
        log_debug("own source id => drop packet");
        return;
    }

    Entry *entry = entry_find(p->src_id);

    if (entry) {
        entry->last_updated = gstate.time_now;
        if (p->seq_num <= entry->seq_num) {
            // old packet => drop
             log_debug("drop packet with old sequence number %d (current is %d)",
                (int) p->seq_num, (int) entry->seq_num);
            return;
        } else {
            entry->seq_num = p->seq_num;
        }
    } else {
        entry = entry_add(p->src_id, p->seq_num);
    }

    if (p->dst_id == g_own_id) {
        log_debug("write %u bytes to %s", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        if (write(gstate.tun_fd, p->payload, p->length) != p->length) {
            log_error("write() %s", strerror(errno));
        }
    } else {
        log_debug("send mcasts");
        send_mcasts(p, recv_len);
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

        data.seq_num = g_sequence_number++;
        data.src_id = g_own_id;
        data.dst_id = dst_id;
        data.length = read_len;

        log_debug("send mcasts");
        send_mcasts(&data, offsetof(DATA, payload) + read_len);
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

    if (fd == gstate.sock_mcast_receive) {
        log_debug("got mcast %s => %s (%s)", str_addr(&from_addr), str_addr(&to_addr), str_ifindex(ifindex));
    } else {
        log_debug("got ucast %s => %s (%s)", str_addr(&from_addr), str_addr(&to_addr), str_ifindex(ifindex));
    }

    switch (buffer[0]) {
    case TYPE_DATA:
        handle_DATA(ifindex, &from_addr, (DATA*) buffer, recv_len);
        break;
    default:
        log_warning("unknown packet type %u from %s (%s)", (unsigned) buffer[0], str_addr(&from_addr), str_ifindex(ifindex));
    }
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

static int console_handler(FILE* fp, const char* cmd)
{
    int ret = 0;
    char d;

    if (sscanf(cmd, " h%c", &d) == 1) {
        fprintf(fp, "  n: print routing table\n");
    } else if (sscanf(cmd, " i%c", &d) == 1) {
        fprintf(fp, "  entry timeout: %ds\n", TIMEOUT_ENTRY);
    } else if (sscanf(cmd, " n%c", &d) == 1) {
        Entry *cur;
        Entry *tmp;
        char buf[64];

        fprintf(fp, "id seq_num last_updated\n");
        HASH_ITER(hh, g_entries, cur, tmp) {
            fprintf(fp, "  %04x %u %s\n",
                cur->id,
                (unsigned) cur->seq_num,
                format_duration(buf, gstate.time_started, cur->last_updated)
            );
        }
    } else {
        ret = 1;
    }

    return ret;
}

static void init()
{
    // get id from IP address
    id_get6(&g_own_id, &gstate.tun_addr);

    // call at least every second
    net_add_handler(-1, &periodic_handler);
}

void flood_0_register()
{
    static const Protocol p = {
        .name = "flood-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler = &ext_handler,
        .console = &console_handler,
    };

    register_protocol(&p);
}
