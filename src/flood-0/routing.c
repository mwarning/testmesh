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
#include "../tun.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../uthash.h"
#include "../interfaces.h"

#include "routing.h"

enum {
    TYPE_DATA
};

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

static uint16_t g_sequence_number = 0;
static Entry *g_entries = NULL;

// returns (new > cur), but wraps around
static int is_newer_seq_num(uint16_t cur, uint16_t new)
{
    if (cur >= new) {
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
            log_debug("timeout entry 0x%08x", cur->id);
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

static void handle_DATA(const Address *addr, DATA *p, unsigned recv_len)
{
    if (recv_len < offsetof(DATA, payload) || recv_len != (offsetof(DATA, payload) + p->length)) {
        log_debug("invalid DATA packet size => drop");
        return;
    }

    log_debug("got DATA packet: %s / 0x%08x => 0x%08x",
        str_addr(addr), p->src_id, p->dst_id);

    if (p->src_id == gstate.own_id) {
        log_debug("own source id => drop packet");
        return;
    }

    Entry *entry = entry_find(p->src_id);

    if (entry) {
        entry->last_updated = gstate.time_now;
        if (is_newer_seq_num(entry->seq_num, p->seq_num)) {
            entry->seq_num = p->seq_num;
        } else {
            // old packet => drop
             log_debug("drop packet with old sequence number %d (current is %d)",
                (int) p->seq_num, (int) entry->seq_num);
            return;
        }
    } else {
        entry = entry_add(p->src_id, p->seq_num);
    }

    if (p->dst_id == gstate.own_id) {
        log_debug("write %u bytes to %s", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        tun_write(p->payload, p->length);
    } else {
        log_debug("send all");
        send_bcasts_l2(p, recv_len);
    }
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

        data.seq_num = g_sequence_number++;
        data.src_id = gstate.own_id;
        data.dst_id = dst_id;
        data.length = read_len;

        log_debug("send all");
        send_bcasts_l2(&data, offsetof(DATA, payload) + read_len);
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
    init_macaddr(&from_addr, &eh->h_source, ifindex);
    init_macaddr(&to_addr, &eh->h_dest, ifindex);


    switch (payload[0]) {
    case TYPE_DATA:
        handle_DATA(&from_addr, (DATA*) payload, payload_len);
        break;
    default:
        log_warning("unknown packet type %d from %s (%s)", payload[0], str_addr(&from_addr),  str_ifindex(ifindex));
    }
}

static int console_handler(FILE* fp, int argc, char *argv[])
{
    if (argc == 1 && !strcmp(argv[0], "h")) {
        fprintf(fp, "n: print routing table\n");
    } else if (argc == 1 && !strcmp(argv[0], "i")) {
        fprintf(fp, "entry timeout: %ds\n", TIMEOUT_ENTRY);
    } else if (argc == 1 && !strcmp(argv[0], "n")) {
        Entry *cur;
        Entry *tmp;
        char buf[64];
        int count = 0;

        fprintf(fp, "id seq_num last_updated\n");
        HASH_ITER(hh, g_entries, cur, tmp) {
            fprintf(fp, "0x%08x %u %s\n",
                cur->id,
                (unsigned) cur->seq_num,
                format_duration(buf, gstate.time_started, cur->last_updated)
            );
            count += 1;
        }
        fprintf(fp, "%d entries\n", count);
    } else {
        return 1;
    }

    return 0;
}

static void init()
{
    // call at least every second
    net_add_handler(-1, &entry_timeout);
}

void flood_0_register()
{
    static const Protocol p = {
        .name = "flood-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console = &console_handler,
    };

    protocols_register(&p);
}
