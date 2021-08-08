#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <linux/if_ether.h>

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

#define TIMEOUT_ENTRY 20

typedef struct {
    uint32_t src_id;
    uint16_t seq_num;
    uint8_t hop_count;
    time_t last_updated;
    Address addr;
    UT_hash_handle hh;
} Entry;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;  // hop count (metric)
    uint16_t seq_num; // sequence number
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t length;  // might not be needed
    uint8_t payload[2000];
} DATA;

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

static void send_one(const Address *addr, const void *data, size_t data_len)
{
    switch (addr->family) {
    case AF_MAC:
        send_ucast_l2(addr->mac.ifindex, &addr->mac.addr.data[0], data, data_len);
        break;
    case AF_INET6:
    case AF_INET:
        send_ucast_l3((const struct sockaddr_storage *) addr, data, data_len);
        break;
    default:
        exit(1);
    }
}

static void send_all(const void *data, size_t data_len)
{
    // on all configured interfaces
    send_bcasts_l2(data, data_len);

    Entry *tmp;
    Entry *cur;

    // all peers
    HASH_ITER(hh, g_entries, cur, tmp) {
        if (cur->addr.family != AF_MAC) {
            send_ucast_l3((struct sockaddr_storage*) &cur->addr, data, data_len);
        }
    }
}

static void entry_timeout()
{
    Entry *tmp;
    Entry *cur;

    HASH_ITER(hh, g_entries, cur, tmp) {
        if ((cur->last_updated + TIMEOUT_ENTRY) < gstate.time_now) {
            log_debug("timeout entry %04x", cur->src_id);
            HASH_DEL(g_entries, cur);
        }
    }
}

static Entry *entry_find(uint32_t src_id)
{
    Entry *cur = NULL;
    HASH_FIND_INT(g_entries, &src_id, cur);
    return cur;
}

static Entry *entry_add(uint32_t src_id, uint16_t seq_num, uint8_t hop_count, const Address *addr)
{
    Entry *e = (Entry*) malloc(sizeof(Entry));

    e->src_id = src_id;
    e->hop_count = hop_count;
    e->seq_num = seq_num;
    e->last_updated = gstate.time_now;
    memcpy(&e->addr, addr, sizeof(Address));

    HASH_ADD_INT(g_entries, src_id, e);

    return e;
}

static void handle_DATA(const Address *from_addr, DATA *p, unsigned recv_len)
{
    if (recv_len < offsetof(DATA, payload) || recv_len != (offsetof(DATA, payload) + p->length)) {
        log_debug("invalid packet size => drop");
        return;
    }

    log_debug("data packet: %s / %04x => %04x",
        str_addr2(from_addr), p->src_id, p->dst_id);

    if (p->src_id == gstate.own_id) {
        log_debug("own source id => drop packet");
        return;
    }

    // update routing table
    Entry *entry = entry_find(p->src_id);
    if (entry) {
        // packet already seen
        if (p->seq_num <= entry->seq_num) {
            if (p->seq_num == entry->seq_num && p->hop_count < entry->hop_count) {
                memcpy(&entry->addr, &from_addr, sizeof(Address));
                entry->last_updated = gstate.time_now;
            }
            // old packet => drop
            log_debug("old sequence number %d (current is %d) => drop packet",
                (int) p->seq_num, (int) entry->seq_num);
            return;
        } else {
            entry->seq_num = p->seq_num;
            entry->last_updated = gstate.time_now;
        }
    } else {
        entry = entry_add(p->src_id, p->seq_num, p->hop_count, from_addr);
    }

    // accept packet
    if (p->dst_id == gstate.own_id) {
        log_debug("write %u bytes to %s => accept packet", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        if (write(gstate.tun_fd, p->payload, p->length) != p->length) {
            log_error("write() %s", strerror(errno));
        }
        return;
    }

    // forward packet
    entry = entry_find(p->dst_id);
    if (entry) {
        log_debug("forward as ucast");
        p->hop_count += 1;
        send_one(&entry->addr, p, recv_len);
    } else {
        log_debug("forward as bcast");
        p->hop_count += 1;
        send_all(p, recv_len);
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
        ssize_t read_len = read(fd, &data.payload[0], sizeof(data.payload));

        if (read_len <= 0) {
            break;
        }

        if (parse_ip_packet(&dst_id, &data.payload[0], read_len)) {
            continue;
        }

        if (dst_id == gstate.own_id) {
            log_warning("send packet to self => drop packet");
            continue;
        }

        data.seq_num = g_sequence_number++;
        data.hop_count = 0;
        data.src_id = gstate.own_id;
        data.dst_id = dst_id;
        data.length = read_len;

        Entry *entry = entry_find(data.src_id);
        if (entry) {
            log_debug("send to one");
            send_one(&entry->addr, &data, offsetof(DATA, payload) + read_len);
        } else {
            log_debug("send to all");
            send_all(&data, offsetof(DATA, payload) + read_len);
        }
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
    set_macaddr(&from_addr, &eh->h_source[0], ifindex);
    set_macaddr(&to_addr, &eh->h_dest[0], ifindex);

    log_debug("got Ethernet packet %s => %s (%s)", str_addr2(&from_addr), str_addr2(&to_addr), str_ifindex(ifindex));

    switch (payload[0]) {
    case TYPE_DATA:
        handle_DATA(&from_addr, (DATA*) payload, payload_len);
        break;
    default:
        log_warning("unknown packet type %d from %s (%s)", payload[0], str_addr2(&from_addr),  str_ifindex(ifindex));
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

        fprintf(fp, "src_id seq_num hop-count last-updated prev-hop\n");
        HASH_ITER(hh, g_entries, cur, tmp) {
            fprintf(fp, "%04x %u %u %s %s\n",
                cur->src_id,
                (unsigned) cur->seq_num,
                (unsigned) cur->hop_count,
                format_duration(buf, gstate.time_started, cur->last_updated),
                str_addr2(&cur->addr)
            );
        }
    } else {
        return 1;
    }

    return 0;
}

static void init()
{
    // call at least every second
    net_add_handler(-1, &periodic_handler);
}

void flood_1_register()
{
    static const Protocol p = {
        .name = "flood-1",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console = &console_handler,
    };

    register_protocol(&p);
}
