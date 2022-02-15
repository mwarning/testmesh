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
#include "../net.h"
#include "../tun.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
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
    uint16_t payload_length;
    //uint8_t payload[ETH_FRAME_LEN];
} DATA;

static uint8_t *get_data_payload(const DATA *data)
{
    return ((uint8_t*) data) + sizeof(DATA);
}

static size_t get_data_size(const DATA *data)
{
    return sizeof(DATA) + data->payload_length;
}

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
    Entry *cur;
    HASH_FIND(hh, g_entries, &id, sizeof(uint32_t), cur);
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

static void handle_DATA(const Address *addr, DATA *p, size_t recv_len)
{
    if (recv_len < sizeof(DATA) || recv_len != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (p->src_id == gstate.own_id) {
        log_debug("DATA: own source id => drop");
        return;
    }

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x",
        str_addr(addr), p->src_id, p->dst_id);

    Entry *entry = entry_find(p->src_id);

    if (entry) {
        entry->last_updated = gstate.time_now;
        if (is_newer_seq_num(entry->seq_num, p->seq_num)) {
            entry->seq_num = p->seq_num;
        } else {
            // old packet => drop
             log_debug("DATA: drop packet with old sequence number %u (current is %u)",
                p->seq_num, entry->seq_num);
            return;
        }
    } else {
        entry = entry_add(p->src_id, p->seq_num);
    }

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: write %u bytes to %s", p->payload_length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        tun_write(get_data_payload(p), p->payload_length);
    } else {
        log_debug("DATA: send all");
        send_bcasts_l2(p, recv_len);
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    DATA *data = (DATA*) (packet - sizeof(DATA));

    data->type = TYPE_DATA;
    data->seq_num = g_sequence_number++;
    data->src_id = gstate.own_id;
    data->dst_id = dst_id;
    data->payload_length = packet_length;

    log_debug("send DATA packet as broadcast");
    send_bcasts_l2(data, get_data_size(data));
}

static void ext_handler_l2(const Address *src_addr, uint8_t *packet, size_t packet_length)
{
    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(src_addr, (DATA*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02 from %s", packet[0], str_addr(src_addr));
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
        int count = 0;

        fprintf(fp, "id seq_num last_updated\n");
        HASH_ITER(hh, g_entries, cur, tmp) {
            fprintf(fp, "0x%08x %u %s\n",
                cur->id,
                cur->seq_num,
                str_duration(gstate.time_started, cur->last_updated)
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
