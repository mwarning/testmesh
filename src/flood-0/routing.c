#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>

#include "../ext/seqnum_cache.h"
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

#define SEQNUM_TIMEOUT_SEC 30


typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num; // sequence number
    uint32_t src_id;
    uint32_t dst_id;
    uint16_t payload_length;
    //uint8_t payload[ETH_FRAME_LEN];
} DATA;

static uint16_t g_sequence_number = 0;

static uint8_t *get_data_payload(const DATA *data)
{
    return ((uint8_t*) data) + sizeof(DATA);
}

static size_t get_data_size(const DATA *data)
{
    return sizeof(DATA) + data->payload_length;
}

static void handle_DATA(const Address *rcv, const Address *src, const Address *dst, DATA *p, size_t length)
{
    if (!address_is_broadcast(dst)) {
        log_trace("unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length < sizeof(DATA) || length != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (p->src_id == gstate.own_id) {
        log_trace("DATA: own source id => drop");
        return;
    }

    uint8_t is_new = seqnum_cache_update(p->src_id, p->seq_num);

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x",
        str_addr(src), p->src_id, p->dst_id);

    if (!is_new) {
        log_trace("DATA: received old packet => drop");
        return;
    }

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: destination reached => accept");

        // destination is the local tun0 interface => write packet to tun0
        tun_write(get_data_payload(p), p->payload_length);
    } else {
        log_debug("DATA: destination not reached => rebroadcast");
        send_bcast_l2(0, p, length);
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    DATA *p = (DATA*) (packet - sizeof(DATA));

    p->type = TYPE_DATA;
    p->seq_num = g_sequence_number++;
    p->src_id = gstate.own_id;
    p->dst_id = dst_id;
    p->payload_length = packet_length;

    seqnum_cache_update(p->src_id, p->seq_num);

    log_debug("send DATA packet as broadcast");
    send_bcast_l2(0, p, get_data_size(p));
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
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src));
    }
}

static void init()
{
    seqnum_cache_init(SEQNUM_TIMEOUT_SEC);
}

void flood_0_register()
{
    static const Protocol p = {
        .name = "flood-0",
        .init_handler = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
    };

    protocols_register(&p);
}
