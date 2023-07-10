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
    TYPE_DATA_FF,
    TYPE_DATA_PF
};

#define FULL_FLOOD_SEND_INTERVAL 30

// flooded data packet
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint16_t seq_num; // sequence number
    uint32_t src_id; // source
    uint32_t dst_id; // destination
    uint32_t sender;
    uint32_t prev_sender;
    uint16_t payload_length;
    //uint8_t payload[ETH_FRAME_LEN];
} DATA;

static uint8_t g_is_critical = 1;
static time_t g_is_critical_time = 0;
static uint16_t g_sequence_number = 0;

static uint8_t *get_data_payload(const DATA *data)
{
    return ((uint8_t*) data) + sizeof(DATA);
}

static size_t get_data_size(const DATA *data)
{
    return sizeof(DATA) + data->payload_length;
}

static void handle_DATA(const Address *rcv, const Address *src, const Address *dst, DATA *p, size_t length, uint8_t is_full_flood)
{
    if (!address_is_broadcast(dst)) {
        log_trace("DATA: unexpected destination (%s) => drop", str_addr(dst));
        return;
    }

    if (length < sizeof(DATA) || length != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    uint8_t is_new = seqnum_cache_update(p->src_id, p->seq_num);

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x (seq_num: %u, sender: 0x%08x, prev_sender: 0x%08x, full_flood: %s)",
        str_addr(src), p->src_id, p->dst_id, p->seq_num, p->sender, p->prev_sender, str_enabled(is_full_flood));

    if (is_full_flood) {
        // prevent us from starting a full flood
        g_is_critical_time = gstate.time_now;

        if (is_new) {
            // packet seen the first time
            if (p->dst_id == gstate.own_id) {
                log_debug("DATA: packet arrived => accept");
                tun_write(get_data_payload(p), p->payload_length);
                // TODO: do we need to forward here as well?
            } else {
                log_debug("DATA: new packet => forward");
                p->prev_sender = p->sender;
                p->sender = gstate.own_id;
                send_bcast_l2(0, p, length);
            }
        } else {
            // packet already seen
            if (p->prev_sender == gstate.own_id) {
                // echo received
                g_is_critical = 1;
                log_debug("DATA: duplicate packet (echo) => critical");
            } else {
                log_debug("DATA: duplicate packet (no echo) => drop");
            }
        }
    } else {
        if (!is_new) {
            log_debug("DATA: duplicate packet => drop");
        } else if (p->dst_id == gstate.own_id) {
            log_debug("DATA: destination reached => accept");

            // destination is the local tun0 interface => write packet to tun0
            tun_write(get_data_payload(p), p->payload_length);
        } else {
            if (g_is_critical) {
                log_debug("DATA: is critical => rebroadcast");
                send_bcast_l2(0, p, length);
            } else {
                log_debug("DATA: not critical => drop");
            }
        }
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    uint8_t is_full_flood = ((g_is_critical_time + FULL_FLOOD_SEND_INTERVAL) < gstate.time_now);

    DATA *p = (DATA*) (packet - sizeof(DATA));

    p->type = is_full_flood ? TYPE_DATA_FF : TYPE_DATA_PF;
    p->seq_num = g_sequence_number++;
    p->src_id = gstate.own_id;
    p->dst_id = dst_id;
    p->sender = gstate.own_id;
    p->prev_sender = gstate.own_id;
    p->payload_length = packet_length;

    seqnum_cache_update(p->src_id, p->seq_num);

    log_debug("send DATA packet as broadcast (is_full_flood: %s)", str_enabled(is_full_flood));

    send_bcast_l2(0, p, get_data_size(p));
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    if (!address_is_broadcast(dst) && !address_equal(dst, rcv)) {
        // packet is not for us (possible e.g. when device is in monitor mode)
        return;
    }

    switch (packet[0]) {
    case TYPE_DATA_FF:
        handle_DATA(rcv, src, dst, (DATA*) packet, packet_length, 1);
        break;
    case TYPE_DATA_PF:
        handle_DATA(rcv, src, dst, (DATA*) packet, packet_length, 0);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src));
    }
}

static bool console_handler(FILE* fp, const char *argv[])
{
    if (match(argv, "i")) {
        fprintf(fp, "critical:   %s (%s ago)\n",
            str_enabled(g_is_critical), str_ago(g_is_critical_time));
    } else {
        return true;
    }

    return false;
}

static void periodic_handler()
{
    // timeout critical
    if (g_is_critical && ((g_is_critical_time + FULL_FLOOD_SEND_INTERVAL) < gstate.time_now)) {
        log_debug("timeout for critical");
        g_is_critical = 0;
    }
}

static void init()
{
    uint32_t r = 0;
    bytes_random(&r, sizeof(r));

    g_is_critical_time = gstate.time_now + (r % 10) - FULL_FLOOD_SEND_INTERVAL;

    seqnum_cache_init(FULL_FLOOD_SEND_INTERVAL);

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
        .console_handler = &console_handler,
    };

    protocols_register(&p);
}
