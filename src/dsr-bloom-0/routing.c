#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <linux/if_ether.h>   //ETH_ALEN(6),ETH_HLEN(14),ETH_FRAME_LEN(1514),struct ethhdr

#include "../log.h"
#include "../utils.h"
#include "../net.h"
#include "../tun.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

#include "routing.h"

#define BLOOM_M 8   // size of the bloom filter (in bytes)
#define BLOOM_K 1   // hash methods / bits to be set per item

#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))

enum {
    TYPE_DATA
};

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id; //needed for the IP header that is contructed on the other end
    uint32_t dst_id;
    uint8_t bloom[BLOOM_M];
    uint16_t payload_length; // might not be needed
    //uint8_t payload[ETH_FRAME_LEN]; // invisible
} DATA;

static uint8_t *get_data_payload(const DATA *data)
{
    return ((uint8_t*) data) + sizeof(DATA);
}

static size_t get_data_size(const DATA *data)
{
    return sizeof(DATA) + data->payload_length;
}

static void bloom_init(uint8_t *bloom, uint32_t id)
{
    memset(bloom, 0, BLOOM_M);

    uint64_t next = id;
    // pseudo random generator
    for (size_t i = 0; i < BLOOM_K; i++) {
        next = next * 1103515245 + 12345;
        uint32_t r = (next / 65536) % 32768;
        uint32_t j = r % (BLOOM_M * 8);
        BLOOM_BITSET(bloom, j);
    }
}

static bool bloom_test(const uint8_t *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M];
    bloom_init(&bloom_id[0], id);

    for (size_t i = 0; i < BLOOM_M; i++) {
        if ((bloom_id[i] & bloom[i]) != bloom_id[i]) {
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

static void handle_DATA(const Address *addr, DATA *p, size_t recv_len)
{
    if (recv_len < sizeof(DATA) || recv_len != get_data_size(p)) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    log_debug("DATA: got packet: %s / 0x%08x => 0x%08x",
        str_addr(addr), p->src_id, p->dst_id);

    if (p->src_id == gstate.own_id) {
        log_debug("DATA: own source id => drop");
        return;
    }

    uint8_t *payload = get_data_payload(p);

    if (p->dst_id == gstate.own_id) {
        log_debug("DATA: write %u bytes to %s => accept", (unsigned) p->payload_length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        tun_write(payload, p->payload_length);
    } else if (!bloom_test(&p->bloom[0], gstate.own_id)) {
        log_debug("DATA: own id not in bloom filter => forward");
        bloom_add(&p->bloom[0], gstate.own_id);
        send_bcasts_l2(p, recv_len);
    } else {
        log_debug("DATA: own id in bloom filter => drop");
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    DATA *data = (DATA*) (packet - sizeof(DATA));

    data->type = TYPE_DATA;
    data->src_id = gstate.own_id;
    data->dst_id = dst_id;
    data->payload_length = packet_length;
    memset(&data->bloom, 0, sizeof(data->bloom));

    send_bcasts_l2(data, get_data_size(data));
}

static void ext_handler_l2(const Address *rcv, const Address *src, const Address *dst, uint8_t *packet, size_t packet_length)
{
    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(src, (DATA*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src));
    }
}

static void init()
{
    // nothing to do
}

void dsr_bloom_0_register()
{
    static const Protocol p = {
        .name = "dsr-bloom-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
    };

    protocols_register(&p);
}
