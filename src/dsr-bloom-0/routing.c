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
    uint16_t length; // might not be needed
    uint8_t payload[2000];
} DATA;

static void bloom_init(uint8_t *bloom, uint32_t id)
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

static int bloom_test(const uint8_t *bloom, uint32_t id)
{
    uint8_t bloom_id[BLOOM_M];
    bloom_init(&bloom_id[0], id);

    for (int i = 0; i < BLOOM_M; i++) {
        if ((bloom_id[i] & bloom[i]) != bloom_id[i]) {
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

static void handle_DATA(int ifindex, const Address *addr, DATA *p, unsigned recv_len)
{
    if (recv_len < offsetof(DATA, payload) || recv_len != (offsetof(DATA, payload) + p->length)) {
        log_debug("invalid packet size => drop");
        return;
    }

    log_debug("got DATA packet: %s / 0x%08x => 0x%08x",
        str_addr(addr), p->src_id, p->dst_id);

    if (p->src_id == gstate.own_id) {
        log_debug("own source id => drop packet");
        return;
    }

    if (p->dst_id == gstate.own_id) {
        log_debug("write %u bytes to %s", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        tun_write(p->payload, p->length);
    } else if (!bloom_test(&p->bloom[0], gstate.own_id)) {
        bloom_add(&p->bloom[0], gstate.own_id);
        send_bcasts_l2(p, recv_len);
    } else {
        // drop packet
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

        data.src_id = gstate.own_id;
        data.dst_id = dst_id;
        data.length = read_len;
        memset(&data.bloom, 0, sizeof(data.bloom));

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
        handle_DATA(ifindex, &from_addr, (DATA*) payload, payload_len);
        break;
    default:
        log_warning("unknown packet type %u from %s (%s)", (unsigned) buffer[0], str_addr(&from_addr), str_ifindex(ifindex));
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
