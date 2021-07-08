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
#include "../interfaces.h"
#include "../main.h"


#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))
#define BLOOM_ADD(filter, hashv)                                                \
  BLOOM_BITSET(((uint8_t*) filter), ((hashv) & (uint32_t)((1UL << sizeof(*filter)) - 1U)))

#define BLOOM_TEST(filter, hashv)                                               \
  BLOOM_BITTEST(((uint8_t*) filter), ((hashv) & (uint32_t)((1UL << sizeof(*filter)) - 1U)))

enum {
    TYPE_DATA
};

typedef struct sockaddr_storage Address;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint32_t src_id;
    uint32_t dst_id;
    uint8_t bloom[8];
    uint16_t length; // might not be needed
    uint8_t payload[2000];
} DATA;

static uint32_t g_own_id = 0; // set from the fe80 addr of tun0


static void handle_DATA(int ifindex, const Address *addr, DATA *p, unsigned recv_len)
{
    log_debug("got data packet: %s / %04x => %04x",
        str_addr(addr), p->src_id, p->dst_id);

    if (p->src_id == g_own_id) {
        log_debug("own source id => drop");
        return;
    }

    if (p->dst_id == g_own_id) {
        log_debug("write %u bytes to %s => accept", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        if (write(gstate.tun_fd, p->payload, p->length) != p->length) {
            log_error("write() %s", strerror(errno));
        }
    } else if (!BLOOM_TEST(&p->bloom, g_own_id)) {
        log_debug("forward as mcast");
        BLOOM_ADD(&p->bloom, g_own_id);
        send_mcasts(p, recv_len);
    } else {
        log_debug("own id in packet header => drop");
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
            log_warning("send packet to self => drop");
            continue;
        }

        data.src_id = g_own_id;
        data.dst_id = dst_id;
        data.length = read_len;
        memset(&data.bloom, 0, sizeof(data.bloom));

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

static void init()
{
    // get id from IP address
    id_get6(&g_own_id, &gstate.tun_addr);
}

void dsr_bloom_1_register()
{
    static const Protocol p = {
        .name = "dsr-bloom-1",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler = &ext_handler,
    };

    register_protocol(&p);
}
