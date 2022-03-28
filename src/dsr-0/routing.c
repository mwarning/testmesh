#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <linux/if_ether.h>   //ETH_ALEN(6),ETH_HLEN(14),ETH_FRAME_LEN(1514),struct ethhdr

#include "../ext/utlist.h"
#include "../ext/seqnum_cache.h"
#include "../ext/packet_cache.h"
#include "../log.h"
#include "../utils.h"
#include "../net.h"
#include "../tun.h"
#include "../unix.h"
#include "../console.h"
#include "../main.h"
#include "../interfaces.h"

#include "routing.h"

/*
 * Dynamic Source Routing
 */

#define MAX_PATH_COUNT 30
#define PATH_CACHE_TIMEOUT_SECONDS 60
#define SEQNUM_CACHE_TIMEOUT_SECONDS 5
#define PACKET_CACHE_TIMEOUT_SECONDS 5

enum {
    ADDR_TYPE_MAC,
    ADDR_TYPE_IPV6,
    ADDR_TYPE_IPV4
};

// memory "efficient" address representation
typedef struct {
    uint8_t type;
    uint16_t port; // only needed for IP address
    uint16_t ifindex; // only needed for MAC + link local addresses
    union {
        struct mac mac;
        struct in6_addr in6;
        struct in_addr in4;
        //char hostname[16]; // ?
    } addr;
} Addr;

enum {
    TYPE_RREQ,
    TYPE_RREP,
    TYPE_DATA
};

// always send as broadcast
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint8_t path_count;
    Addr path[MAX_PATH_COUNT]; // route to destination (so far)
} RREQ;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count;
    uint16_t seq_num;
    uint32_t src_id;
    uint32_t dst_id;
    uint8_t path_count;
    Addr path[MAX_PATH_COUNT]; // route to destination, may be updated on the way back
    /*
    uint8_t dst_path_count;
    uint8_t src_path_count;
    */
} RREP;

typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t hop_count; // used to get the entry from path
    uint32_t src_id;
    uint32_t dst_id;
    uint8_t path_count;
    uint16_t payload_length; // length in bytes
    // invisible fields, because they have variable length
    //uint8_t payload[ETH_FRAME_LEN];
    //uint32_t path[MAX_PATH_COUNT]; // route to destination
} DATA;

typedef struct PathCacheEntry_ {
    uint32_t dst_id;
    Addr path[MAX_PATH_COUNT];
    uint32_t path_count;
    time_t last_updated;
    struct PathCacheEntry_ *next;
} PathCacheEntry;


static PathCacheEntry *g_path_cache = NULL;
static uint16_t g_sequence_number = 0;

static const Addr *address2addr(const Address *address)
{
    static Addr addr;
    memset(&addr, 0, sizeof(addr));

    switch (address->family) {
        case AF_MAC:
            addr.type = ADDR_TYPE_MAC;
            addr.ifindex = address->mac.ifindex;
            memcpy(&addr.addr.mac, &address->mac.addr, 6);
            return &addr;
        case AF_INET:
            addr.type = ADDR_TYPE_IPV4;
            //addr.ifindex = address->ip4.ifindex; // does not exist...
            addr.port = ntohs(address->ip4.sin_port);
            memcpy(&addr.addr.in4, &address->ip4.sin_addr, 4);
            return &addr;
        case AF_INET6:
            addr.type = ADDR_TYPE_IPV6;
            addr.port = ntohs(address->ip6.sin6_port);
            memcpy(&addr.addr.in6, &address->ip6.sin6_addr, 16);
            if (addr_is_link_local((struct sockaddr_storage*) &address->ip6.sin6_addr)) {
                addr.ifindex = ntohs(address->ip6.sin6_scope_id);
            }
            return &addr;
        default:
            exit(1);
    }
}

static const Address *addr2address(const Addr *addr)
{
    static Address address;
    memset(&address, 0, sizeof(address));

    switch (addr->type) {
        case ADDR_TYPE_MAC:
            address.family = AF_MAC;
            address.mac.ifindex = addr->ifindex;
            memcpy(&address.mac.addr, &addr->addr.mac, 6);
            return &address;
        case ADDR_TYPE_IPV4:
            address.family = AF_INET;
            //address->ip4.ifindex = addr.ifindex; // does not exist...
            address.ip4.sin_port = addr->port;
            memcpy(&address.ip4.sin_addr, &addr->addr.in4, 4);
            return &address;
        case ADDR_TYPE_IPV6:
            address.family = AF_INET6;
            address.ip6.sin6_port = addr->port;
            memcpy(&address.ip6.sin6_addr, &addr->addr.in6, 16);
            if (addr_is_link_local((struct sockaddr_storage*) &address.ip6)) {
                address.ip6.sin6_scope_id = htons(addr->ifindex);
            }
            return &address;
        default:
            exit(1);
    }
}

static size_t get_rreq_size(RREQ *p)
{
    return (offsetof(RREQ, path) + (sizeof(Addr) * p->path_count));
}

static size_t get_rrep_size(RREP *p)
{
    return (offsetof(RREP, path) + (sizeof(Addr) * p->path_count));
}

static size_t get_data_size(DATA *p)
{
    return (sizeof(DATA) + p->payload_length + (sizeof(Addr) * p->path_count));
}

static uint8_t* get_data_payload(DATA *p)
{
    return ((uint8_t*) p) + sizeof(DATA);
}

static Addr* get_data_path(DATA *p)
{
    return (Addr*) (((uint8_t*) p) + sizeof(DATA) + p->payload_length);
}

static char *format_path(const Addr *path, uint32_t path_count)
{
    static char buf[MAX_PATH_COUNT * 25];
    char *cur = buf;
    cur[0] = 0;
    for (size_t i = 0; i < path_count; i++) {
        ssize_t left = (buf + sizeof(buf)) - cur;
        switch (path[i].type) {
            case ADDR_TYPE_MAC:
                cur += snprintf(cur, left, i ? ", %s/%u" : "%s/%u", str_mac(&path[i].addr.mac), path[i].ifindex);
                break;
            default:
                exit(1);
        }
    }
    return buf;
}

// called every second
static void path_cache_timeout()
{
    PathCacheEntry *tmp;
    PathCacheEntry *cur;

    LL_FOREACH_SAFE(g_path_cache, cur, tmp) {
        if ((cur->last_updated + PATH_CACHE_TIMEOUT_SECONDS) < gstate.time_now) {
            log_debug("timeout path cache entry for id 0x%08x", cur->dst_id);
            LL_DELETE(g_path_cache, cur);
            free(cur);
        }
    }
}

static PathCacheEntry *path_cache_lookup(uint32_t dst_id)
{
    PathCacheEntry *cur;

    LL_FOREACH(g_path_cache, cur) {
        if (cur->dst_id == dst_id) {
            return cur;
        }
    }

    return NULL;
}

static void path_cache_update(uint32_t dst_id, const void *path, uint32_t path_count)
{
    PathCacheEntry *e;

    e = path_cache_lookup(dst_id);

    if (e) {
        if (e->path_count <= path_count) {
            // update entry
            e->dst_id = dst_id;
            memcpy(&e->path[0], path, sizeof(Addr) * path_count);
            e->path_count = path_count;
            e->last_updated = gstate.time_now;
        }
    } else {
        e = (PathCacheEntry*) malloc(sizeof(PathCacheEntry));

        e->dst_id = dst_id;
        memcpy(&e->path[0], path, sizeof(Addr) * path_count);
        e->path_count = path_count;
        e->last_updated = gstate.time_now;

        LL_PREPEND(g_path_cache, e);
    }
}

static void send_cached_packet(uint32_t dst_id, const Addr *path, uint32_t path_count)
{
    uint8_t buffer[sizeof(DATA) + ETH_FRAME_LEN + sizeof(Addr) * MAX_PATH_COUNT];
    DATA *data = (DATA*) &buffer[0];

    uint8_t* data_payload = get_data_payload(data);
    size_t data_payload_length = 0;
    packet_cache_get_and_remove(data_payload, &data_payload_length, dst_id);

    if (data_payload_length == 0) {
        // no cached packet found
        return;
    }

    data->type = TYPE_DATA;
    data->hop_count = 0,
    data->src_id = gstate.own_id;
    data->dst_id = dst_id;
    data->path_count = path_count;
    data->payload_length = data_payload_length;

    Addr* data_path = get_data_path(data);
    memcpy(data_path, path, sizeof(Addr) * path_count);

    const Address *addr = addr2address(&path[0]);

    log_debug("send DATA (0x%08x => 0x%08x) to %s via [%s]",
        data->src_id, data->dst_id, str_addr(addr), format_path(path, path_count));

    send_ucast_l2(addr, data, get_data_size(data));
}

// Route Reply
static void handle_RREP(const Address *addr, RREP *p, size_t recv_len)
{
    if (recv_len < offsetof(RREP, path)
            || recv_len != get_rrep_size(p)
            || p->path_count > MAX_PATH_COUNT
            || p->path_count == 0
            || p->hop_count > p->path_count) {
        log_debug("RREP: invalid packet size => drop");
        return;   
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_debug("RREQ packet already received => drop");
        return;
    }

    Addr path[MAX_PATH_COUNT];
    memcpy(path, &p->path[0], sizeof(Addr) * p->path_count);

    log_debug("RREP: got packet from %s / 0x%08x => 0x%08x / seq_num: %u / hop_count: %u / [%s]",
        str_addr(addr), p->src_id, p->dst_id, p->seq_num, p->hop_count, format_path(path, p->path_count));

    if (p->dst_id == gstate.own_id) {
        p->hop_count += 1;

        if (p->path_count != p->hop_count) {
            log_error("RREP: packet invalid => drop");
            return;
        }

        log_debug("RREP: arrived at destination => accept");

        // Since the sender path set sender to path
        memcpy(&path[p->path_count - p->hop_count], address2addr(addr), sizeof(Address));

        // add path to cache
        path_cache_update(p->src_id, path, p->path_count);

        send_cached_packet(p->src_id, path, p->path_count);
    } else {
        if (p->path_count <= p->hop_count + 1) {
            log_debug("RREP: packet invalid => drop");
            return;
        }

        // overwrite the now used up address of the path to write the sender address 
        p->hop_count += 1;
        memcpy(&p->path[p->path_count - p->hop_count], address2addr(addr), sizeof(Address));

        const Addr *addr = &path[p->path_count - p->hop_count - 1];
        const Address *address = addr2address(addr);
        log_debug("RREP: send to next hop %s/%u => forward", str_addr(address), addr->ifindex);
        send_ucast_l2(address, p, recv_len);
    }
}

// Route Request
static void handle_RREQ(const Address *addr, RREQ *p, size_t recv_len)
{
    if (recv_len < offsetof(RREQ, path)
            || recv_len != get_rreq_size(p)
            || p->path_count >= MAX_PATH_COUNT
            || p->hop_count != p->path_count) {
        log_debug("RREQ: invalid packet size => drop");
        return;   
    }

    if (!seqnum_cache_update(p->src_id, p->seq_num)) {
        log_debug("RREQ: packet already received => drop");
        return;
    }

    Addr path[MAX_PATH_COUNT];
    memcpy(path, &p->path[0], sizeof(Addr) * p->path_count);

    log_debug("RREQ: got packet from %s / 0x%08x => 0x%08x / seq_num: %u / hop_count: %u / [%s]",
        str_addr(addr), p->src_id, p->dst_id, p->seq_num, p->hop_count, format_path(path, p->path_count));

    if (p->dst_id == gstate.own_id) {
        RREP rrep = {
            .type = TYPE_RREP,
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = p->src_id,
            .path_count = p->path_count,
        };

        // add sender
        memcpy(&path[p->path_count], address2addr(addr), sizeof(Addr));
        rrep.path_count += 1;

        memcpy(&rrep.path, path, sizeof(Addr) * rrep.path_count);

        log_debug("RREQ: send RREP response 0x%08x => 0x%08x [%s] => reply",
            rrep.src_id, rrep.dst_id, format_path(path, rrep.path_count));

        // add own sequence number to avoid processing this packet again
        seqnum_cache_update(rrep.src_id, rrep.seq_num);

        // send back as unicast
        send_ucast_l2(addr, &rrep, get_rrep_size(&rrep));
    } else {
        // add sender
        memcpy(&p->path[p->path_count], address2addr(addr), sizeof(Addr));
        p->path_count += 1;
        p->hop_count += 1;

        // for printing
        Addr path[MAX_PATH_COUNT];
        memcpy(path, &p->path, sizeof(Addr) * p->path_count);

        log_debug("RREQ: resend as broadcast => forward", format_path(path, p->path_count));

        // forward as broadcast
        send_bcasts_l2(p, get_rreq_size(p));
    }
}

static void handle_DATA(const Address *addr, DATA *p, size_t recv_len)
{
    if (recv_len < sizeof(DATA)
            || recv_len != get_data_size(p)
            || p->path_count > MAX_PATH_COUNT
            || p->hop_count >= p->path_count) {
        log_debug("DATA: invalid packet size => drop");
        return;
    }

    if (p->src_id == gstate.own_id) {
        log_debug("DATA: got packet from own source id => drop");
        return;
    }

    Addr *path = get_data_path(p);
    uint8_t *payload = get_data_payload(p);

    log_debug("DATA: got packet from %s / 0x%08x => 0x%08x / hop_count: %u / [%s]",
        str_addr(addr), p->src_id, p->dst_id, p->hop_count, format_path(path, p->path_count));

    if (p->dst_id == gstate.own_id) {
        // destination is the local tun0 interface => write packet to tun0
        tun_write(payload, p->payload_length);
    } else {
        if ((p->hop_count + 1) >= p->path_count) {
            log_debug("DATA: invalid hop_count => drop");
            return;
        }
        const Address *next_hop_addr = addr2address(
            &get_data_path(p)[p->hop_count + 1]
        );

        log_debug("DATA: send to next hop %s => forward", str_addr(next_hop_addr));

        p->hop_count += 1;

        // forward
        send_ucast_l2(next_hop_addr, p, get_data_size(p));
    }
}

// receive traffic from tun0 and send to peers
static void tun_handler(uint32_t dst_id, uint8_t *packet, size_t packet_length)
{
    PathCacheEntry *e = path_cache_lookup(dst_id);
    if (e) {
        DATA *data = (DATA*) (packet - sizeof(DATA));

        data->type = TYPE_DATA;
        data->hop_count = 0;
        data->src_id = gstate.own_id;
        data->dst_id = dst_id;
        data->path_count = e->path_count;
        data->payload_length = packet_length;

        memcpy(get_data_path(data), &e->path[0], sizeof(Addr) * e->path_count);

        log_debug("send new DATA 0x%08x => 0x%08x [%s]",
            data->src_id, data->dst_id, format_path(get_data_path(data), data->path_count));

        send_ucast_l2(addr2address(&e->path[0]), data, get_data_size(data));
    } else {
        RREQ rreq = {
            .type = TYPE_RREQ,
            .hop_count = 0,
            .seq_num = g_sequence_number++,
            .src_id = gstate.own_id,
            .dst_id = dst_id,
            .path_count = 0,
        };

        // avoid processing of this packet again
        seqnum_cache_update(rreq.src_id, rreq.seq_num);

        packet_cache_add(dst_id, packet, packet_length);

        log_debug("send new RREQ (0x%08x => 0x%08x)", rreq.src_id, rreq.dst_id);

        // we drop data until the path is discovered?
        send_bcasts_l2(&rreq, get_rreq_size(&rreq));
    }
}

static void ext_handler_l2(const Address *src_addr, uint8_t *packet, size_t packet_length)
{
    switch (packet[0]) {
    case TYPE_DATA:
        handle_DATA(src_addr, (DATA*) packet, packet_length);
        break;
    case TYPE_RREQ:
        handle_RREQ(src_addr, (RREQ*) packet, packet_length);
        break;
    case TYPE_RREP:
        handle_RREP(src_addr, (RREP*) packet, packet_length);
        break;
    default:
        log_warning("unknown packet type 0x%02x from %s", packet[0], str_addr(src_addr));
    }
}

static int console_handler(FILE *fp, int argc, char *argv[])
{
    if (argc == 1 && !strcmp(argv[0], "h")) {
        fprintf(fp, "n: print routing table\n");
    } else if (argc == 1 && !strcmp(argv[0], "n")) {
        int counter = 0;
        PathCacheEntry *cur;

        fprintf(fp, "dst-id\tupdated\tpath-count\tpath\n");
        LL_FOREACH(g_path_cache, cur) {
            fprintf(fp, "0x%08x\t%s\t%u\t[%s]\n",
                cur->dst_id,
                str_ago(cur->last_updated),
                (unsigned) cur->path_count,
                format_path(&cur->path[0], cur->path_count)
            );
            counter += 1;
        }
        fprintf(fp, "%d entries\n", counter);
    } else {
        return 1;
    }

    return 0;
}

static void init()
{
    seqnum_cache_init(SEQNUM_CACHE_TIMEOUT_SECONDS);
    packet_cache_init(PACKET_CACHE_TIMEOUT_SECONDS);
    net_add_handler(-1, &path_cache_timeout);
}

void dsr_0_register()
{
    static const Protocol p = {
        .name = "dsr-0",
        .init = &init,
        .tun_handler = &tun_handler,
        .ext_handler_l2 = &ext_handler_l2,
        .console = &console_handler,
    };

    protocols_register(&p);
}
