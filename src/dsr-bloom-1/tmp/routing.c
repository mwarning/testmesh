#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <stddef.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <math.h>

#include "../log.h"
#include "../utils.h"
#include "../net.h"
#include "../unix.h"
#include "../interfaces.h"
#include "../console.h"
#include "../main.h"
#include "../utlist.h"
#include "../uthash.h"
#include "../utarray.h"

#include "helper.h"
#include "routing.h"

#define TIMEOUT_NODES 1000
#define TIMEOUT_CACHE 10
#define BLOOM_ENABLED

#ifdef BLOOM_ENABLED
#define BLOOM_BITSET(bv, idx) (bv[(idx)/8U] |= (1U << ((idx)%8U)))
#define BLOOM_BITTEST(bv, idx) (bv[(idx)/8U] & (1U << ((idx)%8U)))
#define BLOOM_ADD(filter, hashv)                                                \
  BLOOM_BITSET(((uint8_t*) filter), ((hashv) & (uint32_t)((1UL << sizeof(*filter)) - 1U)))

#define BLOOM_TEST(filter, hashv)                                               \
  BLOOM_BITTEST(((uint8_t*) filter), ((hashv) & (uint32_t)((1UL << sizeof(*filter)) - 1U)))
#else
#define BLOOM_ADD(filter, hashv) 1
#define BLOOM_TEST(filter, hashv) 1
#endif

/*
gate: a peer or interface

Packet comes from 
 tun_handler // traffic from tun0
 ucast_handler // incoming traffic from IP addresses
 mcast_handler // incoming traffic over WiFi

packet fields:
  destination_id
  path_bloom

- for each gate there is a bloom filter
- if a packet with bloom filter A arrives
  - add A to bloom filter of the gate 
  - compare destiantion_od to other gates bloom filter
    - forward on all matched gates (add own id to path_bloom)
- but how to prevent loops?
  - do not forward if own bits are set in path_bloom!
- how to choose best path if multiple paths are possible?
  - use bandwidth metric
- how to detect missing nodes?
  - remove random bits over time?
    - improve by using counting bloom filter?
  - a destination must be backend by returned traffic?
*/

enum {
    TYPE_DATA,
    TYPE_INTRO,
    TYPE_HELLO // if neighbor does not know the node => broadcast, register and drop otherwise
};

typedef struct __attribute__((__packed__)) {
    uint8_t type : 2;
    uint32_t src_id; //needed for the IP header that is contructed on the other end
    uint32_t dst_id;
    uint16_t seq_no;
    uint16_t hop_no;
    uint16_t bloom;
    uint16_t length; // might not be needed
    uint8_t payload[2000];
} DATA;

// introduction
typedef struct __attribute__((__packed__)) {
    uint8_t type : 2;
    uint16_t bloom;
    Addr addr;
} INTRO;

// Hello / Keep Alive
typedef struct __attribute__((__packed__)) {
    uint8_t type : 2;
    uint16_t src_id;
    uint16_t seq_no;
    uint16_t hop_no;
} HELLO;

typedef struct Interface {
    int ifindex;
    uint16_t bloom;
    struct Interface *next;
} Interface;

typedef struct Peer {
    time_t last_seen;
    Addr addr;
    int ifindex;
    uint16_t bloom;
    struct Peer *next;
} Peer;

typedef struct {
  uint32_t id; // destination
  time_t last_seen;
  Addr addr; // might be low level MAC address
  int ifindex;
  uint16_t seq_no; // always increases, only for broadcasts
  uint16_t hop_no; // our metric
  uint32_t received_bytes;
  uint16_t bloom;
  //cached_entry...
  UT_hash_handle hh;
} Node;

/*
 * Record the brodcasts that we have heard.
 * If we hear someone broadcasting our own broadcast,
 * then mark ourselves critical.
 *
 * If nobody repeats my broadcast, then do not broadcast.
 * But what if the other party does unicast my broadcast? 
 */
typedef struct {
    uint16_t seq_no;
    uint16_t hop_no;
    int ifindex;
    time_t time_added;
    UT_hash_handle hh;
} OVERHEARD_BROADCAST;

static OVERHEARD_BROADCAST *g_overheard_broadcasts = NULL;


void overheard_broadcasts_timeout()
{
    OVERHEARD_BROADCAST *tmp;
    OVERHEARD_BROADCAST *cur;

    HASH_ITER(hh, g_overheard_broadcasts, cur, tmp) {
        if ((cur->time_added + 1) < gstate.time_now) {
            HASH_DEL(g_overheard_broadcasts, cur);
            free(cur);
        }
    }
}

static Node *g_nodes = NULL;
static Peer *g_peers = NULL;
static Interface *g_interfaces = NULL;
static uint32_t g_own_id = 0;
static uint16_t g_seqno = 0;


int is_neighbor(const Node *node)
{
    return (node->hop_no == 1);
}

// send over all interfaces/peers
// we do not know where to forward a packet
void send_all(uint32_t dst_id, const void* data, int data_len)
{
    Node *cur;
    Node *tmp;

    int forwarded_times = 0;

    Interface *ifa = NULL;
    //HASH_FIND_INT(g_peers, &id, cur);
    LL_FOREACH(g_interfaces, ifa) {
        if (BLOOM_TEST(&ifa->bloom, dst_id)) {
            send_mcast(ifa->ifindex, data, data_len);
            forwarded_times += 1;
            break;
        }
    }

/*
    // send at most one packet per interface as broadcast
    struct interface *ifa = NULL;
    while ((ifa = utarray_next(get_interfaces(), ifa))) {
        //printf("ifindex: %d (%s)\n", ifa->ifindex, ifa->ifname);
        // do we know someone on that interface?
        HASH_ITER(hh, g_nodes, cur, tmp) {
            if (is_neighbor(cur) && cur->ifindex == ifa->ifindex) {
                if (BLOOM_TEST(&cur->bloom, dst_id)) {
                    send_mcast(ifa->ifindex, data, data_len);
                    forwarded_times += 1;
                    break;
                }
            }
        }
    }

    // send at most one packet per remote neighbor as unicast
    HASH_ITER(hh, g_nodes, cur, tmp) {
        if (is_neighbor(cur) && !addr_is_link_local(&cur->addr)) {
            if (BLOOM_TEST(&cur->bloom, dst_id)) {
                send_ucast(&cur->addr, data, data_len);
                forwarded_times += 1;
            }
        }
    }
*/
    log_debug("Data to %04x forwarded %d times", dst_id, forwarded_times);
}

void node_free(Node *node)
{
    free(node);
}

Node *node_find(uint32_t id)
{
    Node *cur = NULL;
    HASH_FIND_INT(g_nodes, &id, cur);
    return cur;
}

void node_timeout()
{
    Node *tmp;
    Node *cur;

    HASH_ITER(hh, g_nodes, cur, tmp) {
        if ((cur->last_seen + TIMEOUT_NODES) < gstate.time_now) {
            log_debug("Timeout node %04x", cur->id);
            HASH_DEL(g_nodes, cur);
            node_free(cur);
        }
    }
}

// get neighbor node by address
Node *node_find_neighbor_by_addr(int ifindex, const Addr *addr)
{
    Node *tmp;
    Node *cur;

    HASH_ITER(hh, g_nodes, cur, tmp) {
        if (cur->hop_no == 1 && cur->ifindex == ifindex && addr_equal(&cur->addr, addr)) {
            return cur;
        }
    }
    return NULL;
}

Node *node_add(const Addr *addr, int ifindex, uint32_t id, uint16_t seq_no, uint16_t hop_no, uint32_t bytes)
{
    Node *elt = (Node*) malloc(sizeof(Node));
    /*#*elt = (Node) {
        .id = id,
        seq_no = seq_no,
    };*/
    elt->id = id;
    elt->seq_no = seq_no;
    elt->hop_no = hop_no;
    memcpy(&elt->addr, addr, sizeof(Addr));
    elt->ifindex = ifindex;
    elt->last_seen = gstate.time_now;
    elt->bloom = 0;
    elt->received_bytes = bytes;

    HASH_ADD_INT(g_nodes, id, elt);
    return elt;
}

Peer *peer_find(const Addr *addr)
{
    Peer *cur = NULL;
    //HASH_FIND_INT(g_peers, &id, cur);
    LL_FOREACH(g_peers, cur) {
        if (memcmp(&cur->addr, addr, sizeof(Addr)) == 0) {
            return cur;
        }
    }
    return NULL;
}

Interface *interface_add(int ifindex)
{
    Interface *elt = (Interface*) malloc(sizeof(Interface));
    elt->ifindex = ifindex;
    elt->bloom = 0;

    LL_PREPEND(g_interfaces, elt);

    return elt;
}

Peer *peer_add(const Addr *addr, int ifindex)
{
    Peer *elt = (Peer*) malloc(sizeof(Peer));
    memcpy(&elt->addr, addr, sizeof(Addr));
    elt->ifindex = ifindex;
    elt->bloom = 0;
    elt->last_seen = gstate.time_now;

    LL_PREPEND(g_peers, elt);
    //HASH_ADD_INT(g_peers, id, elt);
    return elt;
}

Node *node_update(const Addr *addr, int ifindex, uint32_t id, uint16_t seq_no, uint16_t hop_no, uint32_t bytes)
{
    //TODO: also update traffic and seen value of neighbor

    Node *node = node_find(id);
    if (node) {
        if (hop_no < node->hop_no) {
            node->hop_no = hop_no;
            node->ifindex = ifindex;
            memcpy(&node->addr, addr, sizeof(Addr));
        }
        //node->seq_no = MAX(node->seq_no, seq_no);
        node->last_seen = gstate.time_now;
        node->received_bytes += bytes; // TODO: handle overflow
    } else {
        node = node_add(addr, ifindex, id, seq_no, hop_no, bytes);
    }

    return node;
}

Peer *peer_update(const Addr *addr, int ifindex)
{
    Peer *peer = peer_find(addr);
    if (peer) {
        //peer->ifindex = ifindex;
        //memcpy(&peer->addr, addr, sizeof(Addr));
        peer->last_seen = gstate.time_now;
    } else {
        peer = peer_add(addr, ifindex);
    }

    return peer;
}

// read traffic from tun0 and send to peers
void dsr_bloom_1_tun_handler(int events, int fd)
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
/*
        // print addresses
        char saddr_str[INET6_ADDRSTRLEN];
        char daddr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET6, daddr, daddr_str, sizeof(daddr_str));

        log_info("received IPv6 packet on %s: %s => %s (len %d)",
            gstate.tun_name, saddr_str, daddr_str, payload_length
        );
*/
        if (IN6_IS_ADDR_MULTICAST(daddr)) {
            // no support for multicast traffic
            //log_debug("is IPv6 multicast packet => drop");
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

        data.src_id = g_own_id;
        data.dst_id = dst_id;
        data.hop_no = 1;
        data.length = read_len;
        data.bloom = 0;

        //BLOOM_ADD(&data.bloom, g_own_id);
        send_mcasts(&data, offsetof(DATA, payload) + read_len);

/*
        Node *node = node_find(dst_id);
        if (node) {
            data.seq_no = 0;
            log_debug("send data packet to %s via ucast", str_addr(&node->addr));
            send_ucast(&node->addr, &data, offsetof(DATA, payload) + read_len);
        } else {
            data.seq_no = ++g_seqno;
            log_debug("send data packet via mcast (seq_no: %u)", (unsigned) data.seq_no);
            send_all(dst_id, &data, offsetof(DATA, payload) + read_len);
        }
*/
    }
}

void consider_intro(uint32_t src_id, uint32_t dst_id, int recv_len)
{
    Node *src = node_find(src_id);
    Node *dst = node_find(dst_id);
    if (src && dst && same_network(&src->addr, &dst->addr)) {
        // TODO: traffic analysis
        log_debug("create INTRO");

        INTRO intro = {
            .type = TYPE_INTRO
        };

        log_debug("send INTRO %s", str_addr(&src->addr));
        memcpy(&intro.addr, &src->addr, sizeof(struct sockaddr_storage));
        send_ucast(&dst->addr, &intro, sizeof(INTRO));

        log_debug("send INTRO %s", str_addr(&dst->addr));
        memcpy(&intro.addr, &dst->addr, sizeof(struct sockaddr_storage));
        send_ucast(&src->addr, &intro, sizeof(INTRO));
    }
}

// get bloom filter for all neighbors
uint16_t get_bloom_filter(int ifindex)
{
    uint16_t filter = 0;
    Node *tmp;
    Node *cur;

    HASH_ITER(hh, g_nodes, cur, tmp) {
        if (cur->ifindex == ifindex) {
            // the id is expected to be random already
            const uint32_t hash = cur->id; //adler32(&cur->id, 4);
            BLOOM_ADD(&filter, hash);
           }
    }

    return filter;
}

static void handle_DATA(int ifindex, Addr *addr, DATA *p, unsigned recv_len)
{
    log_debug("got data packet: %s / %04x => %04x (seq_no: %d, hop_no: %d)",
        str_addr(addr), p->src_id, p->dst_id, (int) p->seq_no, (int) p->hop_no);

    if (p->hop_no >= 255) {
        log_error("too many hops => drop paket");
        return;
    }

    if (p->src_id == g_own_id) {
        log_debug("own source id => drop packet");
        return;
    }

    if (p->dst_id == g_own_id) {
        log_debug("Write %u bytes to %s", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        if (write(gstate.tun_fd, p->payload, p->length) != p->length) {
            log_error("write() %s", strerror(errno));
        }
    } else if (!BLOOM_TEST(&p->bloom, g_own_id)) {
        BLOOM_ADD(&p->bloom, g_own_id);
        send_mcasts(p, recv_len);
    } else {
        // silently drop paket
    }
/*
    if (BLOOM_TEST(&p->bloom, g_own_id)) {
        // prevent loops - do not forward 
        return;
    }
    //Peer *__peer = peer_update(addr, ifindex);

    Node *src = node_update(addr, ifindex, p->src_id, 0, p->hop_no, recv_len);
    int is_mcast = (p->seq_no > 0); //TODO: use addr_is_multicast(addr);

    // data for this node
    if (p->dst_id == g_own_id) {
        //traffic_node_add(from->id, g_own_id, recv_len);

        log_debug("Write %u bytes to %s", (unsigned) p->length, gstate.tun_name);

        // destination is the local tun0 interface => write packet to tun0
        if (write(gstate.tun_fd, p->payload, p->length) != p->length) {
            log_error("write() %s", strerror(errno));
        }
    } else {
        Node *ngh = node_find_neighbor_by_addr(ifindex, addr);
        Node *dst = node_find(p->dst_id);

        // hm, merge?
        src->bloom = p->bloom;
        ngh->bloom &= p->bloom;

        if (dst) {
            //int bytes = traffic_node_add(from->id, to->id, recv_len);
            log_debug("Forward to %04x / %s via ucast",
                dst->id, str_addr(&dst->addr));
            p->hop_no += 1;
            BLOOM_ADD(&p->bloom, g_own_id);
            send_ucast(&dst->addr, p, recv_len);

            //consider_intro(p->src_id, p->dst_id, recv_len);
        } else {
            if (is_mcast) {
                // TODO: optimize with bloom filter?
                if (p->seq_no > src->seq_no) {
                    log_debug("Forward %u bytes via mcast (seq_no: %u, hop_no: %u)",
                        recv_len, (unsigned) p->seq_no, (unsigned) p->hop_no);
                    src->seq_no = p->seq_no;

                    p->hop_no += 1;
                    BLOOM_ADD(&p->bloom, g_own_id);

                    // send 
                    send_all(p->dst_id, p, sizeof(DATA));
                } else {
                    log_debug("Got seq_no %u (current %u) => drop mcast", (unsigned) p->seq_no, (unsigned) src->seq_no);
                }
            } else {
                log_warning("Unknown node %04x => drop ucast", p->dst_id);
            }
        }
    }
*/
}

/*
get packet and send packet back if on same ifindex and 
*/
static void handle_INTRO(int ifindex, const Addr *addr, const INTRO *p, int recv_len)
{
    char p_addr_str[INET6_ADDRSTRLEN + 8];

    str_addr_buf(p_addr_str, addr);

    log_debug("received INTRO from %s: => %s",
        str_addr(addr), p_addr_str);

    Node *node = node_find_neighbor_by_addr(ifindex, addr);
    if (!node) {
        log_warning("Introduction failed: unknown sender node.");
        return;
    }

    //TODO:
    //Node *n = node_update(&p->addr, ifindex, p->src_id, 0, p->hop_no, recv_len);
}

// for mobility?
static void handle_HELLO(int ifindex, const Addr *addr, HELLO *p, int recv_len)
{
    /*
    char p_addr_str[INET6_ADDRSTRLEN + 8];

    str_addr_buf(p_addr_str, &p->addr);

    log_debug("received HELLO from %s: => %s",
        str_addr(addr), p_addr_str);

    if (node_find(id) == NULL) {
        node_update(addr, ifindex, p->src_id, 0, p->hop_no, recv_len);
        if ()
        send_all(p, sizeof(HELLO));
    } else {

    }

    Node *src = node_update(addr, ifindex, p->src_id, 0, p->hop_no, recv_len);
    if (node) {
        // forward
    }*/
}

// read traffic from peers and write to tun0 or forward
void dsr_bloom_1_ucast_handler(int events, int fd)
{
    struct sockaddr_storage from_addr = {0};
    struct sockaddr_storage to_addr = {0};
    uint8_t buffer[sizeof(DATA)];
    ssize_t recv_len;
    int ifindex = 0;

    if (events <= 0) {
        return;
    }

    recv_len = recv6_fromto(
        fd, buffer, sizeof(buffer), 0, &ifindex, &from_addr, &to_addr);

    if (recv_len <= 0) {
        return;
    }
/*
    socklen_t slen = sizeof(addr);
    if ((recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr, &slen)) <= 0) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }
*/

    char from_str[INET6_ADDRSTRLEN + 8];
    char to_str[INET6_ADDRSTRLEN + 8];
    char ifname[IF_NAMESIZE];
    str_addr_buf(from_str, &from_addr);
    str_addr_buf(to_str, &to_addr);
    log_debug("Got ucast %s => %s (%s)", from_str, to_str, if_indextoname(ifindex, ifname));

    switch (buffer[0]) {
    case TYPE_DATA:
        handle_DATA(ifindex, &from_addr, (DATA*) buffer, recv_len);
        break;
    case TYPE_INTRO:
        handle_INTRO(ifindex, &from_addr, (INTRO*) buffer, recv_len);
        break;
    case TYPE_HELLO:
        handle_HELLO(ifindex, &from_addr, (HELLO*) buffer, recv_len);
        break;
    default:
        log_warning("Unknown unicast packet type %u from %s (%s)", (unsigned) buffer[0], str_addr(&from_addr), if_indextoname(ifindex, ifname));
    }
}

// packet over wifi/lan
void dsr_bloom_1_mcast_handler(int events, int fd)
{
    struct sockaddr_storage from_addr = {0};
    struct sockaddr_storage to_addr = {0};
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
/*
    socklen_t slen = sizeof(addr);
    if ((recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr, &slen)) < 0) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }
*/

    char from_str[INET6_ADDRSTRLEN + 8];
    char to_str[INET6_ADDRSTRLEN + 8];
    char ifname[IF_NAMESIZE];
    str_addr_buf(from_str, &from_addr);
    str_addr_buf(to_str, &to_addr);
    log_debug("Got mcast %s => %s (%s)", from_str, to_str, if_indextoname(ifindex, ifname));

    /*
    TODO: register certain networks to special ID
     - e.g. ::/0 => ID 23
    */

    switch (buffer[0]) {
    case TYPE_DATA:
        handle_DATA(ifindex, &from_addr, (DATA*) buffer, recv_len);
        break;
    default:
        log_warning("Unknown multicast packet type %u from %s (%s)", (unsigned) buffer[0], str_addr(&from_addr), if_indextoname(ifindex, ifname));
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

    node_timeout();
}

int dsr_bloom_1_add_peer(FILE* fp, const char *str)
{
    //node_add
}

/*
void dsr_bloom_register()
{
    //add_protocol("dsr-bloom", );
}
*/

void dsr_bloom_1_init()
{
    // get id from IP address
    id_get6(&g_own_id, &gstate.tun_addr);

    // call at least every second
    net_add_handler(-1, &periodic_handler);
/*
    struct interface *ifa = NULL;
    UT_array *array = get_interfaces();
    printf("%p\n", array);
    while ((ifa = utarray_next(array, ifa))) {
        interface_add(ifa->ifindex);
    }
*/
    // set node identifier
    //while (g_own_id == 0) {
    //    bytes_random(&g_own_id, sizeof(g_own_id));
    //}

    //ip link set address {MAC_ADDR} dev {DEVICE}
    //struct in6_addr addr;
    //id_set(&addr, &g_own_id);

/*
//void extract_mac_from_eui64(uint8_t *mac, const struct in6_addr *addr)

    //ip link set address {MAC_ADDR} dev {DEVICE}
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "ip -4 addr flush dev %s", "tun0");
    system(cmd);
    snprintf(cmd, sizeof(cmd), "ip -6 addr flush dev %s", "tun0");
    system(cmd);

    snpritnf(cmd, sizeof(cmd), "ip addr a dev %s"
    snprintf("ip dev %dev");
    system("");
    */
}

void debug_status(FILE* file)
{
    fprintf(file, "Dynamic Source Routing\n");
    fprintf(file, "  own id: %04x\n", g_own_id);

    int neighbor_count = 0;
    int node_count = 0;

    Node *tmp;
    Node *cur;

    HASH_ITER(hh, g_nodes, cur, tmp) {
        if (cur->hop_no == 1) {
            neighbor_count += 1;
        }
        node_count += 1;
    }

    fprintf(file, "  nodes: %d (%d neighbors)\n", node_count, neighbor_count);
}

void debug_neighbors(FILE* file)
{
    char tbuf[64];
    char sbuf[64];
    char ifname[IF_NAMESIZE];
    int neighbor_count = 0;

    Node *tmp;
    Node *cur;

    HASH_ITER(hh, g_nodes, cur, tmp) {
        if (is_neighbor(cur)) {
            fprintf(file, "  %04x / %s (%s)) hop_no: %u, seq_no: %u, last_seen: %s ago, received: %s)\n",
                cur->id,
                str_addr(&cur->addr),
                if_indextoname(cur->ifindex, ifname),
                (unsigned) cur->hop_no,
                (unsigned) cur->seq_no,
                format_duration(tbuf, cur->last_seen, gstate.time_now),
                format_size(sbuf, cur->received_bytes)
            );
            neighbor_count += 1;
        }
    }

    fprintf(file, "(%d entries)\n", neighbor_count);
}

void debug_routes(FILE* file)
{
    char tbuf[64];
    char sbuf[64];
    char ifname[IF_NAMESIZE];
    int node_count = 0;
    Node *tmp;
    Node *cur;

    HASH_ITER(hh, g_nodes, cur, tmp) {
        node_count += 1;
        fprintf(file,"  id: %04x, addr: %s (%s), hop_no: %u, seq_no: %u, last_seen: %s ago, received: %s\n",
            cur->id,
            str_addr(&cur->addr),
            if_indextoname(cur->ifindex, ifname),
            (unsigned) cur->hop_no,
            (unsigned) cur->seq_no,
            format_duration(tbuf, cur->last_seen, gstate.time_now),
            format_size(sbuf, cur->received_bytes)
        );
    }

    fprintf(file, "(%d entries)\n", node_count);
}

int dsr_bloom_1_console(FILE* file, const char* cmd) {
    if (0 == strcmp("s", cmd)) {
        debug_status(file);
        return 0;
    }

    if (0 == strcmp("n", cmd)) {
        debug_neighbors(file);
        return 0;
    }

    if (0 == strcmp("r", cmd)) {
        debug_routes(file);
    }

    return 1;
}

