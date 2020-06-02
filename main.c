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

#include "log.h"
#include "utils.h"
#include "net.h"
#include "unix.h"
#include "main.h"

#define MULTICAST_ADDR "ff12::1234"
#define MULTICAST_PORT 4321


struct config *gconf = NULL;
int g_sock_help = -1;
int g_unicast_send_socket = -1;
int g_tap_fd = -1;
// counters
uint32_t g_route_request_seq = 0; // incremented for each new RouteRequest started by this node
//uint32_t g_broadcast_id = 0;
struct address g_tun_addr = {0};


enum {
    PACKET_TYPE_ROUTE_REQUEST = 1,
    PACKET_TYPE_ROUTE_REPLY = 2,
    PACKET_TYPE_ROUTE_ERROR = 3,
    PACKET_TYPE_ROUTE_REPLY_ACK = 4,
    PACKET_TYPE_DATA_PACKET = 5
};

/*
dst_addr
next_hop
seq
hop_count
lifetime


-  Destination IP Address
-  Destination Sequence Number
-  Valid Destination Sequence Number flag
-  Other state and routing flags (e.g., valid, invalid, repairable,
  being repaired)
-  Network Interface
-  Hop Count (number of hops needed to reach destination)
-  Next Hop
-  List of Precursors (described in Section 6.2)
-  Lifetime (expiration or deletion time of the route)
*/
struct entry {
    struct address dst_addr;
    struct address next_hop_addr;
    int dst_seq;
    int life_time; //updated when entry is used, expire else
    //list of precursor nodes?
    struct entry *next;
};

struct __attribute__((__packed__)) MulticastPacket {
    uint16_t port;
    uint32_t seq;
};

struct __attribute__((__packed__)) RouteError {
    uint8_t type;
};

/*
src_addr
src_seqno
broadcast_id
dst_addr
dst_seqno
hop_count
*/
struct __attribute__((__packed__)) RouteRequest {
    uint8_t type;
    struct address src_addr;
    struct address dst_addr;
    uint16_t seq;
    uint16_t hop_count;
};

/*
src_addr
dst_addr
dst_seqno
hop_count
lifetime
*/
struct __attribute__((__packed__)) RouteReply {
    uint8_t type;
    struct address src_addr;
    struct address dst_addr;
    uint16_t seq;
    uint16_t hop_count;
};

struct __attribute__((__packed__)) DataPacket {
    uint8_t type;
    struct address dst_addr;
    uint16_t hop_count;
    uint16_t length;
    uint8_t payload[2000];
};

struct interface {
    const char *ifname;
    int ifindex;
    struct address addr;
    int mcast_receive_socket;
    int mcast_send_socket;
    int ucast_receive_socket;
    struct interface *next;
};

/*
--peer 128.2.2.1:222 (internet)
- multicast discovery (local peer ip)
- interface

*/

// interface to send mutlicast discovery packets to
static struct interface *g_interfaces = NULL;

static struct entry *g_entries = NULL;

// local network discovery address
static struct sockaddr_in6 g_mcast_addr = {0};

// listen address for unicast packets
static struct sockaddr_in6 g_ucast_addr = {0};

struct entry* find_entry(const struct address *dst_addr)
{
    log_debug("find_entry");
    struct entry *entry;

    int c = 0;
    entry = g_entries;
    while (entry) {
        c += 1;
        log_debug("%d: find_entry: %s == %s", c, strdup(str_addr(dst_addr)), strdup(str_addr(&entry->dst_addr)));
        if (addr_equal(&entry->dst_addr, dst_addr)) {
            log_debug("found entry");
            return entry;
        }
        entry = entry->next;
    }

    log_debug("entry not found");
    return NULL;
}

void add_entry(struct address *dst_addr, struct address *next_hop_addr, int dst_seq)
{
    log_debug("add_entry");
    struct entry *entry = (struct entry*) malloc(sizeof(struct entry));
    memcpy(&entry->dst_addr, dst_addr, sizeof(struct address));
    memcpy(&entry->next_hop_addr, next_hop_addr, sizeof(struct address));
    entry->dst_seq = dst_seq;

    //log_debug("add_entry: %s (seq %d)", str_addr(&entry->dst_addr), entry->dst_seq);
    entry->next = g_entries;
    g_entries = entry;

    int c = 0;
    entry = g_entries;
    while (entry) {
        c += 1;
        entry = entry->next;
    }

    log_debug("entries: %d", c);

}

struct interface *find_interface(const char *ifname)
{
    struct interface *interface = g_interfaces;
    while (interface) {
        if (0 == strcmp(interface->ifname, ifname)) {
            return interface;
        }
        interface = interface->next;
    }

    return NULL;
}

struct interface *add_interface(const char *ifname) //struct interface *interface)
{

    struct interface *ifce = (struct interface*) malloc(sizeof(struct interface));
    ifce->ifname = strdup(ifname);
    interface_get_ifindex(&ifce->ifindex, g_sock_help, ifname);
    interface_get_addr6(&ifce->addr, ifname);

    log_info("Add interface: %s", ifce->ifname);

    ifce->next = g_interfaces;
    g_interfaces = ifce;

    return ifce;
}

int setup_mcast_send_socket(int *sock, int ifindex)
{
    struct in6_addr localInterface;

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("socket() %s", strerror(errno));
        return 1;
    }

    int loopch = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0) {
        log_error("setsockopt(IPV6_MULTICAST_LOOP) %s", strerror(errno));
        close(fd);
        return 1;
    }

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
        log_error("setsockopt(IPV6_MULTICAST_IF) %s", strerror(errno));
        return 1;
    }

    *sock = fd;

    return 0;
}

int setup_mcast_receive_socket(int *sock, int ifindex)
{
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("socket() %s", strerror(errno));
        return 1;
    }

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*) &reuse, sizeof(reuse)) < 0) {
        log_error("setsockopt(SO_REUSEADDR): %s", strerror(errno));
        close(fd);
        return 1;
    }

    g_mcast_addr.sin6_scope_id = ifindex;
    if (bind(fd, (struct sockaddr*) &g_mcast_addr, sizeof(g_mcast_addr)) < 0) {
        log_error("bind() to multicast address: %s", strerror(errno));
        close(fd);
        return 1;
    }

    struct ipv6_mreq group;
    //group.ipv6mr_multiaddr = get_ip_addr(fd, interface->ifname);
    group.ipv6mr_interface = ifindex;
    memcpy(&group.ipv6mr_multiaddr, &g_mcast_addr.sin6_addr, sizeof(struct in6_addr));

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof group) < 0) {
        log_error("setsockopt(IPV6_ADD_MEMBERSHIP) %s", strerror(errno));
        close(fd);
        return 1;
    }

    *sock = fd;

    return 0;
}

int setup_unicast_socket(int *sock)
{
    int fd;

    if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        log_error("socket() %s", strerror(errno));
        close(fd);
        return 1;
    }

    // bind socket to port (works for IPv4 and IPv6)
    if (bind(fd, (struct sockaddr*) &g_ucast_addr, sizeof(g_ucast_addr)) == -1) {
        log_error("bind() to unicast address: %s", strerror(errno));
        close(fd);
        return 1;
    }

    *sock = fd;

    return 0;
}

int interface_parse(struct interface *ifce, const char *ifname)
{
    ifce->ifname = ifname;
    interface_get_ifindex(&ifce->ifindex, g_sock_help, ifname);
    interface_get_addr6(&ifce->addr, ifname);

    return 0;
}

void periodic_handler(int _events, int _fd)
{
    static time_t last = 0;

    // every 5 seconds
    if (last > 0 && (last + 5) < gconf->time_now) {
        return;
    } else {
        last = gconf->time_now;
    }
/*
    // timeout peers
    struct peer *peer = g_peers;
    g_peers = NULL;
    while (peer) {
        struct peer *next = peer->next;
        if ((gconf->time_now - peer->last_contact) > 10) {
            log_debug("timeout peer %s", str_addr(&peer->addr));
            free(peer);
        } else {
            peer->next = g_peers;
            g_peers = peer;
        }
        peer = next;
    }
*/
    // send discovery packet
    struct MulticastPacket p = {
        .port = ntohs(g_ucast_addr.sin6_port),
        .seq = g_route_request_seq
    };
    struct interface *ife = g_interfaces;
    while (ife) {
        if (sendto(ife->mcast_send_socket, &p, sizeof(p), 0, (struct sockaddr*) &g_mcast_addr, sizeof(g_mcast_addr)) < 0) {
            log_warning("sendto() %s", strerror(errno));
        } else {
            //log_debug("multicast discovery send on %s", ife->ifname);
        }
        ife = ife->next;
    }
}

// receive annoucements from peers
void mcast_handler(int events, int fd)
{
    struct address addr = {0};
    struct Entry *entry;
    struct peer *peer;
    int recv_len;
    char buffer[200];

    if (events <= 0) {
        return;
    }

    socklen_t slen = sizeof(addr);
    if ((recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr, &slen)) < 0) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }

    if (recv_len != sizeof(struct MulticastPacket)) {
        return;
    }

    struct MulticastPacket *p = (struct MulticastPacket*) &buffer[0];

    // TODO: remove
    if (g_entries) {
        return;
    }

    if (p->port > 0) {
        port_set(&addr, p->port);
        if (find_entry(&addr) == NULL) {
            add_entry(&addr, &addr, p->seq);
            //peer->first_contact = gconf->time_now;
        }
        //peer->last_contact = gconf->time_now;
    }
}

void send_packet(const struct address *addr, const void *data, int data_len)
{
    socklen_t slen = addr_len(addr); // sizeof(struct sockaddr_in6);
    if (sendto(g_unicast_send_socket, data, data_len, 0, (struct sockaddr*) addr, slen) == -1) {
        log_error("Failed send packet to %s: %s", str_addr(addr), strerror(errno));
    }
}

void send_neighbors(const void *data, int data_len)
{
    struct entry *entry;

    // send to all neighbors
    entry = g_entries;
    while (entry) {
        if (addr_equal(&entry->dst_addr, &entry->next_hop_addr)) {
            send_packet(&entry->dst_addr, data, data_len);
        }
        entry = entry->next;
    }
}

void update_entry(struct address *sender, struct address *src, struct address *dst)
{
        /*
When a New Route Is Available, Route Table Will Be
Updated Only If New Route Has
Larger dest_sequence_#
Or
 Same dest_sequence_# but with Smaller hop_cnt to the
Destination
        */
}

// read traffic from peers and write to tun0
void ucast_handler(int events, int fd)
{
    struct entry *entry;
    struct address addr;
    uint8_t buffer[2000];
    int recv_len;

    if (events <= 0) {
        return;
    }

    socklen_t slen = sizeof(addr);
    if ((recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr, &slen)) <= 0) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }

    if (buffer[0] == PACKET_TYPE_DATA_PACKET) {
        log_debug("got DataPacket");
        struct DataPacket *p = (struct DataPacket*) buffer;

        if (addr_equal(&p->dst_addr, &g_tun_addr)) {
            // write to tun0
            if (write(g_tap_fd, p->payload, p->length) != p->length) {
                log_error("write() %s", strerror(errno));
                return;
            }
        } else if ((entry = find_entry(&p->dst_addr)) != NULL) {
            p->hop_count += 1;
            int p_len = offsetof(struct DataPacket, payload) + p->length;

            // forward packet
            if (p_len != recv_len) {
                log_warning("invalid packet length in header from %s", str_addr(&addr));
                return;
            }

            send_packet(&entry->next_hop_addr, p, p_len);
        } else {
            // drop packet
        }
    }

    else if (buffer[0] == PACKET_TYPE_ROUTE_REPLY) {
        struct RouteReply *p = (struct RouteReply*) buffer;
        log_debug("got RouteReply (src_addr: %s, dst_addr: %s, seq: %d, hop_count: %d)",
            strdup(str_addr(&p->src_addr)), strdup(str_addr(&p->dst_addr)),
            (int) p->seq, (int) p->hop_count
        );

        if (addr_equal(&p->dst_addr, &g_tun_addr)) {
            log_debug("RouteReply reached destination");
            add_entry(&p->src_addr, /*next hop*/, p->seq);
        } else if ((entry = find_entry(&p->dst_addr)) != NULL) {
            p->hop_count += 1;
            send_packet(&entry->next_hop_addr, p, sizeof(struct RouteReply));
        } else {
            // drop (we should have a path?)
            //send_neighbors(p, sizeof(struct RouteReply));
        }
    }

    else if (buffer[0] == PACKET_TYPE_ROUTE_REQUEST) {
        struct RouteRequest *p = (struct RouteRequest*) buffer;

        log_debug("got RouteRequest (src_addr: %s, dst_addr: %s, seq: %d, hop_count: %d), g_tun_addr: %s",
            strdup(str_addr(&p->src_addr)), strdup(str_addr(&p->dst_addr)),
            (int) p->seq, (int) p->hop_count,
            strdup(str_addr(&g_tun_addr))
        );

        if (addr_equal(&p->dst_addr, &g_tun_addr)) {
            //log_debug("RouteRequest destination reached => send RouteReply");
            struct RouteReply reply = {
                .type = PACKET_TYPE_ROUTE_REPLY,
                .seq = g_route_request_seq++,
                .hop_count = p->hop_count
            };
            memcpy(&reply.src_addr, &p->dst_addr, sizeof(struct address));
            memcpy(&reply.dst_addr, &p->src_addr, sizeof(struct address));

            // send reply
            if ((entry = find_entry(&reply.dst_addr))) {
                log_debug("RouteRequest destination reached => send RouteReply back to sender");
                send_packet(&entry->next_hop_addr, &reply, sizeof(struct RouteReply));
            } else {
                log_debug("RouteRequest destination reached => send RouteReply to all neighbors");
                send_neighbors(&reply, sizeof(struct RouteReply));
            }
        } else if ((entry = find_entry(&p->src_addr)) != NULL) {
            if (p->seq > entry->dst_seq) {
                log_debug("RouteRequest not known => forward");
                entry->dst_seq = p->seq;

                p->hop_count += 1;
                send_neighbors(p, sizeof(struct RouteRequest));
            } else {
                log_debug("RouteRequest old seq => drop");
            }
        } else {
            log_debug("RouteRequest destination unknown");
            add_entry(&p->src_addr, &addr, p->seq);

            p->hop_count += 1;

            // send to all neighbors
            send_neighbors(p, sizeof(struct RouteRequest));
        }
    } else {
        log_debug("got unknown packet");
    }
}

// read traffic from tun0 and send to peers
void tun_handler(int events, int fd)
{
    uint8_t buffer[2000];

    if (events <= 0) {
        return;
    }

    //while (1) {
        int read_len = read(fd, buffer, sizeof(buffer));
        if (read_len <= 0) {
            return;
        }

        int ip_version = (buffer[0] >> 4) & 0xff;

        // check if it is a multicast packet
        if (ip_version != 6) {
            log_debug("unknown packet protocol version => drop");
            return;
        }

        // IPv6 packet
        int payload_length = ntohs(*((uint16_t*) &buffer[4]));
        struct in6_addr *saddr = (struct in6_addr *) &buffer[8];
        struct in6_addr *daddr = (struct in6_addr *) &buffer[24];
/*
        // print addresses
        char saddr_str[INET6_ADDRSTRLEN];
        char daddr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET6, daddr, daddr_str, sizeof(daddr_str));

        log_info("received IPv6 packet on %s: %s => %s (len %d)",
            gconf->dev, saddr_str, daddr_str, payload_length
        );
*/
        if (gconf->drop_multicast && IN6_IS_ADDR_MULTICAST(daddr)) {
            log_warning("is IPv6 multicast packet => drop");
            return;
        }

        log_debug("read %d from %s", read_len, gconf->dev);

        struct entry* entry;
        struct address daddr_ = {0};
        daddr_.ipv6.sin6_family = AF_INET6;
        memcpy(&daddr_.ipv6.sin6_addr, daddr, sizeof(struct in6_addr));

        //uint8_t dmac[ETH_ALEN];
        //extract_mac_from_eui64(dmac, daddr);
        if ((entry = find_entry(&daddr_)) != NULL) {
            log_debug("send DataPacket");

            // send to peer
            struct DataPacket p = {
                .type = PACKET_TYPE_DATA_PACKET,
                .hop_count = 0,
                .length = read_len
            };

            memcpy(&p.dst_addr, &daddr_, sizeof(struct address));
            memcpy(&p.payload, buffer, read_len);

            log_debug("forward DataPacket to %s", str_addr(&entry->next_hop_addr));
            int p_len = offsetof(struct DataPacket, payload) + p.length;
            send_packet(&entry->next_hop_addr, &p, p_len);
        } else {
            log_debug("send RouteRequest");
            struct RouteRequest p = {
                .type = PACKET_TYPE_ROUTE_REQUEST,
                .seq = g_route_request_seq++,
                .hop_count = 0
            };
            memcpy(&p.src_addr, &g_tun_addr, sizeof(struct address)); // source
            memcpy(&p.dst_addr, &daddr_, sizeof(struct address)); // target
            //log_debug("g_tun_addr: %s, daddr: %s",
            //    strdup(str_addr(&g_tun_addr)), strdup(str_addr(&daddr_)));

            log_debug("RouteRequest (src_addr: %s, dst_addr: %s, seq: %d, hop_count: %d)",
                strdup(str_addr(&p.src_addr)), strdup(str_addr(&p.dst_addr)), (int) p.seq, (int) p.hop_count);

            send_neighbors(&p, sizeof(struct RouteRequest));
        }
    //}
}

void usage(const char *pname) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -i eth0 -i wlan0\n"
        "\n"
        "-i <interface>  Name of interface to use (Default: <all>).\n"
        "-p <address>    Add a peer mnually by address.\n"
        "-m              Drop multicast IP traffic (Default: 1).\n"
        "-d              Set entry device (Default: tun0).\n"
        "-h              Prints this help text.\n",
        pname
    );
}

void add_all_interfaces()
{
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        log_error("getifaddrs %s", strerror(errno));
        return;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        const int family = ifa->ifa_addr->sa_family;
        const char *ifname = ifa->ifa_name;

        if (family == AF_INET6 || family == AF_INET) {
            if (find_interface(ifname) == NULL && interface_is_up(g_sock_help, ifname)) {
                add_interface(ifname);
            }
        }

       //struct sockaddr_in6 *pAddr = (struct sockaddr_in6 *)ifa->ifa_addr;
       //char buf[100];
       //printf("%s: %s\n", ifa->ifa_name, inet_ntop(AF_INET6, &pAddr->sin6_addr, buf, sizeof(buf)));
    }

    freeifaddrs(ifaddr);
}

int main(int argc, char *argv[])
{
    struct config config = {
        .dev = "tun0",
        .is_running = 1,
        .drop_multicast = 1,
        .use_syslog = 0,
        .verbosity = VERBOSITY_DEBUG
    };

    // set node identifier
    bytes_random(&gconf->id, 4);

    gconf = &config;

    g_sock_help = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock_help < 0) {
        log_error("socket() %s", strerror(errno));
        return 1;
    }

    int option;
    while ((option = getopt(argc, argv, "i:c:d:mh")) > 0) {
        switch(option) {
            case 'i': {
                if (find_interface(optarg) == NULL) {
                    add_interface(optarg);
                } else {
                    log_error("duplicate interface: %s", optarg);
                    return 1;
                }
                break;
            }
            /*
            case 'c': {
                struct address addr = {0};
                if (addr_parse(&addr, optarg, "1234", AF_UNSPEC) == 0) {
                    if (!find_peer(&addr)) {
                        //uint8_t mac[ETH_ALEN] = {0};
                        add_peer(&addr); //, mac);
                    }
                } else {
                    log_error("Invalid address: %s", optarg);
                    return 1;
                }
                break;
            }*/
            case 'd':
                gconf->dev = strdup(optarg);
                break;
            case 'm':
                gconf->drop_multicast = 0;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                log_error("Unknown option %c", option);
                usage(argv[0]);
            return 1;
        }
    }

    argv += optind;
    argc -= optind;

    if (argc > 0) {
        log_error("Too many options!");
        usage(argv[0]);
        return 1;
    }

    if (g_interfaces == NULL) {
        add_all_interfaces();
    }

    // setup multicast address
    g_mcast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, MULTICAST_ADDR, &g_mcast_addr.sin6_addr);
    g_mcast_addr.sin6_port = htons(MULTICAST_PORT);

    // setup unicast address for bind
    g_ucast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &g_ucast_addr.sin6_addr);
    g_ucast_addr.sin6_port = htons(654); //port_random());

    log_info("Listen on multicast: %s", str_addr((struct address*) &g_mcast_addr));
    log_info("Listen on unicast: %s", str_addr((struct address*) &g_ucast_addr));

    unix_signals();

    if ((g_unicast_send_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_error("socket() %s", strerror(errno));
        return 1;
    }

    if ((g_tap_fd = tun_alloc(gconf->dev)) < 0) {
        log_error("Error creating to %s interface: %s", gconf->dev, strerror(errno));
        return 1;
    }

    if (interface_set_up(g_sock_help, gconf->dev) < 0) {
        log_error("Failed to set interface %S up: %s", gconf->dev, strerror(errno));
        return 1;
    }

    if (interface_get_addr6(&g_tun_addr, gconf->dev) < 0) {
        log_error("Failed to get IPv6 address of interface: %s", gconf->dev);
        return 1;
    }

    // port needs to be zero!
    log_debug("g_tun_addr: %s", str_addr(&g_tun_addr));

    struct interface *ife = g_interfaces;
    while (ife) {
        //TODO: make sockets non-blocking
        setup_mcast_send_socket(&ife->mcast_send_socket, ife->ifindex);
        setup_mcast_receive_socket(&ife->mcast_receive_socket, ife->ifindex);
        setup_unicast_socket(&ife->ucast_receive_socket);

        net_add_handler(ife->mcast_receive_socket, &mcast_handler);
        net_add_handler(ife->ucast_receive_socket, &ucast_handler);

        ife = ife->next;
    }



    net_add_handler(-1, &periodic_handler);
    net_add_handler(g_tap_fd, &tun_handler);

    log_debug("Started using %s", gconf->dev);

    net_loop();

    return 0;
}
