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
int g_route_request_seq = 0;
uint8_t g_tun_mac[ETH_ALEN] = {0};

enum {
    PACKET_TYPE_DATA_PACKET,
    PACKET_TYPE_ROUTE_REPLY,
    PACKET_TYPE_ROUTE_REQUEST
};

struct entry {
    uint8_t dst_mac[ETH_ALEN];
    uint8_t next_hop_mac[ETH_ALEN];
    int dst_seq;
    //struct sockaddr_storage addr; //only set when it is a one hop neighbor
    int life_time; //updated when entry is used, expire else
    //list of precursor nodes?
    struct entry *next;
};

// what happens when we sort by 
struct __attribute__((__packed__)) MulticastPacket {
    uint8_t mac[ETH_ALEN];
    uint16_t port;
};

struct __attribute__((__packed__)) RouteRequest {
    uint8_t type;
    uint8_t src_mac[ETH_ALEN];
    uint16_t seq;
    uint8_t dst_mac[ETH_ALEN];
    uint16_t hop_count;
};

struct __attribute__((__packed__)) RouteReply {
    uint8_t type;
    uint8_t src_mac[ETH_ALEN];
    uint16_t src_seq;
    uint8_t dst_mac[ETH_ALEN];
    uint16_t dst_seq;
    uint16_t hop_count;
};

// header for unicast packets
struct __attribute__((__packed__)) DataPacket {
    uint8_t type;
    uint8_t dst_mac[ETH_ALEN];
    uint16_t hop_count;
    uint16_t length;
    uint8_t payload[2000];
};

struct interface {
    const char *ifname;
    int ifindex;
    uint8_t mac[ETH_ALEN];
    int mcast_receive_socket;
    int mcast_send_socket;
    int ucast_receive_socket;
    struct interface *next;
};

struct peer {
    uint8_t mac[ETH_ALEN]; // <= next_hop_mac
    struct sockaddr_storage addr;
    struct peer *next;
};

/*
--peer 128.2.2.1:222 (internet)
- multicast discovery (local peer ip)
- interface

*/

// interface to send mutlicast discovery packets to
static struct interface *g_interfaces = NULL;

static struct entry *g_entries = NULL;

// all known neighbors peer
static struct peer *g_peers = NULL;

// local network discovery address
static struct sockaddr_in6 g_mcast_addr = {0};

// listen address for unicast packets
static struct sockaddr_in6 g_ucast_addr = {0};

struct entry* find_entry(const uint8_t *dst_mac)
{
    struct entry *entry;

    entry = g_entries;
    while (entry) {
        if (0 == memcmp(entry->dst_mac, dst_mac, ETH_ALEN)) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

void add_entry(struct entry* entry)
{
    entry->next = g_entries;
    g_entries = entry;
}

struct peer *find_peer_by_addr(const struct sockaddr_storage *addr)
{
    struct peer *peer = g_peers;
    while (peer) {
        // compare address only (ignores port)
        if (addr_equal(&peer->addr, addr)) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

struct peer *find_peer_by_mac(const uint8_t *mac)
{
    struct peer *peer = g_peers;
    while (peer) {
        if (0 == memcmp(&peer->mac[0], mac, ETH_ALEN)) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

struct peer *add_peer(const struct sockaddr_storage *addr, const uint8_t *mac)
{
    struct peer *peer = (struct peer *) malloc(sizeof(struct peer));
    memcpy(&peer->addr, addr, sizeof(struct sockaddr_storage));
    memcpy(&peer->mac, mac, ETH_ALEN);
    //peer->first_contact = 0;
    //peer->last_contact = 0;

    log_info("Add peer: %s", str_addr(&peer->addr));

    peer->next = g_peers;
    g_peers = peer;

    return peer;
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

struct interface *add_interface(struct interface *interface)
{
    struct interface *ifce = (struct interface*) malloc(sizeof(struct interface));
    memcpy(ifce, interface, sizeof(struct interface));
    ifce->ifname = strdup(interface->ifname);

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
    interface_get_mac(&ifce->mac[0], g_sock_help, ifname);

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
    struct MulticastPacket p;
    p.port = g_ucast_addr.sin6_port;
    memcpy(&p.mac, &g_tun_mac, ETH_ALEN);

    struct interface *ife = g_interfaces;
    while (ife) {
        if (sendto(ife->mcast_send_socket, &p, sizeof(p), 0, (struct sockaddr*) &g_mcast_addr, sizeof(g_mcast_addr)) < 0) {
            log_warning("sendto() %s", strerror(errno));
        } else {
            log_debug("multicast discovery send on %s", ife->ifname);
        }
        ife = ife->next;
    }
}

// receive annoucements from peers
void mcast_handler(int events, int fd)
{
    struct sockaddr_storage addr;
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

    if (p->port > 0) {
        struct peer *peer = find_peer_by_addr(&addr);
        if (peer == NULL) {
            port_set(&addr, ntohs(p->port));
            add_peer(&addr, &p->mac[0]);
            //peer->first_contact = gconf->time_now;
        }
        //peer->last_contact = gconf->time_now;
    }
}

void send_packet(const struct sockaddr_storage *addr, const void *data, int data_len)
{
    socklen_t slen = addr_len(addr); // sizeof(struct sockaddr_in6);
    if (sendto(g_unicast_send_socket, data, data_len, 0, (struct sockaddr*) addr, slen) == -1) {
        log_error("Failed send packet to %s: %s", str_addr(addr), strerror(errno));
    }
}

// read traffic from peers and write to tun0
void ucast_handler(int events, int fd)
{
    struct entry *entry;
    struct sockaddr_storage addr;
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

/*
    {
        struct peer *peer = g_peers;
        while (peer) {
            if (addr_equal(&peer->addr, &addr)) {
                memcpypeer->mac
                break;
            }
            peer = peer->next;
        }
    }
*/

    if (buffer[0] == PACKET_TYPE_DATA_PACKET) {
        log_debug("got PACKET_TYPE_DATA_PACKET");
        struct DataPacket *p = (struct DataPacket*) buffer;

        if (0 == memcmp(p->dst_mac, g_tun_mac, ETH_ALEN)) {
            // write to tun0
            if (write(g_tap_fd, p->payload, p->length) != p->length) {
                log_error("write() %s", strerror(errno));
                return;
            }
        } else if ((entry = find_entry(p->dst_mac)) != NULL) {
            struct peer *peer = find_peer_by_mac(&entry->next_hop_mac[0]);
            memcpy(&p->dst_mac, &entry->next_hop_mac, ETH_ALEN);
            p->hop_count += 1;
            int p_len = offsetof(struct DataPacket, payload) + p->length;

            // forward packet
            if (p_len != recv_len) {
                log_warning("invalid packet length in header from %s", str_addr(&addr));
                return;
            }

            if (peer) {
                send_packet(&peer->addr, p, p_len);
            } else {
                log_error("No address for next_hop_mac!");
            }
        } else {
            // drop packet
        }
    }

    else if (buffer[0] == PACKET_TYPE_ROUTE_REPLY) {
        log_debug("got PACKET_TYPE_ROUTE_REPLY");
        struct RouteReply *p = (struct RouteReply*) buffer;
        if ((entry = find_entry(p->dst_mac)) != NULL) {
            struct peer *peer = find_peer_by_mac(&entry->next_hop_mac[0]);
            send_packet(&peer->addr, p, sizeof(struct RouteReply));
        } else {
            // drop packet 
        }
    }

    else if (buffer[0] == PACKET_TYPE_ROUTE_REQUEST) {
        log_debug("got PACKET_TYPE_ROUTE_REQUEST");
        struct RouteRequest *p = (struct RouteRequest*) buffer;

        if (0 == memcmp(&p->dst_mac, g_tun_mac, ETH_ALEN)) {
            struct RouteReply reply = {.type = PACKET_TYPE_ROUTE_REPLY};

            // send reply back
            send_packet(&addr, &reply, sizeof(struct RouteReply));
        } else if ((entry = find_entry(&p->dst_mac[0])) != NULL) {
            struct peer *peer = find_peer_by_mac(&entry->next_hop_mac[0]);
            // compare seq number 
            if (p->seq > entry->dst_seq) {
                entry->dst_seq = p->seq;
                p->hop_count += 1;
                send_packet(&peer->addr, p, sizeof(struct RouteRequest));
            } else {
                // drop packet
            }
        } else {
            /*
            entry = (struct entry*) malloc(sizeof(struct entry));
            memcpy(&entry->dst_mac[0], p-> ETH_ALEN);
            memcpy(&entry->next_hop_mac[0], ETH_ALEN);
            entry->dst_seq = p->seq;
    //struct sockaddr_storage addr; //only set when it is a one hop neighbor

            add_entry(entry);
            */

            p->hop_count += 1;

            // send to all neighbors
            struct peer *peer = g_peers;
            while (peer) {
                send_packet(&peer->addr, p, sizeof(struct RouteRequest));
                peer = peer->next;
            }
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

    while (1) {
        int read_len = read(fd, buffer, sizeof(buffer));
        if (read_len <= 0) {
            break;
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
        uint8_t dmac[ETH_ALEN];
        extract_mac_from_eui64(dmac, daddr);
        if ((entry = find_entry(dmac)) != NULL) {
            struct peer *peer = find_peer_by_mac(&entry->next_hop_mac[0]);

            // send to peer
            struct DataPacket p = {
                .type = PACKET_TYPE_DATA_PACKET,
                .hop_count = 0,
                .length = read_len
            };

            memcpy(&p.dst_mac, dmac, ETH_ALEN);
            memcpy(&p.payload, buffer, read_len);

            log_debug("forward DataPacket to %s", str_addr(&peer->addr));
            int p_len = offsetof(struct DataPacket, payload) + p.length;
            send_packet(&peer->addr, &p, p_len);
        } else {
            struct RouteRequest p = {
                .type = PACKET_TYPE_ROUTE_REQUEST,
                .seq = g_route_request_seq++,
                .hop_count = 0
            };
            memcpy(&p.src_mac, g_tun_mac, ETH_ALEN); // source
            memcpy(&p.dst_mac, dmac, ETH_ALEN); // target

            struct peer *peer = g_peers;
            while (peer) {
                log_debug("send RouteRequest to %s", str_addr(&peer->addr));
                send_packet(&peer->addr, &p, sizeof(struct RouteRequest));
                peer = peer->next;
            }
        }
        //memcpy(&rreq.src, &saddr, struct(struct in6_addr));
        //memcpy(&rreq.dst, &daddr, struct(struct in6_addr));
    }

    //send_all_peers(&rreq, sizeof(rreq));
    //send_all_peers(&p, sizeof(p.header) + p.header.length);
}

void usage(const char *pname) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -i eth0 -i wlan0\n"
        "\n"
        "-i <interface>  Name of interface to use.\n"
        "-p <address>    Add a peer mnually by address.\n"
        "-m              Drop multicast IP traffic (Default: 1).\n"
        "-d              Set entry device (Default: tun0).\n"
        "-h              Prints this help text.\n",
        pname
    );
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
                struct interface ifce = {0};
                if (interface_parse(&ifce, optarg) == 0) {
                    if (!find_interface(optarg)) {
                        add_interface(&ifce);
                    }
                } else {
                    log_error("Invalid interface: %s", optarg);
                    return 1;
                }
                break;
            }
            case 'c': {
                struct sockaddr_storage addr = {0};
                if (addr_parse(&addr, optarg, "1234", AF_UNSPEC) == 0) {
                    if (!find_peer_by_addr(&addr)) {
                        uint8_t mac[ETH_ALEN] = {0};
                        add_peer(&addr, mac);
                    }
                } else {
                    log_error("Invalid address: %s", optarg);
                    return 1;
                }
                break;
            }
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

    // setup multicast address
    g_mcast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, MULTICAST_ADDR, &g_mcast_addr.sin6_addr);
    g_mcast_addr.sin6_port = htons(MULTICAST_PORT);

    // setup unicast address for bind
    g_ucast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &g_ucast_addr.sin6_addr);
    g_ucast_addr.sin6_port = htons(port_random());

    log_info("Listen on multicast: %s", str_addr((struct sockaddr_storage*) &g_mcast_addr));
    log_info("Listen on unicast: %s", str_addr((struct sockaddr_storage*) &g_ucast_addr));

    unix_signals();

    if ((g_unicast_send_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_error("socket() %s", strerror(errno));
        return 1;
    }

    if ((g_tap_fd = tun_alloc(gconf->dev)) < 0) {
        log_error("Error connecting to %s interface: %s", gconf->dev, strerror(errno));
        return 1;
    }

    interface_get_mac(&g_tun_mac[0], g_sock_help, gconf->dev);

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

    interface_set_up(g_sock_help, gconf->dev);

    net_add_handler(-1, &periodic_handler);
    net_add_handler(g_tap_fd, &tun_handler);

    log_debug("Started using %s", gconf->dev);

    net_loop();

    return 0;
}
