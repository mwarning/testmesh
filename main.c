
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <linux/if_tun.h>

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

// address for automatic local network peering
static struct sockaddr_in6 g_mcast_addr = {0};
static struct sockaddr_in6 g_ucast_addr = {0};

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
    struct sockaddr_storage addr;
    struct peer *next;
};

struct interface *g_interfaces = NULL;
struct peer *g_peers = NULL;

struct peer *find_peer(const struct sockaddr_storage *addr)
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

void add_peer(const struct sockaddr_storage *addr)
{
    if (find_peer(addr)) {
        return;
    }

    struct peer *peer = (struct peer *) malloc(sizeof(struct peer));
    memcpy(&peer->addr, addr, sizeof(struct sockaddr_storage));

    log_info("Add peer: %s", str_addr(&peer->addr));

    peer->next = g_peers;
    g_peers = peer;
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

void add_interface(struct interface *ifce)
{
    if (find_interface(ifce->ifname)) {
        return;
    }

    struct interface *interface = (struct interface*) malloc(sizeof(struct interface));
    memcpy(interface, ifce, sizeof(struct interface));
    interface->ifname = strdup(interface->ifname);

    log_info("Add interface: %s", interface->ifname);

    interface->next = g_interfaces;
    g_interfaces = interface;
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
    struct ifreq if_idx;
    struct ifreq if_mac;

    // get the index of the interface to send on
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(g_sock_help, SIOCGIFINDEX, &if_idx) < 0) {
        log_error("ioctl(SIOCGIFINDEX) %s", strerror(errno));
        return 1;
    }

    // get the MAC address of the interface to send on
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(g_sock_help, SIOCGIFHWADDR, &if_mac) < 0) {
        log_error("ioctl(SIOCGIFHWADDR) %s", strerror(errno));
        return 1;
    }

    ifce->ifindex = if_idx.ifr_ifindex;
    ifce->ifname = ifname;
    memcpy(&ifce->mac, (uint8_t *)&if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}

int setup_tun(int sockfd, const char *ifname)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_mtu = 1500;

    if (ioctl(sockfd, SIOCSIFMTU, &ifr) == -1) {
      log_error("ioctl(SIOCSIFMTU) %s", strerror(errno));
      return 1;
    }

    return 0;
}

int tun_alloc(const char *dev)
{
    const char *clonedev = "/dev/net/tun";
    struct ifreq ifr = {0};
    int fd;
    int err;

    if ((fd = open(clonedev, O_RDWR)) < 0 ) {
        log_error("open %s: %s", clonedev, strerror(errno));
        return -1;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, dev);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
        log_error("ioctl(TUNSETIFF) %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (0 != strcmp(ifr.ifr_name, dev)) {
        return -1;
    }

    return fd;
}

static int interface_up(const char* ifname) {
    struct ifreq ifr = {0};
    int oldflags;

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    if (ioctl(g_sock_help, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("ioctl(SIOCGIFFLAGS) for %s: %s", ifname, strerror(errno));
        return 1;
    }

    oldflags = ifr.ifr_flags;
    ifr.ifr_flags |= IFF_UP;

    if (oldflags == ifr.ifr_flags) {
        // interface is already up/down
        return 0;
    }

    if (ioctl(g_sock_help, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("ioctl(SIOCSIFFLAGS) for %s: %s", ifname, strerror(errno));
        return 1;
    }

    return 0;
}

void periodic_handler(int _events, int _fd) {
    char msg[20];

    static time_t last = 0;
    if (last > 0 && (last + 3) < gconf->time_now) {
        return;
    } else {
        last = gconf->time_now;
    }

    // prepare message
    sprintf(msg, "%d", (int) ntohs(g_ucast_addr.sin6_port));

    struct interface *ife = g_interfaces;
    while (ife) {
        if (sendto(ife->mcast_send_socket, msg, strlen(msg) + 1, 0, (struct sockaddr*) &g_mcast_addr, sizeof(g_mcast_addr)) < 0) {
            log_warning("sendto() %s", strerror(errno));
        } else {
            log_debug("multicast discovery send: %s (%s)", msg, ife->ifname);
        }
        ife = ife->next;
    }
}

// receive annoucements from peers
void mcast_handler(int events, int fd)
{
    struct sockaddr_storage addr;
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

    buffer[recv_len] = '\0';
    int port = port_parse(buffer, -1);

    if (port > 0) {
        port_set(&addr, port);
        add_peer(&addr);
    }
}

// forward traffic from peers to tun0
void ucast_handler(int events, int fd)
{
    uint8_t buffer[2000];
    struct sockaddr_storage addr;
    int recv_len;

    if (events <= 0) {
        return;
    }

    socklen_t slen = sizeof(addr);
    if ((recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &addr, &slen)) < 0) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }

    struct peer *peer = find_peer(&addr);
    if (peer) {
        // send out of tap interface
        if (write(g_tap_fd, buffer, recv_len) != recv_len) {
            log_error("write() %s", strerror(errno));
            return;
        }
    } else {
        log_warning("ignore packet from unknown peer: %s", str_addr(&addr));
    }
}

// forward traffic from tun0 to peers
void tap_handler(int events, int fd)
{
    if (events <= 0) {
        return;
    }

    uint8_t buffer[2000];
    int read_len = read(fd, buffer, sizeof(buffer));
    if (read_len <= 40) {
        log_warning("packet too small: %d", read_len);
        return;
      }

    int ip_version = (buffer[0] >> 4) & 0xff;

    // check if it is a multicast packet
    if (ip_version == 4) {
        // IPv4 packet
        int total_length = ntohs(*((uint16_t*) &buffer[2]));
        struct in_addr *saddr = (struct in_addr *) &buffer[12];
        struct in_addr *daddr = (struct in_addr *) &buffer[16];

        char saddr_str[INET_ADDRSTRLEN];
        char daddr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET, daddr, daddr_str, sizeof(daddr_str));

        log_info("received IPv4 packet on %s: %s => %s (len %d)",
            gconf->dev, saddr_str, daddr_str, total_length
        );

        if (gconf->drop_multicast && IN_MULTICAST(ntohl(daddr->s_addr))) {
            log_warning("is IPv4 multicast packet => drop");
            return;
        }
    } else if (ip_version == 6) {
        // IPv6 packet
        int payload_length = ntohs(*((uint16_t*) &buffer[4]));
        struct in6_addr *saddr = (struct in6_addr *) &buffer[8];
        struct in6_addr *daddr = (struct in6_addr *) &buffer[24];

        char saddr_str[INET6_ADDRSTRLEN];
        char daddr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET6, daddr, daddr_str, sizeof(daddr_str));

        log_info("received IPv6 packet on %s: %s => %s (len %d)",
            gconf->dev, saddr_str, daddr_str, payload_length
        );

        if (gconf->drop_multicast && IN6_IS_ADDR_MULTICAST(daddr)) {
            log_warning("is IPv6 multicast packet => drop");
            return;
        }
    } else {
        log_debug("unknown packet protocol version => drop");
        return;
    }

    if (g_peers == NULL) {
        log_warning("no peers known => drop");
    }

    struct peer *peer = g_peers;
    while (peer) {
        // send to all peers
        socklen_t slen = sizeof(struct sockaddr_in6);
        if (sendto(g_unicast_send_socket, buffer, read_len, 0, (struct sockaddr*) &peer->addr, slen) == -1) {
            log_error("Failed forward packet to %s: %s", str_addr(&peer->addr), strerror(errno));
        }
        peer = peer->next;
    }
}

/*
void got_unicast()
{
}

void got_multicast(const struct sin6_addr *addr, const char *payload, int payload_len)
{
// we have a one hop mapping of mac <=> id + position

  ping ipv6 address
  1. address to position
  2. route according to position
}
*/

void usage(const char *pname) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -i eth0 -i wlan0\n"
        "\n"
        "-i <interface>  Name of interface to use.\n"
        "-p <address>    Add a peer mnually by address.\n"
        "-m              Allow multicast traffic (Default: 0).\n"
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
                    add_interface(&ifce);
                } else {
                    log_error("Invalid interface: %s", optarg);
                    return 1;
                }
                break;
            }
            case 'c': {
                struct sockaddr_storage addr = {0};
                if (addr_parse(&addr, optarg, "1234", AF_UNSPEC) == 0) {
                    add_peer(&addr);
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
    g_ucast_addr.sin6_port = htons(port_random());

    unix_signals();

    if ((g_unicast_send_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        log_error("socket() %s", strerror(errno));
        return 1;
    }

    if ((g_tap_fd = tun_alloc(gconf->dev)) < 0) {
        log_error("Error connecting to %s interface: %s", gconf->dev, strerror(errno));
        return 1;
    }

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

    interface_up(gconf->dev);

    net_add_handler(-1, &periodic_handler);
    net_add_handler(g_tap_fd, &tap_handler);

    log_debug("Started using %s", gconf->dev);

    net_loop();

    return 0;
}
