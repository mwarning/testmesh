
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ip6.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/if.h>
#include <stdio.h>
#include <ifaddrs.h>
#include <math.h>

#include "log.h"
#include "utils.h"
#include "net.h"
#include "unix.h"
#include "other.h"
#include "main.h"

#define MULTICAST_ADDR "ff12::1234"
#define MULTICAST_PORT 4321


struct config *gconf = NULL;
float g_coords[3] = {NAN};
int g_sock_help = -1;
int g_unicast_send_socket = -1;
int g_tap_fd = -1;

// address for automatic local network peering
struct sockaddr_in6 g_mcast_addr = {0};

struct interface {
    char *ifname;
    int ifindex;
    uint8_t mac[ETH_ALEN];
    int mcast_receive_socket;
    int mcast_send_socket;
    int ucast_receive_socket;
    struct sockaddr_in6 addr;
    struct interface *next;
};

struct peer {
    struct sockaddr_in6 addr;
    struct peer *next;
};

struct interface *g_interfaces = NULL;
struct peer *g_peers = NULL;

struct peer *find_peer(const struct sockaddr_in6 *addr, int port)
{
    port = htons(port);

    struct peer *peer = g_peers;
    while (peer) {
        // compare address, scope id and port
        if (0 == memcmp(&peer->addr.sin6_addr, &addr->sin6_addr, 16)
                && peer->addr.sin6_scope_id == addr->sin6_scope_id
                && port == peer->addr.sin6_port) {
            return peer;
        }
        peer = peer->next;
    }
    return NULL;
}

void add_peer(const struct sockaddr_in6 *addr, int port)
{
    if (find_peer(addr, port)) {
        return;
    }

    // peer UDP address
    struct sockaddr_in6 address;
    memcpy(&address, addr, sizeof(struct sockaddr_in6));
    address.sin6_port = htons(port);

    struct peer *peer = (struct peer *) malloc(sizeof(struct peer));
    //peer->ifindex = ifindex;
    memcpy(&peer->addr, &address, sizeof(address));

    log_info("add peer: %s", sockaddr6_str(&address));
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

void add_interface(const char *ifname)
{
    if (find_interface(ifname)) {
        return;
    }

    struct interface *interface = (struct interface *) malloc(sizeof(struct interface));
    memset(interface, 0, sizeof(struct interface));
    interface->ifname = strdup(ifname);

    log_info("add interface: %s", ifname);
    interface->next = g_interfaces;
    g_interfaces = interface;
}

//https://www.tenouk.com/Module41c.html
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

    /* Set local interface for outbound multicast datagrams. */
    /* The IP address specified must be associated with a local, */
    /* multicast capable interface. */
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
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
        log_error("setsockopt(SO_REUSEADDR): %s", strerror(errno));
        close(fd);
        return 1;
    }

    // BIND
    struct sockaddr_in6 address = {0};
    address.sin6_family = AF_INET6;
    address.sin6_port = g_mcast_addr.sin6_port;

    if (bind(fd, (struct sockaddr*)&address, sizeof address) < 0) {
        log_error("bind(): %s", strerror(errno));
        close(fd);
        return 1;
    }

    // JOIN MEMBERSHIP
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

int setup_unicast_socket6(struct interface *interface)
{
    int sock;

    if ((sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        log_error("socket() %s", strerror(errno));
        close(sock);
        return 1;
    }

/*
    struct sockaddr_in6 si_me = {0};
    si_me.sin6_family = AF_INET6;
    si_me.sin6_port = htons(port_random());
    memcpy(&si_me.sin6_addr, &interface->addr.sin6_addr, sizeof(struct in6_addr));
*/

    printf("bind to udp: %s (%s)\n", sockaddr6_str(&interface->addr), interface->ifname);

    // bind socket to port
    //if (bind(sock, (struct sockaddr*)&si_me, sizeof(si_me)) == -1) {
    if (bind(sock, (struct sockaddr*)&interface->addr, sizeof(struct sockaddr_in6)) == -1) {
        log_error("bind() %s", strerror(errno));
        close(sock);
        return 1;
    }

    interface->ucast_receive_socket = sock;
    return 0;
}

//https://stackoverflow.com/questions/19227781/linux-getting-all-network-interface-names
int setup_ipv6_address2(struct interface* interface)
{
    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if (if_nidxs != NULL) {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++) {
            printf("%s\n", intf->if_name);
        }

        if_freenameindex(if_nidxs);
    }
    return 0;
}

int setup_ipv6_address(struct sockaddr_in6 *addr, const char *ifname)
{
    struct ifaddrs *addrs;
    struct ifaddrs *cur;

    if (getifaddrs(&addrs) == -1) {
        log_error("getifaddrs() %s", strerror(errno));
        return 1;
    }
    cur = addrs;

    int scope_id = 0;
    while (cur) {
        if (cur->ifa_addr && cur->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6*) cur->ifa_addr;

            if (strcmp(cur->ifa_name, ifname) == 0) {
                if (scope_id > in6->sin6_scope_id) {
                    continue;
                }

                memcpy(addr, in6, sizeof(struct sockaddr_in6));
                addr->sin6_port = htons(port_random());
            }
        }
        cur = cur->ifa_next;
    }

    freeifaddrs(addrs);
}

int setup_interface(struct interface *ifce)
{
    struct ifreq if_idx;
    struct ifreq if_mac;

    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifce->ifname, IFNAMSIZ-1);
    if (ioctl(g_sock_help, SIOCGIFINDEX, &if_idx) < 0) {
        log_error("ioctl(SIOCGIFINDEX) %s", strerror(errno));
        return 1;
    }

    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifce->ifname, IFNAMSIZ-1);
    if (ioctl(g_sock_help, SIOCGIFHWADDR, &if_mac) < 0) {
        log_error("ioctl(SIOCGIFHWADDR) %s", strerror(errno));
        return 1;
    }

    ifce->ifindex = if_idx.ifr_ifindex;
    memcpy(&ifce->mac, (uint8_t *)&if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    setup_mcast_send_socket(&ifce->mcast_send_socket, ifce->ifindex);
    setup_mcast_receive_socket(&ifce->mcast_receive_socket, ifce->ifindex);
    setup_ipv6_address(&ifce->addr, ifce->ifname);
    setup_unicast_socket6(ifce);

    log_info("interface %s: %s", ifce->ifname, sockaddr6_str(&ifce->addr));

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

int tun_alloc(char *dev)
{
    const char *clonedev = "/dev/net/tun";
    struct ifreq ifr = {0};
    int fd;
    int err;

    if ((fd = open(clonedev, O_RDWR)) < 0 ) {
        log_error("open /dev/net/tun %s", strerror(errno));
        return fd;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
        log_error("ioctl(TUNSETIFF) %s", strerror(errno));
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);

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

void usage(const char *pname) {
    fprintf(stderr,
        "Usage:\n"
        "  %s -i eth0 -i wlan0\n"
        "\n"
        "-i <interface>  Name of interface to use (at least one needed).\n"
        "-p <address>    Add a peer mnually by address.\n"
        "-h              Prints this help text.\n",
        pname
    );
}

void periodic_handler(int _events, int _fd) {
    char msg[20];

    static time_t last = 0;
    if (last > 0 && (last + 3) < gconf->time_now) {
        return;
    } else {
        last = gconf->time_now;
    }

    struct interface *interface = g_interfaces;
    while (interface) {
        sprintf(msg, "%d", htons(interface->addr.sin6_port));
        if (sendto(interface->mcast_send_socket, msg, strlen(msg) + 1, 0, (struct sockaddr*)&g_mcast_addr, sizeof(g_mcast_addr)) > 0) {
            log_debug("multicast send: %s (%s)", msg, interface->ifname);
        }
        interface = interface->next;
    }
}

// receive annoucements from peers
void mcast_handler(int events, int fd)
{
    struct sockaddr_in6 si_other;
    int recv_len;
    char buffer[200];

    if (events <= 0) {
        return;
    }

    int slen = sizeof(si_other);
    if ((recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &si_other, &slen)) == -1) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }

    buffer[recv_len] = '\0';
    int port = atoi(buffer);

    add_peer(&si_other, port);
}

void ucast_handler(int events, int fd)
{
    uint8_t buffer[2000];
    struct sockaddr_in6 si_other;
    int recv_len;

    if (events <= 0) {
        return;
    }

    int slen = sizeof(si_other);
    if ((recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &si_other, &slen)) == -1) {
        log_error("recvfrom() %s", strerror(errno));
        return;
    }

    // send out of tap interface
    if (write(g_tap_fd, buffer, recv_len) != recv_len) {
        log_error("write() %s", strerror(errno));
        return;
    }
}

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

    //hexDump (NULL, buffer, len);
    int ip_version = (buffer[0] >> 4) & 0xff;

    // IPv6 packet
    if (ip_version != 6) {
        log_warning("not an IPv6 packet => drop");
        return;
    }

    struct ip6_hdr *hdr = (struct ip6_hdr*) buffer;

    int payload_len = ntohs(*((uint16_t*) &buffer[4]));
    uint8_t *payload = (uint8_t*) &buffer[40];
    uint8_t next_header = buffer[7];
    struct in6_addr *saddr = (struct in6_addr *) &buffer[8];
    struct in6_addr *daddr = (struct in6_addr *) &buffer[24];

    char *tmp = strdup(addr6_str(saddr));
    log_info("received on tap: %s => %s (%d)", tmp, addr6_str(daddr), payload_len);
    free(tmp);

    if (40 + payload_len != read_len) {
        log_warning("size mismatch => drop");
        return;
    }

    if (IN6_IS_ADDR_MULTICAST(daddr)) {
        log_warning("got multicast => drop");
        return;
    }

    //send via udp to another device
    // add header..
    struct peer *peer = g_peers;
    if (peer == NULL) {
        log_warning("drop packet, no peers known => drop");
    } else while (peer) {
        // send to all neihgbors..
        //now reply the client with the same data
        int slen = sizeof(struct sockaddr_in6);
        if (sendto(g_unicast_send_socket, buffer, read_len, 0, (struct sockaddr*) &peer->addr, slen) == -1) {
            // destination address required...?
            log_error("Failed forward to %s: %s", sockaddr6_str(&peer->addr), strerror(errno));
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

int main(int argc, char *argv[]) {
    struct config config = {0};
    config.is_running = 1;
    config.use_syslog = 0;
    config.af = AF_INET;
    config.verbosity = VERBOSITY_DEBUG,

    gconf = &config;

    int option;
    char entry_if[IFNAMSIZ] = "tun0";

    while ((option = getopt(argc, argv, "i:hp:")) > 0) {
        switch(option) {
            case 'h':
                usage(argv[0]);
                return 0;
            case 'i':
                log_debug("add interface: %s\n", optarg);
                add_interface(optarg);
                break;
            case 'p':
                log_debug("add peer: %s\n", optarg);
                struct sockaddr_storage addr;
                if (addr_parse(&addr, optarg, "1234", AF_UNSPEC) == 0) {
                    //add_peer(&addr);
                } else {
                    log_error("Invalid address: %s", optarg);
                    return 1;
                }
                break;
            default:
                log_error("Unknown option %c", option);
                usage(argv[0]);
            return 1;
        }
    }

    g_sock_help = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    argv += optind;
    argc -= optind;

    if (argc > 0) {
        log_error("Too many options!");
        usage(argv[0]);
        return 1;
    }

    if (*entry_if == '\0') {
        log_error("Must specify interface name!");
        usage(argv[0]);
        return 1;
    }

    // setup multicast address
    g_mcast_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, MULTICAST_ADDR, &g_mcast_addr.sin6_addr);
    g_mcast_addr.sin6_port = htons(MULTICAST_PORT);

    unix_signals();

    if ((g_unicast_send_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        log_error("socket() %s", strerror(errno));
        return 1;
    }

    //int flags = IFF_TAP; // IFF_TUN;
    if ((g_tap_fd = tun_alloc(entry_if)) < 0 ) {
        log_error("Error connecting to tun/tap interface %s!", entry_if);
        return 1;
    }

    struct interface *interface = g_interfaces;
    while (interface) {
        log_debug("Setup %s", interface->ifname);
        setup_interface(interface);

        net_add_handler(interface->mcast_receive_socket, &mcast_handler);
        net_add_handler(interface->ucast_receive_socket, &ucast_handler);

        interface = interface->next;
    }

    interface_up(entry_if);

    net_add_handler(-1, &periodic_handler);
    net_add_handler(g_tap_fd, &tap_handler);

    log_debug("Started using %s", entry_if);

    net_loop();

    return 0;
}
