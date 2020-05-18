
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


//sudo setcap cap_net_admin,cap_net_raw=eip a.out

#define MULTICAST_ADDR "ff12::1234"
#define MULTICAST_PORT 4321

struct config *gconf = NULL;
float g_coords[3] = {NAN};
int g_sock_help = -1;
int g_unicast_send_socket = -1;
int g_tap_fd = -1;

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

struct neighbor {
    struct sockaddr_in6 addr;
    float coords[3];
    struct neighbor *next;
};

struct interface *g_interfaces = NULL;
struct neighbor *g_neighbors = NULL;

int neighbor_equal(const struct neighbor * neigh, const struct in6_addr *addr, int port) {
    return (0 == memcmp(&neigh->addr.sin6_addr, addr, 16) && port == ntohs(neigh->addr.sin6_port));
}

int neighbor_exists(const struct in6_addr *addr, int port)
{
    struct neighbor *neighbor = g_neighbors;
    while (neighbor) {
        if (neighbor_equal(neighbor, addr, port)) {
            return 1;
        }
        neighbor = neighbor->next;
    }
    return 0;
}

void add_neighbor(const struct in6_addr *addr, int port)
{
    // neighbor UDP address
    struct sockaddr_in6 address = {0};
    address.sin6_port = htons(port);
    memcpy(&address.sin6_addr, addr, sizeof(struct in6_addr));

    log_info("add neighbor: %s", sockaddr6_str(&address));

    struct neighbor *neighbor = (struct neighbor *) malloc(sizeof(struct neighbor));
    //neighbor->ifindex = ifindex;
    memcpy(&neighbor->addr, &address, sizeof(address));
    neighbor->coords[0] = NAN;
    neighbor->coords[1] = NAN;
    neighbor->coords[2] = NAN;

    neighbor->next = g_neighbors;
    g_neighbors = neighbor;
}

void add_interface(const char *ifname)
{
    struct interface *interface = (struct interface *) malloc(sizeof(struct interface));
    memset(interface, 0, sizeof(struct interface));
    interface->ifname = strdup(ifname);

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
        log_error("IPV6_MULTICAST_LOOP %s", strerror(errno));
        close(fd);
        return 1;
    }

    /* Set local interface for outbound multicast datagrams. */
    /* The IP address specified must be associated with a local, */
    /* multicast capable interface. */
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
        log_error("IPV6_MULTICAST_IF %s", strerror(errno));
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
        log_error("SO_REUSEADDR: %s", strerror(errno));
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
        log_error("IPV6_ADD_MEMBERSHIP: %s", strerror(errno));
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
        perror("socket()");
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
        perror("bind()");
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

int setup_ipv6_address(struct sockaddr_in6 *addr, const char *ifname) //struct interface* interface)
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
        log_error("SIOCGIFINDEX: %s", strerror(errno));
        return 1;
    }

    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifce->ifname, IFNAMSIZ-1);
    if (ioctl(g_sock_help, SIOCGIFHWADDR, &if_mac) < 0) {
        log_error("SIOCGIFHWADDR: %s", strerror(errno));
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
      log_error("SIOCSIFMTU: %s", strerror(errno));
      return 1;
    }

    return 0;
}

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if ((fd = open(clonedev, O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

static int _ioctl_v6 = -1;

static int set_base_tunnel_up(const char* name) {
    struct ifreq ifr;
    int oldflags;

    if (_ioctl_v6 < 0) {
        _ioctl_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
        if (_ioctl_v6 == -1) {
            log_error("Node is not IPv6 capable");
            return 1;
        }
    }

    // make sure base interface is up for incoming tunnel traffic
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IF_NAMESIZE);

    if (ioctl(_ioctl_v6, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("SIOCGIFFLAGS for %s: %s", name, strerror(errno));
        return 1;
    }

    oldflags = ifr.ifr_flags;
    ifr.ifr_flags |= IFF_UP;

    if (oldflags == ifr.ifr_flags) {
        // interface is already up/down
        return 0;
    }

    if (ioctl(_ioctl_v6, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("SIOCSIFFLAGS for %s: %s", name, strerror(errno));
        return 1;
    }

    return 0;
}

void usage(const char *pname) {
    fprintf(stderr,
        "Usage:\n"
        "%s -i <ifacename>\n"
        "%s -h\n"
        "\n"
        "-i <ifacename>: Name of interface to use (at least one needed)\n"
        "-h: prints this help text\n",
        pname,
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

// receive annoucements from neighbors
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

    if (!neighbor_exists(&si_other.sin6_addr, port)) {
        add_neighbor(&si_other.sin6_addr, port);
    }
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
    struct neighbor *neighbor = g_neighbors;
    if (neighbor == NULL) {
        log_warning("drop packet, no neighbors known => drop");
    } else while (neighbor) {
        // send to all neihgbors..
        //now reply the client with the same data
        int slen = sizeof(struct sockaddr_in6);
        if (sendto(g_unicast_send_socket, buffer, read_len, 0, (struct sockaddr*) &neighbor->addr, slen) == -1) {
            log_error("Failed forward to %s: %s", sockaddr6_str(&neighbor->addr), strerror(errno));
        }
        neighbor = neighbor->next;
    }
}

/*
void route()
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

    /* Check command line options */
    while((option = getopt(argc, argv, "i:h")) > 0) {
        switch(option) {
          case 'h':
            usage(argv[0]);
            return 0;
          case 'i':
            log_debug("add interface: %s\n", optarg);
            add_interface(optarg);
            //strncpy(entry_if, optarg, IFNAMSIZ-1);
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
    if ((g_tap_fd = tun_alloc(entry_if, IFF_TUN | IFF_NO_PI)) < 0 ) {
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

    set_base_tunnel_up(entry_if);

    log_debug("Successfully connected to interface %s", entry_if);

    net_add_handler(-1, &periodic_handler);
    net_add_handler(g_tap_fd, &tap_handler);

    net_loop();

    return 0;
}
