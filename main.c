
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

#define UDP_PORT 1244
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
    struct in6_addr addr;
    struct interface *next;
};

struct neighbor {
    struct sockaddr_in6 addr;
    float coords[3];
    struct neighbor *next;
};

struct interface *g_interfaces = NULL;
struct neighbor *g_neighbors = NULL;

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
void setup_multicast_outbound_sockets6(struct interface *interface)
{
    struct in6_addr localInterface;

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("Opening datagram socket error");
        exit(1);
    }

    int loopch = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loopch, sizeof(loopch)) < 0) {
        perror("Setting IP_MULTICAST_LOOP error");
        close(fd);
        exit(1);
    }

    /* Set local interface for outbound multicast datagrams. */
    /* The IP address specified must be associated with a local, */
    /* multicast capable interface. */

    int ifindex = interface->ifindex;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
      perror("Setting local interface error");
      exit(1);
    }

    interface->mcast_send_socket = fd;
}

int setup_multicast_inbound_sockets6(struct interface *interface)
{
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
        perror("Setting SO_REUSEADDR error");
        close(fd);
        return 1;
    }

    // BIND
    struct sockaddr_in6 address = {0};
    address.sin6_family = AF_INET6;
    address.sin6_port = g_mcast_addr.sin6_port;

    if (bind(fd, (struct sockaddr*)&address, sizeof address) < 0) {
        log_error("Binding datagram socket error");
        close(fd);
        return 1;
    }

    // JOIN MEMBERSHIP
    struct ipv6_mreq group;
    //group.ipv6mr_multiaddr = get_ip_addr(fd, interface->ifname);
    group.ipv6mr_interface = interface->ifindex;
    memcpy(&group.ipv6mr_multiaddr, &g_mcast_addr.sin6_addr, sizeof(struct in6_addr));

    if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof group) < 0) {
        log_error("Adding multicast group error");
        close(fd);
        return 1;
    }

    interface->mcast_receive_socket = fd;
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

    struct sockaddr_in6 si_me = {0};
    si_me.sin6_family = AF_INET6;
    si_me.sin6_port = htons(UDP_PORT);
    memcpy(&si_me.sin6_addr, &interface->addr, sizeof(struct in6_addr));

    printf("bind to udp: %s (%s)\n", sockaddr6_str(&si_me), interface->ifname);

    // bind socket to port
    if (bind(sock, (struct sockaddr*)&si_me, sizeof(si_me)) == -1) {
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
    if ( if_nidxs != NULL )
    {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++)
        {
            printf("%s\n", intf->if_name);
        }

        if_freenameindex(if_nidxs);
    }
    return 0;
}

int setup_ipv6_address(struct interface* interface)
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

            if (strcmp(cur->ifa_name, interface->ifname) == 0) {
                if (scope_id > in6->sin6_scope_id) {
                    continue;
                }

                scope_id = in6->sin6_scope_id;
                memcpy(&interface->addr, &in6->sin6_addr, sizeof(struct in6_addr));
                {
                    char b[50];
                    inet_ntop(AF_INET6, &in6->sin6_addr, b, sizeof(b));
                    printf("set %s scope: %d, ifname: %s\n", b, in6->sin6_scope_id, interface->ifname);
                }
            }
        }
        //ifa_addr
        cur = cur->ifa_next;
    }

    freeifaddrs(addrs);
}


int setup_interface(struct interface *interface)
{
    struct ifreq if_idx;
    struct ifreq if_mac;

    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface->ifname, IFNAMSIZ-1);
    if (ioctl(g_sock_help, SIOCGIFINDEX, &if_idx) < 0) {
        log_error("SIOCGIFINDEX: %s", strerror(errno));
        return 1;
    }

    /* Get the MAC address of the interface to send on */
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, interface->ifname, IFNAMSIZ-1);
    if (ioctl(g_sock_help, SIOCGIFHWADDR, &if_mac) < 0) {
        log_error("SIOCGIFHWADDR: %s", strerror(errno));
        return 1;
    }

    interface->ifindex = if_idx.ifr_ifindex;
    memcpy(&interface->mac, (uint8_t *)&if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    setup_multicast_outbound_sockets6(interface);
    setup_multicast_inbound_sockets6(interface);
    setup_ipv6_address(interface);
    setup_unicast_socket6(interface);

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

static int _set_base_tunnel_up(const char* name) {
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

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(const char *progname) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

void periodic_handler(int _events, int _fd) {
    //printf("outbound_multicast %d\n", events);

    static time_t last = 0;
    if (gconf->time_now == last) {
        return;
    } else {
        last = gconf->time_now;
    }

    char msg[20];
    sprintf(msg, "%d", UDP_PORT); 

    struct interface *interface = g_interfaces;
    while (interface) {
        if (sendto(interface->mcast_send_socket, msg, strlen(msg) + 1, 0, (struct sockaddr*)&g_mcast_addr, sizeof(g_mcast_addr)) > 0) {
            printf("multicast send: %s\n", msg);
        }
        interface = interface->next;
    }

    // send raw..

/*

  if ((g_sock_raw = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
      perror("socket");
      return 1;
  }

    // let's try to send via raw socket
    uint8_t dmac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    struct interface* interface = g_interfaces;
    while (interface) {
        send_packet(g_sock_raw, interface->ifindex, interface->mac, dmac, msg, strlen(msg) + 1);
        interface = interface->next;
    }
*/
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

    add_neighbor(&si_other.sin6_addr, port);
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

    // IPv6 packet
    if (((buffer[0] >> 4) & 0xff) != 6) {
        log_warning("Not an IPv6 packet");
        return;
    }

    struct ip6_hdr *hdr = (struct ip6_hdr*) buffer;

    int payload_len = ntohs(*((uint16_t*) &buffer[4]));
    uint8_t *payload = (uint8_t*) &buffer[40];
    uint8_t next_header = buffer[7];
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &buffer[8], srcip, sizeof(srcip));
    inet_ntop(AF_INET6, &buffer[24], dstip, sizeof(dstip));
    log_info("%s => %s (%d)", srcip, dstip, payload_len);

    if (40 + payload_len != read_len) {
        log_warning("size mismatch\n");
        return;
    }

    //send via udp to another device
    // add header..
    struct neighbor *neighbor = g_neighbors;
    if (neighbor == NULL) {
        log_warning("drop packet, no neighbors known.");
    }

    while (neighbor) {
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
            break;
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

    _set_base_tunnel_up(entry_if);

    log_debug("Successfully connected to interface %s", entry_if);

    net_add_handler(-1, &periodic_handler);
    net_add_handler(g_tap_fd, &tap_handler);

    net_loop();

    return 0;
}
