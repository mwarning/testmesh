#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <ifaddrs.h>
#include <assert.h>
#include <unistd.h>           // close()
#include <net/if.h>           // if_nametoindex()
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>         // struct ifreq
#include <linux/if_ether.h>   // ETH_ALEN(6), ETH_HLEN(14), ETH_FRAME_LEN(1514), struct ethhdr
#include <linux/if_packet.h>  // struct sockaddr_ll

#include "ext/utarray.h"
#include "net.h"
#include "log.h"
#include "utils.h"
#include "traffic.h"
#include "interfaces.h"


struct interface {
    unsigned ifindex;
    struct mac ifmac;
    int ifsock_l2;
    int is_dynamic;     // added dynamically
    char *ifname;       // persistent
    struct interface *next;
};

static struct interface *g_interfaces = NULL;
static const struct mac g_nullmac = {{0, 0, 0, 0, 0, 0}};

// forward declaration
static void read_internal_l2(int events, int fd);

static void interface_reset_handler(struct interface *ifa)
{
    if (ifa->ifsock_l2 != -1) {
        net_remove_handler(ifa->ifsock_l2, &read_internal_l2);
        close(ifa->ifsock_l2);
        ifa->ifsock_l2 = -1;
    }

    ifa->ifmac = g_nullmac;
    ifa->ifindex = 0;
}

static int is_valid_ifa(const struct interface *ifa)
{
    return ifa && (ifa->ifindex > 0) && (memcmp(&ifa->ifmac, &g_nullmac, ETH_ALEN) != 0);
}

static struct interface *get_interface_by_name(const char *ifname)
{
    struct interface *ifa;

    ifa = g_interfaces;
    while (ifa) {
        if (0 == strcmp(ifa->ifname, ifname)) {
            return ifa;
        }
        ifa = ifa->next;
    }

    return NULL;
}

const char *str_ifindex(unsigned ifindex)
{
    struct interface *ifa;

    if (ifindex == 0) {
        return NULL;
    }

    ifa = g_interfaces;
    while (ifa) {
        if (ifa->ifindex == ifindex) {
            return ifa->ifname;
        }
        ifa = ifa->next;
    }

    return NULL;
}

// get mac address of an interface
static struct mac if_nametomac(const char *ifname)
{
    struct ifreq if_mac = { 0 };

    strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(gstate.sock_help, SIOCGIFHWADDR, &if_mac) < 0) {
        return g_nullmac;
    }

    struct mac addr;
    memcpy(&addr, &if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
    return addr;
}

// for raw socket
static int set_promisc_mode(const char *ifname)
{
    struct ifreq ifopts;

    strncpy(ifopts.ifr_name, ifname, IFNAMSIZ - 1);
    int rc1 = ioctl(gstate.sock_help, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    int rc2 = ioctl(gstate.sock_help, SIOCSIFFLAGS, &ifopts);

    return (rc1 == 0 && rc2 == 0) ? 0 : 1;
}

static int setup_raw_socket(int *sock_ret, const char *ifname, unsigned ifindex)
{
    int sock = *sock_ret;

    if (sock != -1) {
        close(sock);
        net_remove_handler(sock, &read_internal_l2);
    }

    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(gstate.ether_type))) == -1) {
        log_error("setup_raw_socket: socket(SOCK_RAW): %s", strerror(errno));
        return 1;
    }

    struct sockaddr_ll interfaceAddr;
    struct packet_mreq mreq;

    memset(&interfaceAddr,0,sizeof(interfaceAddr));
    memset(&mreq, 0, sizeof(mreq));

    interfaceAddr.sll_ifindex = ifindex;
    interfaceAddr.sll_family = AF_PACKET;

    if (bind(sock, (struct sockaddr *)&interfaceAddr, sizeof(interfaceAddr)) == -1) {
        log_error("setup_raw_socket: bind(): %s", strerror(errno));
        return 1;
    }

    mreq.mr_ifindex = ifindex;
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_alen = 6;

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mreq, (socklen_t) sizeof(mreq)) == -1) {
        log_error("setup_raw_socket: setsockopt(PACKET_ADD_MEMBERSHIP): %s", strerror(errno));
        return 1;
    }

    *sock_ret = sock;

    net_add_handler(sock, &read_internal_l2);

    return 0;
}

static int interface_setup(struct interface *ifa)
{
    const char *ifname = ifa->ifname;
    int quiet = ifa->is_dynamic;

    ifa->ifindex = if_nametoindex(ifname);
    if (ifa->ifindex == 0) {
        if (!quiet) {
            log_warning("interface not found: %s", ifname);
        }
        return 1;
    }

    ifa->ifmac = if_nametomac(ifname);
    if (memcmp(&ifa->ifmac, &g_nullmac, ETH_ALEN) == 0) {
        if (!quiet)
           log_warning("failed to get interface MAC address: %s", ifname);
        return 1;
    }

    if (gstate.protocol->ext_handler_l2) {
        if (set_promisc_mode(ifname)) {
            if (!quiet)
                log_warning("failed to set interface into promisc mode: %s", ifname);
            return 1;
        }

        if (setup_raw_socket(&ifa->ifsock_l2, ifa->ifname, ifa->ifindex)) {
            return 1;
        }
    }

    log_info("interface added: %s (%s)", ifa->ifname, ifa->is_dynamic ? "dynamic" : "static");

    return 0;
}

static struct interface *get_interface_by_fd(int fd)
{
    struct interface *ifa = NULL;

    if (fd == -1) {
        return NULL;
    }

    ifa = g_interfaces;
    while (ifa) {
        if (ifa->ifsock_l2 == fd) {
            return ifa;
        }
        ifa = ifa->next;
    }

    return NULL;
}

static void interface_remove(struct interface *ifa_prev, struct interface *ifa)
{
    if (ifa == g_interfaces) {
        g_interfaces = ifa->next;
    } else {
        ifa_prev->next = ifa->next;
    }

    free(ifa->ifname);
    free(ifa);
}

static int interface_add_internal(const char *ifname, int is_dynamic)
{
    if (gstate.tun_name && 0 == strcmp(ifname, gstate.tun_name)) {
        log_error("Cannot add own tun interface: %s", ifname);
        return 1;
    }

    if (get_interface_by_name(ifname)) {
        log_error("Cannot add duplicate interface: %s", ifname);
        return 1;
    }

    struct interface *ifa = (struct interface*) calloc(1, sizeof(struct interface));
    *ifa = (struct interface) {
        .ifname = strdup(ifname),
        .ifmac = g_nullmac,
        .ifsock_l2 = -1,
        .is_dynamic = is_dynamic,
    };

    interface_setup(ifa);

    // prepend
    if (g_interfaces == NULL) {
        ifa->next = NULL;
    } else {
        ifa->next = g_interfaces;
    }
    g_interfaces = ifa;

    return 0;
}

int interface_add(const char *ifname)
{
    return interface_add_internal(ifname, 0);
}

int interface_del(const char *ifname)
{
    struct interface *ifa_prev;
    struct interface *ifa;

    if (g_interfaces == NULL) {
        return 1;
    }

    ifa_prev = NULL;
    ifa = g_interfaces;
    while (ifa) {
        if (0 == strcmp(ifa->ifname, ifname)) {
            interface_remove(ifa_prev, ifa);
            return 0;
        }
        ifa_prev = ifa;
        ifa = ifa->next;
    }

    return 1;
}

static void init_macaddr(Address *dst, const void *mac_addr, int ifindex)
{
    memset(dst, 0, sizeof(Address));
    dst->mac.family = AF_MAC;
    memcpy(&dst->mac.addr, mac_addr, ETH_ALEN);
    dst->mac.ifindex = ifindex;
}

static void read_internal_l2(int events, int fd)
{
    // some offset to prepend a header before forwarding
    #define OFFSET 100

    struct interface *ifa;
    ssize_t readlen;
    uint8_t buffer[OFFSET + ETH_FRAME_LEN];
    uint8_t *buf = &buffer[OFFSET];

    if (events <= 0) {
        return;
    }

    readlen = read(fd, buf, ETH_FRAME_LEN);

    if (readlen < 0 || readlen > ETH_FRAME_LEN) {
        log_warning("recv(): %zd %s", readlen, strerror(errno));
        return;
    }

    ifa = get_interface_by_fd(fd);

    if (readlen < sizeof(struct ethhdr)) {
        log_error("recvfrom() for %s returned %lld: %s",
            (ifa ? ifa->ifname : "???"),
            readlen,
            (readlen < 0) ? strerror(errno) : "packet too small");
        return;
    }

    if (!is_valid_ifa(ifa)) {
        log_error("recvfrom() on invalid interface %s", (ifa ? ifa->ifname : "???"));
        return;
    }

    struct ethhdr *eh = (struct ethhdr *) &buf[0];

    Address src_addr;
    //Address dst_addr;

    init_macaddr(&src_addr, &eh->h_source, ifa->ifindex);
    //init_macaddr(&dst_addr, &eh->h_dest, ifa->ifindex);

    traffic_add_bytes_read(&src_addr, readlen);

    uint8_t *payload = &buf[sizeof(struct ethhdr)];
    size_t payload_len = readlen - sizeof(struct ethhdr);

    assert(src_addr.family == AF_MAC);
    gstate.protocol->ext_handler_l2(&src_addr, payload, payload_len);
}

static int send_internal_l2(struct interface *ifa, const uint8_t dst_addr[ETH_ALEN], const void* sendbuf, size_t sendlen)
{
    if (!is_valid_ifa(ifa)) {
        return 1;
    }

    if (!gstate.protocol->ext_handler_l2) {
        log_error("No ext_handler_l2 handler registered => abort");
        exit(1);
    }

    struct ethhdr *eh = (struct ethhdr *) sendbuf;

    eh->h_proto = htons(gstate.ether_type);
    memcpy(&eh->h_dest, dst_addr, ETH_ALEN);
    memcpy(&eh->h_source, &ifa->ifmac, ETH_ALEN);

    struct sockaddr_ll socket_address = {};
    socket_address.sll_halen = ETH_ALEN;
    socket_address.sll_ifindex = ifa->ifindex;
    memcpy(&socket_address.sll_addr, dst_addr, ETH_ALEN);

    if (sendto(ifa->ifsock_l2, sendbuf, sendlen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        log_warning("sendto() failed on raw socket for %s: %s", ifa->ifname, strerror(errno));
        interface_reset_handler(ifa);
        return 1;
    }

    Address addr;
    init_macaddr(&addr, dst_addr, ifa->ifindex);
    traffic_add_bytes_write(&addr, sendlen);

    return 0;
}

void send_bcasts_l2(const void* data, size_t data_len)
{
    static uint8_t dst_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    char sendbuf[ETH_FRAME_LEN] = {0};
    const size_t sendlen = sizeof(struct ethhdr) + data_len;

    if (sendlen >= sizeof(sendbuf)) {
        log_error("send_raws(): too much data");
        return;
    }

    memcpy(&sendbuf[sizeof(struct ethhdr)], data, data_len);

    int count = 0;
    struct interface *ifa = g_interfaces;
    while (ifa) {
        send_internal_l2(ifa, &dst_addr[0], &sendbuf[0], sendlen);
        count += 1;
        ifa = ifa->next;
    }

    log_trace("send_raws: %d bytes on %d interfaces", (int) data_len, count);
}

int send_ucast_l2(const Address *addr, const void* data, size_t data_len)
{
    struct interface *ifa;

    if (addr->family != AF_MAC) {
        log_error("send_ucast_l2: used wrong address type");
        return 1;
    }

    unsigned ifindex = addr->mac.ifindex;
    const uint8_t *dst_addr = &addr->mac.addr.data[0];

    char sendbuf[ETH_FRAME_LEN] = {0};
    const size_t sendlen = sizeof(struct ethhdr) + data_len;

    if (ifindex == 0) {
        log_error("send_ucast_l2(): invalid ifindex");
        return 1;
    }

    if (sendlen > sizeof(sendbuf)) {
        log_error("send_ucast_l2(): too much data (%zu > %zu)", sendlen, sizeof(sendbuf));
        return 1;
    }

    memcpy(&sendbuf[sizeof(struct ethhdr)], data, data_len);

    int found = 0;
    ifa = g_interfaces;
    while (ifa) {
        if (ifa->ifindex == ifindex) {
            found = 1;
            break;
        }
        ifa = ifa->next;
    }

    if (!found) {
        log_error("send_raws(): ifindex not found: %u", ifindex);
        return 1;
    }

    return send_internal_l2(ifa, dst_addr, sendbuf, sizeof(struct ethhdr) + data_len);
}

static void read_internal_l3(int events, int fd)
{
    Address src_addr = {0};
    ssize_t readlen;
    uint8_t buffer[ETH_FRAME_LEN];
    socklen_t addr_len;

    if (events <= 0) {
        return;
    }

    addr_len = sizeof(Address);
    readlen = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &src_addr, &addr_len);
    //static ssize_t recv6_fromto(int fd, void *buf, size_t len, int flags, unsigned *ifindex, struct sockaddr_storage *from, struct sockaddr_storage *to)

    if (readlen <= 0) {
        log_error("recvfrom() for %s returned %lld: %s", str_addr(&src_addr), readlen, strerror(errno));
        return;
    }


    traffic_add_bytes_read(&src_addr, readlen);

    assert(src_addr.family == AF_INET6 || src_addr.family == AF_INET);
    gstate.protocol->ext_handler_l3(&src_addr, &buffer[0], readlen);
}

void send_ucast_l3(const Address *addr, const void *data, size_t data_len)
{
    if (!(addr->family == AF_INET || addr->family == AF_INET6)) {
        log_error("send_ucast_l3: used wrong address type");
        return;
    }

    socklen_t slen = sizeof(struct sockaddr_storage);
    if (sendto(gstate.sock_udp, data, data_len, 0, (struct sockaddr*) addr, slen) == -1) {
        log_error("failed send packet to %s: %s", str_addr(addr), strerror(errno));
    }
}

#ifdef MULTICAST
static void join_mcast(int sock, int ifindex)
{
    struct ipv6_mreq group = {0};
    //group.ipv6mr_multiaddr = get_ip_addr(fd, interface->ifname);
    group.ipv6mr_interface = ifindex; // if_nametoindex("vboxnet0"); //hm, works 
    memcpy(&group.ipv6mr_multiaddr, &gstate.mcast_addr.sin6_addr, sizeof(struct in6_addr));

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
        if (errno != EADDRINUSE) {
            log_error("setsockopt(IPV6_ADD_MEMBERSHIP) %s", strerror(errno));
            exit(1);
        }
    }

    // do not reseive own packets send to a multicast group (remove if we have multiple instances on the same host)
    //int loop = 0;
    //if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
    //    log_warning("setsockopt(IPV6_MULTICAST_LOOP) %s\n", strerror(errno));
    //}
}

int send_mcast_l3(unsigned ifindex, const void* data, int data_len)
{
    if (ifindex == 0) {
        return 1;
    }

    if (gstate.sock_udp == -1) {
        log_error("no handler registered for udp socket!");
        return 1;
    }

    // ignore errors if we already have joined
    // the multicast group previously
    join_mcast(gstate.sock_mcast_receive, ifindex);

    if (setsockopt(gstate.sock_udp, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
        log_warning("setsockopt(IPV6_MULTICAST_IF) %s\n", strerror(errno));
        // interface vanished or have been recreated (for VPN tunnels or usb ethernet dongles)
        //g_do_detect_interfaces = 1;
        return 1;
    }

    if (sendto(gstate.sock_udp, data, data_len, 0, (struct sockaddr*) &gstate.mcast_addr, sizeof(gstate.mcast_addr)) < 0) {
        log_warning("sendto() %s", strerror(errno));
    }

    return 0;
}

void send_mcasts_l3(const void* data, int data_len)
{
    if (g_interfaces == NULL) {
        return;
    }

    if (gstate.sock_udp == -1) {
        log_error("no handler registered for udp socket!");
        return;
    }

    struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        int rc = send_mcast_l3(ifa->ifindex, data, data_len);
        if (rc != 0) {
        	// disable interface
        	ifa->ifindex = 0;
            ifa->ifmac = g_nullmac;
        }
    }
}
#endif

#if 0
static ssize_t recv6_fromto(int fd, void *buf, size_t len, int flags, unsigned *ifindex, struct sockaddr_storage *from, struct sockaddr_storage *to)
{
    struct iovec iov[1];
    char cmsg6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct cmsghdr *cmsgptr;
    struct msghdr msg;
    ssize_t recv_length;

    iov[0].iov_base = buf;
    iov[0].iov_len = len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr *)from;
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = &cmsg6;
    msg.msg_controllen = sizeof(cmsg6);

    recv_length = recvmsg(fd, &msg, flags);

    if (recv_length < 0) {
        log_error("recvmsg() %s", strerror(errno));
        return recv_length;
    }

    for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
        if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO) {
            //log_debug("set ipv6 socket data");
            struct in6_pktinfo* info = (struct in6_pktinfo*) CMSG_DATA(cmsgptr);
            ((struct sockaddr_in6*)to)->sin6_family = AF_INET6;
            memcpy(&((struct sockaddr_in6*)to)->sin6_addr, &info->ipi6_addr, sizeof(struct in6_addr));
            ((struct sockaddr_in6*)to)->sin6_port = 0;
            *ifindex = info->ipi6_ifindex;
            break;
        }
    }

    if (cmsgptr == NULL) {
        log_error("IPV6_PKTINFO not found!");
        return 0;
    } else {
        return recv_length;
    }
}
#endif

// add interfaces automatically
static void find_and_add_interfaces()
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

        if (!(ifa->ifa_flags & IFF_RUNNING) || (ifa->ifa_flags & IFF_LOOPBACK)) {
            continue;
        }

        if (ifa->ifa_addr->sa_family != AF_PACKET) {
            continue;
        }

        // do not send protocol data via own tunnel interface
        if (0 == strcmp(ifa->ifa_name, gstate.tun_name)) {
            continue;
        }

        // avoid to add interfaces multiple times
        if (get_interface_by_name(ifa->ifa_name)) {
            continue;
        }

        interface_add_internal(ifa->ifa_name, 1);
    }

    freeifaddrs(ifaddr);
}

// interfaces might have disappeared or appeared
static void periodic_interfaces_handler(int _events, int _fd)
{
    static time_t check_time = 0;
    struct interface *ifa_prev;
    struct interface *ifa;

    if (check_time != 0 && check_time >= gstate.time_now) {
        return;
    } else {
        check_time = gstate.time_now + 5;
    }

    if (gstate.find_interfaces) {
        find_and_add_interfaces();
    }

    // detect vanished interfaces
    // - reset if added via configuration
    // - remove if added dynamically
    ifa_prev = NULL;
    ifa = g_interfaces;
    while (ifa) {
        unsigned ifindex = if_nametoindex(ifa->ifname);
        if (ifindex != ifa->ifindex) {
            log_warning("interface %s changed ifindex: %d => %d", ifa->ifname, ifa->ifindex, ifindex);
            interface_reset_handler(ifa);
        }

        if (!is_valid_ifa(ifa)) {
            int rc = interface_setup(ifa);
            if (rc && ifa->is_dynamic) {
                struct interface *next = ifa->next;
                interface_remove(ifa_prev, ifa);
                ifa = next;
                continue;
            }
        }
        ifa_prev = ifa;
        ifa = ifa->next;
    }
}

int interfaces_debug(FILE *fd)
{
    int count = 0;
    struct interface *ifa;

    fprintf(fd, "name         status mac-address        dynamic ifsocket ifindex\n");

    ifa = g_interfaces;
    while (ifa) {
        fprintf(fd, "%-12s %-6s %-18s %-7s %-8u %-8u\n",
            ifa->ifname,
            is_valid_ifa(ifa) ? "up" : "down",
            str_mac(&ifa->ifmac),
            str_enabled(ifa->is_dynamic),
            ifa->ifsock_l2,
            ifa->ifindex
        );
        count += 1;
        ifa = ifa->next;
    }
    fprintf(fd, " %d interfaces\n", count);

    return 0;
}

void interfaces_init()
{
    if (g_interfaces == NULL && gstate.find_interfaces == 0) {
        log_warning("No mesh interfaces given.");
    }

    if (gstate.sock_udp > 0) {
        net_add_handler(gstate.sock_udp, &read_internal_l3);
    }

#ifdef MULTICAST
    if (gstate.sock_mcast_receive > 0) {
        net_add_handler(gstate.sock_mcast_receive, &read_internal_l3);
    }
#endif

    net_add_handler(-1, &periodic_interfaces_handler);
}
