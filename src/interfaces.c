#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <ifaddrs.h>
#include <assert.h>
#include <unistd.h>           // close()
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>         // struct ifreq
#include <linux/if_ether.h>   // ETH_ALEN(6), ETH_HLEN(14), ETH_FRAME_LEN(1514), struct ethhdr
#include <linux/if_packet.h>  // struct sockaddr_ll

#include "net.h"
#include "log.h"
#include "utils.h"
#include "utarray.h"
#include "interfaces.h"


struct interface {
    int ifindex;
    char *ifname;
    struct mac ifmac;
    int ifsock_l2;
};

static UT_array *g_interfaces = NULL;
static int g_add_all_interfaces = 0;
static const struct mac g_nullmac = {{0, 0, 0, 0, 0, 0}};

static void interface_copy(void *_dst, const void *_src)
{
    struct interface *dst = (struct interface*) _dst;
    const struct interface *src = (const struct interface*) _src;

    dst->ifname = strdup(src->ifname);
    dst->ifindex = src->ifindex;
    dst->ifsock_l2 = src->ifsock_l2;
    memcpy(&dst->ifmac, &src->ifmac, ETH_ALEN);
}

static void interface_dtor(void *_ifa)
{
    struct interface *ifa = (struct interface*) _ifa;

    if (ifa->ifname) {
        free(ifa->ifname);
    }

    if (ifa->ifsock_l2 != 0) {
        net_remove_handler(ifa->ifsock_l2, gstate.protocol->ext_handler_l2);
        close(ifa->ifsock_l2);
    }
}

static UT_icd interface_icd = {sizeof(struct interface), NULL, interface_copy, interface_dtor};

static int is_valid_ifa(const struct interface *ifa)
{
    return (ifa->ifindex != 0 && memcmp(&ifa->ifmac, &g_nullmac, ETH_ALEN) != 0);
}

static int find_interface(const char *ifname)
{
    int i = 0;
    struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        if (0 == strcmp(ifa->ifname, ifname)) {
            return i;
        }
        i += 1;
    }

    return -1;
}

static int if_nametomac2(struct mac *addr, const char *ifname)
{
    struct ifreq if_mac = { 0 };

    strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(gstate.sock_help, SIOCGIFHWADDR, &if_mac) < 0) {
        return 1;
    }

    memcpy(addr, &if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}

static int if_nametoindex2(int *ifindex, const char *ifname)
{
    struct ifreq if_idx = { 0 };

    strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(gstate.sock_help, SIOCGIFINDEX, &if_idx) < 0) {
        return 1;
    }

    *ifindex = if_idx.ifr_ifindex;

    return 0;
}

// for raw socket
static int set_promisc_mode(const char *ifname)
{
    struct ifreq ifopts;

    strncpy(ifopts.ifr_name, ifname, IFNAMSIZ-1);
    int rc1 = ioctl(gstate.sock_help, SIOCGIFFLAGS, &ifopts);
    ifopts.ifr_flags |= IFF_PROMISC;
    int rc2 = ioctl(gstate.sock_help, SIOCSIFFLAGS, &ifopts);

    return (rc1 == 0 && rc2 == 0) ? 0 : -1;
}

static int setup_raw_socket(int *sock_ret, const char *ifname)
{
    int sock = *sock_ret;

    if (sock != 0) {
        close(sock);
        net_remove_handler(sock, gstate.protocol->ext_handler_l2);
    }

    // ETH_P_ALL for all
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(gstate.ether_type))) == -1) {
        log_error("socket(SOCK_RAW): %s", strerror(errno));
        return 1;
    }

    int sockopt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) {
        close(sock);
        log_error("setsockopt(SO_REUSEADDR): %s", strerror(errno));
        return 1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, IFNAMSIZ-1) == -1) {
        close(sock);
        log_error("setsockopt(SO_BINDTODEVICE) on %s: %s", ifname, strerror(errno));
        return 1;
    }

    *sock_ret = sock;

    net_add_handler(sock, gstate.protocol->ext_handler_l2);

    return 0;
}

static void interface_setup(struct interface *ifa, int quiet)
{
    const char *ifname = ifa->ifname;

    if (if_nametoindex2(&ifa->ifindex, ifname)) {
        if (!quiet)
            log_warning("Interface not found: %s", ifname);
        return;
    }

    if (if_nametomac2(&ifa->ifmac, ifname)) {
        if (!quiet)
           log_warning("Failed to get interface MAC address: %s", ifname);
        return;
    }

    if (gstate.protocol->ext_handler_l2) {
        if (set_promisc_mode(ifname)) {
            if (!quiet)
                log_warning("Failed to set interface into promisc mode: %s", ifname);
            return;
        }

        if (setup_raw_socket(&ifa->ifsock_l2, ifa->ifname)) {
            return;
        }
    }

    log_info("Interface ready: %s", ifa->ifname);
}

int interface_get_ifindex(int fd)
{
    struct interface *ifa = NULL;

    while ((ifa = utarray_next(g_interfaces, ifa))) {
        if (ifa->ifsock_l2 == fd) {
            return ifa->ifindex;
        }
    }

    return 0;
}

int interface_add(const char *ifname)
{
    if (g_interfaces == NULL) {
        utarray_new(g_interfaces, &interface_icd);
    }

    if (0 == strcmp(ifname, gstate.tun_name)) {
        log_error("try to add tun interface: %s", ifname);
        return 1;
    }

    if (-1 != find_interface(ifname)) {
        log_error("duplicate interface: %s", ifname);
        return 1;
    }

    struct interface ifa = {
        .ifindex = 0,
        .ifname = strdup(ifname),
        .ifmac = g_nullmac,
        .ifsock_l2 = 0,
    };

    interface_setup(&ifa, 0);

    utarray_push_back(g_interfaces, &ifa);

    return 0;
}

int interface_del(const char *ifname)
{
    if (g_interfaces == NULL) {
        return 1;
    }

    int idx = find_interface(ifname);

    if (idx != -1) {
       utarray_erase(g_interfaces, idx, 1);
       return 0;
    }

    return 1;
}

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

/*
    // do not reseive own packets send to a multicast group (remove if we have multiple instances on the same host)
    int loop = 0;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
        log_warning("setsockopt(IPV6_MULTICAST_LOOP) %s\n", strerror(errno));
    }
*/
}

static int send_l2_internal(const struct interface *ifa, const uint8_t *dst_addr, const void* sendbuf, size_t sendlen)
{
    if (!is_valid_ifa(ifa)) {
        return 1;
    }

    if (NULL == gstate.protocol->ext_handler_l2) {
        log_error("No ext_handler_l2 handler registered => abort");
        exit(1);
    }

    struct ethhdr *eh = (struct ethhdr *) sendbuf;

    eh->h_proto = htons(gstate.ether_type);
    memcpy(&eh->h_dest, dst_addr, ETH_ALEN);
    memcpy(&eh->h_source, &ifa->ifmac, ETH_ALEN);

    struct sockaddr_ll socket_address;
    socket_address.sll_halen = ETH_ALEN;
    socket_address.sll_ifindex = ifa->ifindex;
    memcpy(&socket_address.sll_addr, dst_addr, ETH_ALEN);

    if (sendto(ifa->ifsock_l2, sendbuf, sendlen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        log_warning("sendto() failed on raw socket: %s", strerror(errno));
        return 1;
    }

    return 0;
}

void send_bcasts_l2(const void* data, size_t data_len)
{
    log_debug("send_raws: %d (%d interfaces)", (int) data_len, (int) utarray_len(g_interfaces));

    char sendbuf[ETH_FRAME_LEN] = {0};
    static uint8_t dst_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const size_t sendlen = sizeof(struct ethhdr) + data_len;

    if (sendlen >= sizeof(sendbuf)) {
        log_error("send_raws(): data too big");
        return;
    }

    memcpy(&sendbuf[sizeof(struct ethhdr)], data, data_len);

    const struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        send_l2_internal(ifa, &dst_addr[0], &sendbuf[0], sendlen);
    }
}

int send_ucast_l2(const Address *addr, const void* data, size_t data_len)
{
    assert(addr->family == AF_MAC);
    int ifindex = addr->mac.ifindex;
    const uint8_t *dst_addr = &addr->mac.addr.data[0];

    char sendbuf[ETH_FRAME_LEN] = {0};
    const size_t sendlen = sizeof(struct ethhdr) + data_len;

    if (ifindex == 0) {
        log_error("send_ucast_l2(): invalid ifindex");
        return 1;
    }

    if (sendlen > sizeof(sendbuf)) {
        log_error("send_ucast_l2(): data too big");
        return 1;
    }

    memcpy(&sendbuf[sizeof(struct ethhdr)], data, data_len);

    int found = 0;

    const struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        if (ifa->ifindex == ifindex) {
            found = 1;
            break;
        }
    }

    if (!found) {
        log_error("send_raws(): ifindex not found");
        return 1;
    }

    return send_l2_internal(ifa, dst_addr, sendbuf, sizeof(struct ethhdr) + data_len);
}

void send_ucast_l3(const struct sockaddr_storage *addr, const void *data, size_t data_len)
{
    socklen_t slen = sizeof(struct sockaddr_storage);
    if (sendto(gstate.sock_udp, data, data_len, 0, (struct sockaddr*) addr, slen) == -1) {
        log_error("Failed send packet to %s: %s", str_addr2((Address*) addr), strerror(errno));
    }
}

int send_mcast_l3(int ifindex, const void* data, int data_len)
{
    if (ifindex <= 0) {
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

ssize_t recv6_fromto(int fd, void *buf, size_t len, int flags, int *ifindex, struct sockaddr_storage *from, struct sockaddr_storage *to)
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

static void get_all_interfaces(int (*interface_add_cb)(const char *ifname))
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
        if (-1 != find_interface(ifa->ifa_name)) {
            continue;
        }

        interface_add_cb(ifa->ifa_name);
    }

    freeifaddrs(ifaddr);
}

static void periodic_interfaces_handler(int _events, int _fd)
{
    static time_t check_time = 0;

    if (check_time != 0 && check_time <= gstate.time_now) {
        return;
    } else {
        check_time = gstate.time_now + 2;
    }

    struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        if (!is_valid_ifa(ifa)) {
            interface_setup(ifa, 1);
        }
    }

    if (g_add_all_interfaces) {
        //g_do_detect_interfaces = 0;
        get_all_interfaces(&interface_add);
    }
}

int interfaces_debug(FILE *fd)
{
    int count = 0;
    char mac_buf[18];
    struct interface *ifa = NULL;

    fprintf(fd, "name index mac socket status\n");
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        fprintf(fd, "%s %d %s %d %s\n",
            ifa->ifname,
            ifa->ifindex,
            format_mac(mac_buf, &ifa->ifmac),
            ifa->ifsock_l2,
            is_valid_ifa(ifa) ? "active" : "inactive"
        );
        count += 1;
    }
    fprintf(fd, " %d interfaces\n", count);

    return 0;
}

void interfaces_init()
{
    if (g_interfaces == NULL) {
        utarray_new(g_interfaces, &interface_icd);
    }

    if (utarray_len(g_interfaces) == 0) {
        log_info("No interface given => add all");
        g_add_all_interfaces = 1;
    }

    net_add_handler(-1, &periodic_interfaces_handler);
}
