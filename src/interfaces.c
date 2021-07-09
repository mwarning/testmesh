#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <assert.h>

#include "net.h"
#include "log.h"
#include "utils.h"
#include "interfaces.h"


static UT_array *g_interfaces = NULL;
//static int g_do_detect_interfaces = 0;
static int g_add_all_interfaces = 0;

static void interface_copy(void *_dst, const void *_src)
{
  struct interface *dst = (struct interface*)_dst;
  struct interface *src = (struct interface*)_src;
  dst->ifindex = src->ifindex;
  dst->ifname = src->ifname ? strdup(src->ifname) : NULL;
}

static void interface_dtor(void *_ifa)
{
  struct interface *ifa = (struct interface*)_ifa;

  if (ifa->ifname) {
    free((char*) ifa->ifname);
  }

  if (ifa->data) {
    free(ifa->data);
  }
}

static UT_icd interface_icd = {sizeof(struct interface), NULL, interface_copy, interface_dtor};

UT_array *get_interfaces()
{
    return g_interfaces;
}

static int interface_registered(const char *ifname)
{
    if (g_interfaces == NULL) {
        return 0;
    }

    struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        if (0 == strcmp(ifa->ifname, ifname)) {
            return 1;
        }
    }

    return 0;
}

int add_interface(const char *ifname)
{
    if (g_interfaces == NULL) {
        utarray_new(g_interfaces, &interface_icd);
    }

    assert(g_interfaces != NULL);

    if (0 == strcmp(ifname, gstate.tun_name)) {
        //log_error("try to add tun interface: %s", ifname);
        return 1;
    }

    if (interface_registered(ifname)) {
        //log_error("duplicate interface: %s", ifname);
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) {
        //log_error("if_nametoindex(%s): %s", ifname, strerror(errno));
        return 1;
    }

    struct interface ifce = {
        .ifindex = ifindex,
        .ifname = ifname
    };

    utarray_push_back(g_interfaces, &ifce);

    return 0;
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
}

int send_mcast(int ifindex, const void* data, int data_len)
{
    if (ifindex <= 0) {
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

void send_mcasts(const void* data, int data_len)
{
    if (g_interfaces == NULL) {
        return;
    }

    struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        int rc = send_mcast(ifa->ifindex, data, data_len);
        //log_debug("ifname: %s, rc: %d", ifa->ifname, rc);
        if (rc != 0) {
        	// disable interface
        	ifa->ifindex = 0;
        }
    }
}

void renew_invalid_ifindex()
{
    if (g_interfaces == NULL) {
        return;
    }

    struct interface *ifa = NULL;
    while ((ifa = utarray_next(g_interfaces, ifa))) {
        if (ifa->ifindex == 0) {
            ifa->ifindex = if_nametoindex(ifa->ifname);
        }
    }
}

static void get_all_interfaces(int (*add_interface_cb)(const char *ifname))
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

        // do not set broadcast via own tunnel interface
        if (0 == strcmp(ifa->ifa_name, gstate.tun_name)) {
            continue;
        }

        add_interface_cb(ifa->ifa_name);

/*
        // if no interface has been set => use all
        if (g_interfaces_len > 0) {
            if (!interface_registered(ifa->ifa_name)) {
                continue;
            }
        }

        //log_debug("send multicast packet on %s via %s", ifa->ifa_name, str_addr6(&gstate.mcast_addr));

        unsigned ifindex = if_nametoindex(ifa->ifa_name);

        // ignore errors if we already have joined the multicast group
        //join_mcast(gstate.sock_mcast_receive, ifindex);

        // we use the socket for unicasts to send to the multicast groups
        _send_mcast(gstate.sock_udp, ifindex, data, data_len);
*/
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

    renew_invalid_ifindex();

    if (g_add_all_interfaces) {
        //g_do_detect_interfaces = 0;
        get_all_interfaces(&add_interface);
    }
}

void interfaces_init()
{
    if (g_interfaces == NULL || utarray_len(g_interfaces) == 0) {
        g_add_all_interfaces = 1;
    }

    net_add_handler(-1, &periodic_interfaces_handler);
}
