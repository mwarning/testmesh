#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h> // close()
#include <net/if.h>
#include <sys/time.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // IFF_TUN, IFF_NO_PI, TUNSETIFF
#include <linux/if_tun.h>
#include <fcntl.h> // open(), O_RDWR
#include <stdarg.h>

#include "uthash.h"
#include "log.h"
#include "utils.h"


static const char *protocol_str(int protocol)
{
    switch (protocol) {
        case 0x06: return "TCP";
        case 0x11: return "UDP";
        default: return "???";
    }
}

static const char *debug_payload(uint8_t *buf, size_t buflen)
{
    static char ret[200];

    if (buf == NULL || buflen == 0) {
        snprintf(ret, sizeof(ret), "invalid input");
        return ret;
    }

    int ip_version = (buf[0] >> 4) & 0x0f;

    if (ip_version == 4 && buflen >= 20) {
        // IPv4 packet
        //size_t ihl = buf[0] & 0x0f;
        size_t length = ntohs(*((uint16_t*) &buf[2]));
        struct in_addr *saddr = (struct in_addr *) &buf[12];
        struct in_addr *daddr = (struct in_addr *) &buf[16];
        int protocol = buf[9];

        if (protocol == 0x06 || protocol == 0x11) {
            int sport = ntohs(*((uint16_t*) &buf[20]));
            int dport = ntohs(*((uint16_t*) &buf[22]));

            snprintf(ret, sizeof(ret), "IPv4/%s, plen: %zu, %s:%d => %s:%d",
                protocol_str(protocol), length, str_in4(saddr), sport, str_in4(daddr), dport
            );
        } else {
            snprintf(ret, sizeof(ret), "IPv4/0x%02x, plen: %zu, %s => %s",
                protocol, length, str_in4(saddr), str_in4(daddr)
            );
        }
    } else if (ip_version == 6 && buflen >= 44) {
        // IPv6 packet
        size_t length = ntohs(*((uint16_t*) &buf[4]));
        struct in6_addr *saddr = (struct in6_addr *) &buf[8];
        struct in6_addr *daddr = (struct in6_addr *) &buf[24];
        int protocol = buf[6];

        if (protocol == 0x06 || protocol == 0x11) {
            int sport = ntohs(*((uint16_t*) &buf[40]));
            int dport = ntohs(*((uint16_t*) &buf[42]));
            snprintf(ret, sizeof(ret), "IPv6/%s, plen: %zu, [%s]:%d => [%s]:%d",
                protocol_str(protocol), length, str_in6(saddr), sport, str_in6(daddr), dport
            );
        } else {
            snprintf(ret, sizeof(ret), "IPv6/0x%02x, plen: %zu, %s=> %s",
                protocol, length, str_in6(saddr), str_in6(daddr)
            );
        }
    } else {
        snprintf(ret, sizeof(ret), "unknown packet");
    }

    return ret;
}

// is an IPv4 address to get a mesh ID from
// e.g. 10.0.0.0/8 or 192.168.0.0/16
static int addr4_is_mesh(const struct in_addr *addr)
{
    const uint8_t *a = (const uint8_t*) &addr->s_addr;
    return (a[0] == 10) || (a[0] == 192 && a[1] == 168);
}

// is an IPv6 address to get a mesh ID from
// e.g. 200::/8 or 300::/8
static int addr6_is_mesh(const struct in6_addr *addr)
{
    uint8_t a1 = addr->s6_addr[0];
    uint8_t a2 = addr->s6_addr[1];
    return (a1 == 0x02) || (a1 == 0x03) || (a1 == 0xfe && a2 == 0x80);
}

int parse_ip_packet(uint32_t *dst_id_ret, const uint8_t *buf, ssize_t read_len)
{
    uint32_t src_id = 0;
    uint32_t dst_id = 0;

    if (buf == NULL || read_len == 0) {
        return 1;
    }

    int ip_version = (buf[0] >> 4) & 0x0f;

    if (ip_version == 4 && read_len >= 20) {
        // IPv4 packet
        size_t length = ntohs(*((uint16_t*) &buf[2]));
        struct in_addr *saddr = (struct in_addr *) &buf[12];
        struct in_addr *daddr = (struct in_addr *) &buf[16];

        if (IN_MULTICAST(&daddr->s_addr)) {
            // no support for multicast traffic
            log_debug("parse_ip_packet: IPv4 multicast => drop");
            return 1;
        }

        if (addr4_is_mesh(daddr)) {
            dst_id = in4_addr_id(daddr);
        } else {
            dst_id = gstate.gateway_id;
        }

        src_id = in4_addr_id(saddr);

        if (dst_id == 0) {
            // invalid id
            log_debug("parse_ip_packet: no destination for IPv4 packet => drop");
            return 1;
        }

        log_debug("got 0x%08x => 0x%08x", src_id, dst_id);

        if (read_len < length) {
            log_warning("parse_ip_packet: Partial IPv4 packet (%zu < %zu). Consider to set an MTU. => drop", read_len, length);
            return 1;
        }

        *dst_id_ret = dst_id;
        return 0;
    }

    if (ip_version == 6 && read_len >= 24) {
        // IPv6 packet
        size_t length = ntohs(*((uint16_t*) &buf[4]));
        struct in6_addr *saddr = (struct in6_addr *) &buf[8];
        struct in6_addr *daddr = (struct in6_addr *) &buf[24];

        if (IN6_IS_ADDR_MULTICAST(daddr)) {
            log_debug("parse_ip_packet: IPv6 multicast => drop");
            // no support for multicast traffic
            return 1;
        }

        if (addr6_is_mesh(daddr)) {
            dst_id = in6_addr_id(daddr);
        } else {
            dst_id = gstate.gateway_id;
        }

        src_id = in6_addr_id(saddr);

        if (dst_id == 0) {
            // invalid id
            log_debug("parse_ip_packet: no destination for IPv6 packet => drop");
            return 1;
        }

        log_debug("got 0x%08x => 0x%08x", src_id, dst_id);

        if (read_len < length) {
            log_warning("parse_ip_packet: IPv6 packet bigger than received data (%zu < %zu). => drop", read_len, length);
            return 1;
        }

        *dst_id_ret = dst_id;
        return 0;
    }

    log_debug("parse_ip_packet: invalid ip packet => drop");

    // invalid IP packet
    return 1;
}

static int ip_disabled(uint8_t *data, ssize_t len)
{
    int ip_version = (data[0] >> 4) & 0x0f;
    switch (ip_version) {
        case 4:
            return gstate.disable_ipv4;
        case 6:
            return gstate.disable_ipv6;
        default:
            return 0;
    }
}

ssize_t tun_write(uint8_t *buf, ssize_t buflen)
{
    if (buf == NULL || buflen <= 0 || ip_disabled(buf, buflen)) {
        return -1;
    }

    if (gstate.log_verbosity == VERBOSITY_DEBUG) {
        log_debug("tun_write: blen: %zu, %s", buflen, debug_payload(buf, buflen));
    }

    ssize_t ret = write(gstate.tun_fd, buf, buflen);
    if (ret != buflen) {
        log_error("write() %s", strerror(errno));
    } else {
        //log_debug("write %u bytes to %s => accept packet", (unsigned) len, gstate.tun_name);
    }

    return ret;
}

ssize_t tun_read(uint32_t *dst_id, uint8_t *buf, ssize_t buflen)
{
    ssize_t read_len = read(gstate.tun_fd, buf, buflen);

    if (buf == NULL || read_len <= 0 || ip_disabled(buf, buflen)) {
        return -1;
    }

    if (gstate.log_verbosity == VERBOSITY_DEBUG) {
        log_debug("tun_read: blen: %zu, %s", buflen, debug_payload(buf, buflen));
    }

    if (parse_ip_packet(dst_id, buf, read_len)) {
        return -1;
    }

    return read_len;
}

static int tun_alloc(const char *ifname)
{
    const char *clonedev = "/dev/net/tun";
    struct ifreq ifr = {0};
    int fd;

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        log_error("open(%s): %s", clonedev, strerror(errno));
        return -1;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, ifname);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_error("ioctl(TUNSETIFF) %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (0 != strcmp(ifr.ifr_name, ifname)) {
        return -1;
    }

    return fd;
}

int tun_init(uint32_t id, const char *ifname)
{
    if (id == 0) {
        log_error("No id set.");
        return EXIT_FAILURE;
    }

    if (ifname == NULL) {
        log_error("No tunnel interface set.");
        return EXIT_FAILURE;
    }

    if ((gstate.tun_fd = tun_alloc(ifname)) < 0) {
        log_error("Error creating to %s interface: %s", ifname, strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
