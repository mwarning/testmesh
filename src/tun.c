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


static void execute(const char *fmt, ...)
{
    char cmd[128];
    va_list vlist;

    va_start(vlist, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, vlist);
    va_end(vlist);

    if (system(cmd) != 0) {
        log_error("Failed to execute: %s", cmd);
        exit(1);
    }
}

void debug_payload(const char *name, uint8_t *buf, size_t buflen)
{
    if (buf == NULL || buflen == 0) {
        log_debug("%s: Invalid packet: buflen: %zu", name, buflen);
        return;
    }

    int ip_version = (buf[0] >> 4) & 0x0f;

    if (ip_version == 4 && buflen >= 20) {
        // IPv4 packet
        size_t length = ntohs(*((uint16_t*) &buf[2]));
        struct in_addr *saddr = (struct in_addr *) &buf[12];
        struct in_addr *daddr = (struct in_addr *) &buf[16];

        log_debug("%s: IPv4 buflen: %zu (length: %zu): %s => %s",
            name, buflen, length, str_in4(saddr), str_in4(daddr));
    } else if (ip_version == 6 && buflen >= 24) {
        // IPv6 packet
        size_t length = ntohs(*((uint16_t*) &buf[4]));
        struct in6_addr *saddr = (struct in6_addr *) &buf[8];
        struct in6_addr *daddr = (struct in6_addr *) &buf[24];

        log_debug("%s: IPv6 buflen: %zu (length: %zu): %s => %s",
            name, buflen, length, str_in6(saddr), str_in6(daddr));
    } else {
        log_debug("%s: invalid packet: ip_version: %d, buflen: %zu",
            name, ip_version, buflen);
    }
}

int parse_ip_packet(uint32_t *dst_id_ret, const uint8_t *buf, ssize_t read_len)
{
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
            log_debug("parse_ip_packet: ipv4 multicast => drop");
            return 1;
        }

        // is link local address
        if ((daddr->s_addr & 0x0000ffff) == 0x0000fea9) {
            const uint8_t* s = (const uint8_t*) &daddr->s_addr;
            ((uint8_t*) &dst_id)[1] = s[2];
            ((uint8_t*) &dst_id)[0] = s[3];
        } else {
            dst_id = gstate.gateway_id;
        }

        if (dst_id == 0) {
            log_debug("parse_ip_packet: no gateway for IPv4 traffic => drop");
            return 1;
        }

        log_debug("read %zu/%zu from %s: %s => %s (0x%08x)",
            read_len, length, gstate.tun_name, str_in4(saddr), str_in4(daddr), dst_id);

        if (read_len != length) {
            log_warning("parse_ip_packet: consider to lower mtu on %s", gstate.tun_name);
            log_warning("parse_ip_packet: incomplete IPv4 packet in buffer => drop");
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

        // is local address
        if ((daddr->s6_addr[0] & 0xfc) == 0xfc) {
            const uint8_t* addr = (const uint8_t*) &daddr->s6_addr;
            ((uint8_t*) &dst_id)[3] = addr[12];
            ((uint8_t*) &dst_id)[2] = addr[13];
            ((uint8_t*) &dst_id)[1] = addr[14];
            ((uint8_t*) &dst_id)[0] = addr[15];
        } else {
            dst_id = gstate.gateway_id;
        }

        if (dst_id == 0) {
            // no valid id / no gateway defined
            log_debug("parse_ip_packet: no gateway for IPv6 traffic => drop");
            return 1;
        }

        log_debug("read %zu/%zu from %s: %s => %s (0x%08x)",
            read_len, length, gstate.tun_name, str_in6(saddr), str_in6(daddr), dst_id);

        *dst_id_ret = dst_id;
        return 0;
    }

    log_debug("parse_ip_packet: invalid ip packet => drop");

    // invalid IP packet
    return 1;
}

ssize_t tun_write(uint8_t *data, ssize_t len)
{
    debug_payload("tun_write", data, len);

    ssize_t ret = write(gstate.tun_fd, data, len);
    if (ret != len) {
        log_error("write() %s", strerror(errno));
    } else {
        log_debug("write %u bytes to %s => accept packet", (unsigned) len, gstate.tun_name);
    }

    return ret;
}

ssize_t tun_read(uint32_t *dst_id, uint8_t *buf, ssize_t buflen)
{
    ssize_t read_len = read(gstate.tun_fd, buf, buflen);

    if (read_len <= 0) {
    	return read_len;
    }

    debug_payload("tun_read", buf, read_len);

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

    if (gstate.tun_setup) {
        execute("ip link set up %s", ifname);
        execute("ip -4 addr flush dev %s", ifname);
        execute("ip -6 addr flush dev %s", ifname);

        const uint8_t *addr = (const uint8_t*) &id;

        if (id < 0xffff) {
            execute("ip -4 addr add 169.254.%u.%u/16 dev tun0", (unsigned) addr[1], (unsigned) addr[0]);
        } else {
            log_warning("Own identifier too big for use with IPv4!");
        }

        execute("ip -6 addr add fe80::%02x%02x:%02x%02x/64 dev tun0", addr[3], addr[2], addr[1], addr[0]);

        // MTU show not be too low, otherwise IP is not supported anymore (addresses are dropped)
        execute("ip link set dev %s mtu 1400", ifname);
    }

    return EXIT_SUCCESS;
}
