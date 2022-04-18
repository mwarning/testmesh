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

#include "ext/uthash.h"
#include "log.h"
#include "net.h"
#include "utils.h"


static uint64_t g_tun_bytes_read = 0;
static uint64_t g_tun_bytes_write = 0;
static time_t g_tun_bytes_updated = 0;

// for speed measurement
static uint64_t g_tun_bytes_read_prev = 0;
static uint64_t g_tun_bytes_write_prev = 0;


uint64_t tun_read_total()
{
    return g_tun_bytes_read;
}

uint64_t tun_write_total()
{
    return g_tun_bytes_write;
}

uint64_t tun_write_speed()
{
    if (g_tun_bytes_write >= g_tun_bytes_write_prev
            && gstate.time_now > g_tun_bytes_updated) {
        return (g_tun_bytes_write - g_tun_bytes_write_prev)
            / (gstate.time_now - g_tun_bytes_updated);
    } else {
        return 0;
    }
}

uint64_t tun_read_speed()
{
    if (g_tun_bytes_read >= g_tun_bytes_read_prev
            && gstate.time_now > g_tun_bytes_updated) {
        return (g_tun_bytes_read - g_tun_bytes_read_prev)
            / (gstate.time_now - g_tun_bytes_updated);
    } else {
        return 0;
    }
}

static const char *protocol_str(int protocol)
{
    static char buf[6];
    switch (protocol) {
        case 0x01: return "ICMP";
        case 0x06: return "TCP";
        case 0x11: return "UDP";
        case 0x3a: return "ICMP6";
        default:
            sprintf(buf, "0x%02x", protocol);
            return buf;
    }
}

/*
 * Write some payload information. It is usually an IP packet.
 */
static const char *debug_payload(uint8_t *buf, size_t buflen)
{
    static char ret[200];

    if (buf == NULL || buflen == 0) {
        snprintf(ret, sizeof(ret), "invalid input");
        return ret;
    }

    uint8_t ip_version = (buf[0] >> 4) & 0x0f;

    if (ip_version == 4 && buflen >= 20) {
        // IPv4 packet
        //size_t ihl = buf[0] & 0x0f;
        size_t length = ntohs(*((uint16_t*) &buf[2]));
        struct in_addr *saddr = (struct in_addr *) &buf[12];
        struct in_addr *daddr = (struct in_addr *) &buf[16];
        uint8_t protocol = buf[9];

        if (protocol == 0x06 || protocol == 0x11) {
            uint16_t sport = ntohs(*((uint16_t*) &buf[20]));
            uint16_t dport = ntohs(*((uint16_t*) &buf[22]));

            snprintf(ret, sizeof(ret), "IPv4/%s, iplen: %zu, %s:%hu => %s:%hu",
                protocol_str(protocol), length, str_in4(saddr), sport, str_in4(daddr), dport
            );
        } else {
            snprintf(ret, sizeof(ret), "IPv4/%s, iplen: %zu, %s => %s",
                protocol_str(protocol), length, str_in4(saddr), str_in4(daddr)
            );
        }
    } else if (ip_version == 6 && buflen >= 44) {
        // IPv6 packet
        size_t length = ntohs(*((uint16_t*) &buf[4]));
        struct in6_addr *saddr = (struct in6_addr *) &buf[8];
        struct in6_addr *daddr = (struct in6_addr *) &buf[24];
        uint8_t protocol = buf[6];

        if (protocol == 0x06 || protocol == 0x11) {
            uint16_t sport = ntohs(*((uint16_t*) &buf[40]));
            uint16_t dport = ntohs(*((uint16_t*) &buf[42]));
            snprintf(ret, sizeof(ret), "IPv6/%s, iplen: %zu, [%s]:%hu => [%s]:%hu",
                protocol_str(protocol), length, str_in6(saddr), sport, str_in6(daddr), dport
            );
        } else {
            snprintf(ret, sizeof(ret), "IPv6/%s, iplen: %zu, %s => %s",
                protocol_str(protocol), length, str_in6(saddr), str_in6(daddr)
            );
        }
    } else {
        snprintf(ret, sizeof(ret), "unknown packet");
    }

    return ret;
}

// IPv4 address, we can extract a mesh ID
// e.g. 10.0.0.0/8 or 192.168.0.0/16
static int addr4_is_mesh(const struct in_addr *addr)
{
    const uint8_t *a = (const uint8_t*) &addr->s_addr;
    return (a[0] == 10) || (a[0] == 192 && a[1] == 168);
}

// IPv6 address, we can extract a mesh ID
// e.g. 200::/8 or 300::/8 or fe80::/16 (we skip the full /7 here)
static int addr6_is_mesh(const struct in6_addr *addr)
{
    uint8_t a1 = addr->s6_addr[0];
    uint8_t a2 = addr->s6_addr[1];
    return (a1 == 0x02) || (a1 == 0x03) || (a1 == 0xfe && a2 == 0x80);
}

// extract node id from mesh IPv6 address
static uint32_t in6_addr_id(const struct in6_addr *addr)
{
    uint32_t id = 0;
    const uint8_t* p = (const uint8_t*) &addr->s6_addr;

    ((uint8_t*) &id)[0] = p[15];
    ((uint8_t*) &id)[1] = p[14];
    ((uint8_t*) &id)[2] = p[13];
    ((uint8_t*) &id)[3] = p[12];

    return id;
}

// extract node id from mesh IPv4 address
static uint32_t in4_addr_id(const struct in_addr *addr)
{
    uint32_t id = 0;
    const uint8_t* p = (const uint8_t*) &addr->s_addr;
    // ignore p[0], it should be always 10 as in 10.x.y.z
    ((uint8_t*) &id)[2] = p[1];
    ((uint8_t*) &id)[1] = p[2];
    ((uint8_t*) &id)[0] = p[3];
    return id;
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
            log_trace("parse_ip_packet: IPv4 multicast => drop");
            return 1;
        }

        // map destination IP address to mesh id
        if (addr4_is_mesh(daddr)) {
            dst_id = in4_addr_id(daddr);
        } else if (gstate.gateway_id_set){
            dst_id = gstate.gateway_id;
        } else {
            // invalid id
            log_trace("parse_ip_packet: no mesh destination for IPv4 packet => drop");
            return 1;
        }

        // map source IP address to mesh id
        if (addr4_is_mesh(saddr)) {
            src_id = in4_addr_id(saddr);
        } else {
            log_warning("read packet with non-mesh IPv4 source address (%s) on %s => drop", str_in4(saddr), gstate.tun_name);
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
            log_trace("parse_ip_packet: IPv6 multicast => drop");
            // no support for multicast traffic
            return 1;
        }

        // map destination IP destination to mesh id
        if (addr6_is_mesh(daddr)) {
            dst_id = in6_addr_id(daddr);
        } else if (gstate.gateway_id_set) {
            dst_id = gstate.gateway_id;
        } else {
            // invalid id
            log_trace("parse_ip_packet: no mesh destination for IPv6 packet => drop");
            return 1;
        }

        // map source IP address to mesh id
        if (addr6_is_mesh(saddr)) {
            src_id = in6_addr_id(saddr);
        } else {
            log_warning("read packet with non-mesh IPv6 source address (%s) on %s => drop", str_in6(saddr), gstate.tun_name);
            return 1;
        }

        if (read_len < length) {
            log_warning("parse_ip_packet: IPv6 packet bigger than received data (%zu < %zu). => drop", read_len, length);
            return 1;
        }

        *dst_id_ret = dst_id;
        return 0;
    }

    log_trace("parse_ip_packet: invalid ip packet => drop");

    // invalid IP packet
    return 1;
}

static int ip_enabled(const uint8_t ip_byte)
{
    uint8_t ip_version = (ip_byte >> 4) & 0x0f;
    switch (ip_version) {
        case 4:
            return gstate.enable_ipv4;
        case 6:
            return gstate.enable_ipv6;
        default:
            return 0;
    }
}

ssize_t tun_write(uint8_t *buf, ssize_t buflen)
{
    if (buf == NULL || buflen <= 0 || !ip_enabled(buf[0])) {
        return -1;
    }

    ssize_t write_len = write(gstate.tun_fd, buf, buflen);

    log_trace("tun_write: %zu bytes, %s", write_len, debug_payload(buf, buflen));

    if (write_len != buflen) {
        log_error("write() %s", strerror(errno));
    }

    if (write_len > 0) {
        if ((g_tun_bytes_updated + 1) < gstate.time_now) {
            g_tun_bytes_write_prev = g_tun_bytes_write;
        }

        g_tun_bytes_write += write_len;
        g_tun_bytes_updated = gstate.time_now;
    }

    return write_len;
}

static void tun_read_internal(int events, int fd)
{
    // some offset to prepend a header before forwarding
    #define OFFSET 100

    uint8_t buffer[OFFSET + ETH_FRAME_LEN];
    uint8_t *buf = &buffer[OFFSET];
    uint32_t dst_id;

    if (events <= 0) {
        return;
    }

    while (1) {
        ssize_t read_len = read(gstate.tun_fd, buf, ETH_FRAME_LEN);

        if (read_len <= 0) {
            break;
        }

        if (!ip_enabled(buf[0])) {
            continue;
        }

        log_trace("tun_read_internal: %zu bytes, %s", read_len, debug_payload(buf, read_len));

        if ((g_tun_bytes_updated + 1) < gstate.time_now) {
            g_tun_bytes_read_prev = g_tun_bytes_read;
        }

        g_tun_bytes_read += read_len;
        g_tun_bytes_updated = gstate.time_now;

        if (parse_ip_packet(&dst_id, buf, read_len)) {
            continue;
        }

        gstate.protocol->tun_handler(dst_id, buf, read_len);
    }
}

ssize_t tun_read(uint32_t *dst_id, uint8_t *buf, ssize_t buflen)
{
    ssize_t read_len = read(gstate.tun_fd, buf, buflen);

    if (buf == NULL || read_len <= 0 || !ip_enabled(buf[0])) {
        return -1;
    }

    if (read_len > 0) {
        g_tun_bytes_read += read_len;
    }

    log_trace("tun_read: %zu bytes, %s", read_len, debug_payload(buf, read_len));

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
        log_error("Failed to create %s device: %s", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    if (0 != strcmp(ifr.ifr_name, ifname)) {
        return -1;
    }

    return fd;
}

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

static void address_mapping_sanity_check()
{
    uint32_t id = 0x12345678;
    const uint8_t *addr = (const uint8_t*) &id;

    char addr_str[INET6_ADDRSTRLEN];
    sprintf(addr_str, "fe80::%02x%02x:%02x%02x", addr[3], addr[2], addr[1], addr[0]);
    struct in6_addr addr_bin = {0};
    if (inet_pton(AF_INET6, addr_str, &addr_bin) <= 0) {
        log_error("invalid address");
        exit(1);
    }

    uint32_t extracted_id = in6_addr_id(&addr_bin);
    if (extracted_id != id) {
        log_error("inconsistent id in address_mapping_sanity_check(): 0x%08x != 0x%08x", extracted_id, id);
        exit(1);
    }
}

int tun_init(uint32_t id, const char *ifname)
{
    address_mapping_sanity_check();

    if (ifname == NULL) {
        log_error("No tunnel interface name set.");
        return EXIT_FAILURE;
    }

    if ((gstate.tun_fd = tun_alloc(ifname)) < 0) {
        log_error("Error creating to %s interface: %s", ifname, strerror(errno));
        return EXIT_FAILURE;
    }

    // tun interface setup
    if (gstate.tun_setup) {
        execute("ip link set up %s", ifname);

        // A smaller MTU is needed to make sure the IP stack leaves enough
        // space for the extra mesh header. This is an issue with IPv4 only.
        // IPv6 has autmatic MTU detection.
        if (gstate.enable_ipv4) {
            execute("ip link set dev %s mtu %u", ifname, gstate.tun_setup_ipv4_mtu);
        }

        const uint8_t *addr = (const uint8_t*) &id;

        if (gstate.enable_ipv4) {
            execute("ip -4 addr flush dev %s", ifname);
            if (id < 0xffff) {
                execute("ip -4 addr add 169.254.%u.%u/16 dev tun0", (unsigned) addr[1], (unsigned) addr[0]);
            } else {
                log_warning("Own identifier too big for use with IPv4!");
            }
        }

        if (gstate.enable_ipv6) {
            execute("ip -6 addr flush dev %s", ifname);
            execute("ip -6 addr add fe80::%02x%02x:%02x%02x/64 dev tun0", addr[3], addr[2], addr[1], addr[0]);
        }
    }

    if (gstate.protocol->tun_handler == NULL) {
        log_error("tun_handler not set for protocol %s", gstate.protocol->name);
        return EXIT_FAILURE;
    }

    g_tun_bytes_updated = gstate.time_now;

    net_add_handler(gstate.tun_fd, &tun_read_internal);

    return EXIT_SUCCESS;
}
