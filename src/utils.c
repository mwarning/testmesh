
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h> // struct ifreq
#include <arpa/inet.h> // inet_ntop
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h> // IFF_TUN, IFF_NO_PI, TUNSETIFF
#include <ifaddrs.h>

#include "main.h"
#include "log.h"
#include "utils.h"


// separate a string into a list of arguments (int argc, char **argv)
int setargs(char **argv, int argv_size, char *args)
{
    int count = 0;

    // skip spaces
    while (isspace(*args)) {
        ++args;
    }

    while (*args) {
        if ((count + 1) < argv_size) {
            argv[count] = args;
        } else {
            log_error("CLI: too many arguments");
            break;
        }

        // parse word
        while (*args && !isspace(*args)) {
            ++args;
        }

        if (*args) {
            *args++ = '\0';
        }

        // skip spaces
        while (isspace(*args)) {
            ++args;
        }

        count++;
    }

    argv[MIN(count, argv_size - 1)] = NULL;

    return count;
}

uint32_t adler32(const void *buf, size_t buflength)
{
    const uint8_t *buffer = (const uint8_t*) buf;

    uint32_t s1 = 1;
    uint32_t s2 = 0;

    for (size_t n = 0; n < buflength; n++) {
        s1 = (s1 + buffer[n]) % 65521;
        s2 = (s2 + s1) % 65521;
    }

    return (s2 << 16) | s1;
}

// fill buffer with random bytes
ssize_t bytes_random(void *buffer, size_t size)
{
   int fd = open("/dev/urandom", O_RDONLY);
   if (fd < 0) {
       log_error("Failed to open /dev/urandom");
       exit(1);
   }

   int rc = read(fd, buffer, size);

   close(fd);

   return rc;
}

bool address_is_multicast(const Address *addr)
{
    switch (addr->family) {
    case AF_MAC: {
        const uint8_t *mac = &addr->mac.addr.data[0];
        return mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e;
    }
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6*) addr)->sin6_addr);
    case AF_INET:
        return IN_MULTICAST(ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr));
    default:
        log_error("address_is_multicast: invalid address");
        exit(1);
    }
}

bool address_is_broadcast(const Address *addr)
{
    static const uint8_t bmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    switch (addr->family) {
    case AF_MAC:
        return 0 == memcmp(&addr->mac.addr, &bmac[0], sizeof(bmac));
    case AF_INET6:
        // there are no broadcasts in IPv6
        return 0;
    case AF_INET:
        return (ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr) & 0xff) == 0xff;
    default:
        log_error("address_is_broadcast: invalid address");
        exit(1);
    }
}

bool address_is_unicast(const Address *addr)
{
    return !address_is_broadcast(addr) && !address_is_multicast(addr);
}

bool address_equal(const Address *a, const Address *b)
{
    return 0 == memcmp(a, b, sizeof(Address));
}

void hex_dump(const char *desc, const void *buf, size_t buflen)
{
    const uint8_t *pc = (const uint8_t*) buf;
    uint8_t buff[17];
    size_t i;

    // Output description if given.
    if (desc != NULL) {
        printf("%s:\n", desc);
    }

    // Length checks.
    if (buflen == 0) {
        printf("  ZERO LENGTH\n");
        return;
    } else if (buflen < 0) {
        printf("  NEGATIVE LENGTH: %ld\n", buflen);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < buflen; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04lx ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And buffer a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) { // isprint() may be better.
            buff[i % 16] = '.';
        } else {
            buff[i % 16] = pc[i];
        }
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII buffer.
    printf("  %s\n", buff);
}

// add source and destination and ports to create a connection fingerprint / stream id
uint32_t get_ip_connection_fingerprint(const uint8_t *buf, size_t buflen)
{
    if (buf == NULL || buflen == 0) {
        return 0;
    }

    uint8_t ip_version = (buf[0] >> 4) & 0x0f;

    if (ip_version == 4 && buflen >= 20) {
        // IPv4 packet
        uint32_t saddr = ((const struct in_addr *) &buf[12])->s_addr;
        uint32_t daddr = ((const struct in_addr *) &buf[16])->s_addr;
        uint8_t protocol = buf[9];
        uint32_t id = saddr ^ daddr;

        if (protocol == 0x06 || protocol == 0x11) {
            // TCP or UDP
            uint16_t sport = *((const uint16_t*) &buf[20]);
            uint16_t dport = *((const uint16_t*) &buf[22]);
            return id ^ (sport + (((uint32_t) dport) << 16));
        } else {
            return id;
        }
    } else if (ip_version == 6 && buflen >= 44) {
        // IPv6 packet
        const uint32_t *saddr = (const uint32_t*) &((const struct in6_addr *) &buf[8])->s6_addr;
        const uint32_t *daddr = (const uint32_t*) &((const struct in6_addr *) &buf[24])->s6_addr;
        uint8_t protocol = buf[6];
        uint32_t id = saddr[0] ^ saddr[1] ^ daddr[0] ^ daddr[1];

        if (protocol == 0x06 || protocol == 0x11) {
            // TCP or UDP
            uint16_t sport = *((const uint16_t*) &buf[40]);
            uint16_t dport = *((const uint16_t*) &buf[42]);
            return id ^ (sport + (((uint32_t) dport) << 16));
        } else {
            return id;
        }
    }

    return 0;
}

struct in6_ifreq {
    struct in6_addr addr;
    uint32_t prefixlen;
    uint32_t ifindex;
};

static const char *str_addr_storage_buf(char *addrbuf, const struct sockaddr_storage *addr)
{
    char buf[INET6_ADDRSTRLEN];
    int port;

    switch (addr->ss_family) {
    case AF_INET6:
        port = ((struct sockaddr_in6 *)addr)->sin6_port;
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buf, sizeof(buf));
        sprintf(addrbuf, "[%s]:%hu", buf, ntohs(port));
        break;
    case AF_INET:
        port = ((struct sockaddr_in *)addr)->sin_port;
        inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, buf, sizeof(buf));
        sprintf(addrbuf, "%s:%hu", buf, ntohs(port));
        break;
    default:
        return "<invalid address>";
    }

    return addrbuf;
}

const char *str_yesno(bool value)
{
    return value ? "yes" : "no";
}

const char *str_onoff(bool value)
{
    return value ? "on" : "off";
}

const char *str_bool(bool value)
{
    return value ? "true" : "false";
}

const char *str_time(time_t time)
{
    static char strdurationbuf[4][64];
    static size_t strdurationbuf_i = 0;
    char *buf = strdurationbuf[++strdurationbuf_i % 4];

    size_t years, days, hours, minutes, seconds;
    const char *prefix = "";

    if (time < 0) {
        time = -time;
        // prepend minus sign
        prefix = "-";
    }

    years = time / (365 * 24 * 60 * 60);
    time -= years * (365 * 24 * 60 * 60);
    days = time / (24 * 60 * 60);
    time -= days * (24 * 60 * 60);
    hours = time / (60 * 60);
    time -= hours * (60 * 60);
    minutes = time / 60;
    time -= minutes * 60;
    seconds = time;

    if (years > 0) {
        snprintf(buf, 64, "%s%zuy%zud", prefix, years, days);
    } else if (days > 0) {
        snprintf(buf, 64, "%s%zud%zuh", prefix, days, hours);
    } else if (hours > 0) {
        snprintf(buf, 64, "%s%zuh%zum", prefix, hours, minutes);
    } else if (minutes > 0) {
        snprintf(buf, 64, "%s%zum%zus", prefix, minutes, seconds);
    } else {
        snprintf(buf, 64, "%s%zus", prefix, seconds);
    }

    return buf;
}

const char *str_duration(time_t from, time_t to)
{
    if (from == 0 || to == 0) {
        return "unknown";
    }

    return str_time(to - from);
}

const char *str_since(time_t time)
{
    return str_duration(gstate.time_started, time);
}

const char *str_ago(time_t time)
{
    return str_duration(time, gstate.time_now);
}

const char *str_bytes(uint64_t bytes)
{
    static char strbytesbuf[4][8];
    static size_t strbytesbuf_i = 0;
    char *buf = strbytesbuf[++strbytesbuf_i % 4];

    if (bytes < 1000) {
        snprintf(buf, 8, "%uB", (unsigned) bytes);
    } else if (bytes < 1000000) {
        snprintf(buf, 8, "%.1fK", bytes / 1000.0);
    } else if (bytes < 1000000000) {
        snprintf(buf, 8, "%.1fM", bytes / 1000000.0);
    } else if (bytes < 1000000000000) {
        snprintf(buf, 8, "%.1fG", bytes / 1000000000.0);
    } else if (bytes < 1000000000000000) {
        snprintf(buf, 8, "%.1fT", bytes / 1000000000000.0);
    } else if (bytes < 1000000000000000000) {
        snprintf(buf, 8, "%.1fP", bytes / 1000000000000000.0);
    } else {
        snprintf(buf, 8, "%.1fE", bytes / 1000000000000000000.0);
    }

    return buf;
}

const char *str_mac(const struct mac *addr)
{
    static char strmacbuf[4][18];
    static size_t strmacbuf_i = 0;
    char *buf = strmacbuf[++strmacbuf_i % 4];

    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr->data[0], addr->data[1], addr->data[2],
            addr->data[3], addr->data[4], addr->data[5]);

    return buf;
}

const char *str_addr(const Address *addr)
{
    static char straddrbuf[4][INET6_ADDRSTRLEN + 8]; // +8 for "[]:<port>"
    static size_t straddrbuf_i = 0;
    char *buf = straddrbuf[++straddrbuf_i % 4];

    switch (addr->family) {
    case AF_INET6:
    case AF_INET:
        return str_addr_storage_buf(buf, (struct sockaddr_storage*) addr);
    case AF_MAC: {
        const struct mac *a = &addr->mac.addr;
        snprintf(buf, INET6_ADDRSTRLEN + 8,
            "%02x:%02x:%02x:%02x:%02x:%02x",
            a->data[0], a->data[1], a->data[2],
            a->data[3], a->data[4], a->data[5]);
        return buf;
    }
    default:
        return NULL;
    }
}

static bool addr_is_link_local_ipv4(const struct in_addr *addr)
{
    return ((addr->s_addr & 0x0000ffff) == 0x0000fea9);
}

static bool addr_is_link_local_ipv6(const struct in6_addr *addr)
{
    return (addr->s6_addr[0] == 0xfe) && ((addr->s6_addr[1] & 0xC0) == 0x80);
}

uint32_t address_ifindex(const Address *addr)
{
    switch (addr->family) {
    case AF_INET6:
        if (addr_is_link_local_ipv6(&addr->ip6.sin6_addr)) {
            return addr->ip6.sin6_flowinfo;
        }
        return 0;
    case AF_INET:
        if (addr_is_link_local_ipv4(&addr->ip4.sin_addr)) {
            return 0; // no interface available for IPv4?
        }
        return 0;
    case AF_MAC:
        return addr->mac.ifindex;
    default:
        return 0;
    }
}

const char *str_addr6(const struct sockaddr_in6 *addr)
{
    static char straddr6buf[4][INET6_ADDRSTRLEN + 8];
    static size_t straddr6buf_i = 0;
    char *buf = straddr6buf[++straddr6buf_i % 4];
    return str_addr_storage_buf(buf, (struct sockaddr_storage*) addr);
}

const char *str_in4(const struct in_addr *addr)
{
    static char strin4buf[4][INET6_ADDRSTRLEN];
    static size_t strin4buf_i = 0;
    char *buf = strin4buf[++strin4buf_i % 4];
    return inet_ntop(AF_INET, addr, buf, INET6_ADDRSTRLEN);
}

const char *str_in6(const struct in6_addr *addr)
{
    static char strin6buf[4][INET6_ADDRSTRLEN];
    static size_t strin6buf_i = 0;
    char *buf = strin6buf[++strin6buf_i % 4];
    return inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN);
}

static uint32_t common_bits(const void *p1, const void* p2, uint32_t bits_n)
{
    const uint8_t *a1 = (const uint8_t*) p1;
    const uint8_t *a2 = (const uint8_t*) p2;

    for (size_t i = 0; i < bits_n; i += 1) {
        uint8_t m = (1 << (7 - (i & 0x0F)));
        if ((a1[i / 8] & m) != (a2[i / 8] & m)) {
            return i + 1;
        }
    }

    return bits_n;
}

uint32_t addr_cmp_subnet(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2, uint32_t subnet_len)
{
    const void *p1;
    const void* p2;

    if (addr1->ss_family != addr2->ss_family) {
        return 0;
    }

    switch (addr1->ss_family) {
    case AF_INET6:
        p1 = &((const struct sockaddr_in6 *)addr1)->sin6_addr;
        p2 = &((const struct sockaddr_in6 *)addr2)->sin6_addr;
        break;
    case AF_INET:
        p1 = &((const struct sockaddr_in *)addr1)->sin_addr;
        p2 = &((const struct sockaddr_in *)addr2)->sin_addr;
        break;
    default:
        return 0;
    }

    return common_bits(p1, p2, subnet_len);
}

bool addr_is_localhost(const struct sockaddr_storage *addr)
{
    //return (memcmp(addr, &in6addr_loopback, 16) == 0);
    // 127.0.0.1
    const uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

    switch (addr->ss_family) {
    case AF_INET:
        return (memcmp(&((struct sockaddr_in *)addr)->sin_addr, &inaddr_loopback, 4) == 0);
    case AF_INET6:
        return (memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr, &in6addr_loopback, 16) == 0);
    default:
        return false;
    }
}

bool addr_is_multicast(const struct sockaddr_storage *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return IN_MULTICAST(ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr));
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6*) addr)->sin6_addr);
    default:
        return false;
    }
}

bool addr_is_link_local(const struct sockaddr_storage *addr)
{
    switch (addr->ss_family) {
    case AF_INET: {
        const struct in_addr *a = &((const struct sockaddr_in *) addr)->sin_addr;
        return addr_is_link_local_ipv4(a);
    }
    case AF_INET6: {
        const struct in6_addr *a = &((const struct sockaddr_in6 *) addr)->sin6_addr;
        return addr_is_link_local_ipv6(a);
    }
    default:
        log_error("addr_is_link_local not implemented for protocol");
        return false;
    }
}

static int addr_parse_internal(struct sockaddr_storage *ret, const char addr_str[], const char port_str[], uint32_t af)
{
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct addrinfo *p = NULL;
    int rc = EXIT_FAILURE;

    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = af;

    if (getaddrinfo(addr_str, port_str, &hints, &info) != 0) {
        return EXIT_FAILURE;
    }

    p = info;
    while (p != NULL) {
        if ((af == AF_UNSPEC || af == AF_INET6) && p->ai_family == AF_INET6) {
            memcpy(ret, p->ai_addr, sizeof(struct sockaddr_in6));
            rc = EXIT_SUCCESS;
            break;
        }

        if ((af == AF_UNSPEC || af == AF_INET) && p->ai_family == AF_INET) {
            memcpy(ret, p->ai_addr, sizeof(struct sockaddr_in));
            rc = EXIT_SUCCESS;
            break;
        }
        p = p->ai_next;
    }

    freeaddrinfo(info);

    return rc;
}

/*
* Parse/Resolve various string representations of
* IPv4/IPv6 addresses and optional port.
* An address can also be a domain name.
* A port can also be a service (e.g. 'www').
*
* "<address>"
* "<ipv4_address>:<port>"
* "[<address>]"
* "[<address>]:<port>"
*/
int addr_parse(struct sockaddr_storage *addr_ret, const char full_addr_str[], const char default_port[], uint32_t af)
{
    char addr_buf[256];
    char *addr_beg;
    char *addr_tmp;
    char *last_colon;
    const char *addr_str = NULL;
    const char *port_str = NULL;
    size_t len;

    len = strlen(full_addr_str);
    if (len >= (sizeof(addr_buf) - 1)) {
        // address too long
        return -1;
    } else {
        addr_beg = addr_buf;
    }

    memset(addr_buf, '\0', sizeof(addr_buf));
    memcpy(addr_buf, full_addr_str, len);

    last_colon = strrchr(addr_buf, ':');

    if (addr_beg[0] == '[') {
        // [<addr>] or [<addr>]:<port>
        addr_tmp = strrchr(addr_beg, ']');

        if (addr_tmp == NULL) {
            // broken format
            return EXIT_FAILURE;
        }

        *addr_tmp = '\0';
        addr_str = addr_beg + 1;

        if (*(addr_tmp + 1) == '\0') {
            port_str = default_port;
        } else if (*(addr_tmp + 1) == ':') {
            port_str = addr_tmp + 2;
        } else {
            // port expected
            return EXIT_FAILURE;
        }
    } else if (last_colon && last_colon == strchr(addr_buf, ':')) {
        // <non-ipv6-addr>:<port>
        addr_tmp = last_colon;
        if (addr_tmp) {
            *addr_tmp = '\0';
            addr_str = addr_buf;
            port_str = addr_tmp + 1;
        } else {
            addr_str = addr_buf;
            port_str = default_port;
        }
    } else {
        // <addr>
        addr_str = addr_buf;
        port_str = default_port;
    }

    return addr_parse_internal(addr_ret, addr_str, port_str, af);
}

bool match(const char *argv[], const char *pattern)
{
    const char *p_beg = &pattern[0];
    size_t j = 0;

    for (size_t i = 0; ; i += 1) {
        const char c = pattern[i];
        if (c == ',' || c == '\0') {
            const char *p_end = &pattern[i];
            const size_t p_len = p_end - p_beg;
            const char *v = argv[j];

            if (v == NULL) {
                return false;
            }

            const size_t v_len = strlen(v);
            if (((p_len == v_len) && !memcmp(v, p_beg, p_len))
                    || ((p_len == 1) && !memcmp("*", p_beg, p_len))) {
                j += 1;
            } else {
                return false;
            }

            p_beg = p_end + 1;
            if (c == '\0') {
                break;
            }
        }
    }

    if (argv[j] != NULL) {
        // another value without a pattern
        return false;
    } else {
        return true;
    }
}
