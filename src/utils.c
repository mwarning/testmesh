
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
int bytes_random(void *buffer, size_t size)
{
   int fd;
   int rc;

   fd = open("/dev/urandom", O_RDONLY);
   if (fd < 0) {
       log_error("Failed to open /dev/urandom");
       exit(1);
   }

   rc = read(fd, buffer, size);

   close(fd);

   return rc;
}

void set_macaddr(Address *dst, const uint8_t *addr, int ifindex)
{
    dst->mac.family = AF_MAC;
    memcpy(&dst->mac.addr, addr, 6);
    dst->mac.ifindex = ifindex;
}

const char *address_type_str(const Address *addr)
{
    static const char *ucast = "unicast";
    static const char *mcast = "multicast";
    static const char *bcast = "broadcast";
    static const uint8_t bmac[6] = {0,0,0,0,0,0};

    switch (addr->family) {
    case AF_MAC:
        //TODO: distinguish broadcast/multicast
        return memcmp(&addr->mac.addr, &bmac[0], sizeof(bmac)) ? ucast : bcast;
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6*) addr)->sin6_addr) ? mcast : ucast;
    case AF_INET:
        return IN_MULTICAST(ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr)) ? mcast : ucast;
    default:
        exit(1);
    }
}

void hex_dump(const char *desc, const void *addr, const int len)
{
    const unsigned char *pc = (const unsigned char *)addr;
    unsigned char buff[17];
    int i;

    // Output description if given.
    if (desc != NULL) {
        printf("%s:\n", desc);
    }

    // Length checks.
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    } else if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
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

struct in6_ifreq {
    struct in6_addr addr;
    uint32_t prefixlen;
    unsigned int ifindex;
};

// configure interface
int add_addr6(struct in6_addr *addr, int prefixlen, unsigned ifindex)
{
    struct in6_ifreq ifr6;

    memcpy(&ifr6.addr, addr, sizeof(struct in6_addr));
    ifr6.ifindex = ifindex;
    ifr6.prefixlen = prefixlen;
    return ioctl(gstate.sock_help, SIOCSIFADDR, &ifr6);
}

// configure interface
int del_addr6(struct in6_addr *addr, int prefixlen, unsigned ifindex)
{
    struct in6_ifreq ifr6;

    memcpy(&ifr6.addr, addr, sizeof(struct in6_addr));
    ifr6.ifindex = ifindex;
    ifr6.prefixlen = prefixlen;
    return ioctl(gstate.sock_help, SIOCDIFADDR, &ifr6);
}

static const char *str_addr_buf(char *addrbuf, const struct sockaddr_storage *addr)
{
    //static char buf[INET6_ADDRSTRLEN + 8];
    char buf[INET6_ADDRSTRLEN];
    int port;

    switch (addr->ss_family) {
    case AF_INET6:
        port = ((struct sockaddr_in6 *)addr)->sin6_port;
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buf, sizeof(buf));
        sprintf(addrbuf, "[%s]:%d", buf, ntohs(port));
        break;
    case AF_INET:
        port = ((struct sockaddr_in *)addr)->sin_port;
        inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, buf, sizeof(buf));
        sprintf(addrbuf, "%s:%d", buf, ntohs(port));
        break;
    default:
        return "<invalid address>";
    }

    return addrbuf;
}

const char *str_addr(const struct sockaddr_storage *addr)
{
    static char addrbuf[2][INET6_ADDRSTRLEN + 8];
    static unsigned addrbuf_i = 0;
    return str_addr_buf(addrbuf[++addrbuf_i % 2], addr);
}

const char *str_addr6(const struct sockaddr_in6 *addr)
{
    return str_addr((struct sockaddr_storage*) addr);
}

const char *str_in4(const struct in_addr *addr)
{
    static char addrbuf[2][INET6_ADDRSTRLEN];
    static unsigned addrbuf_i = 0;
    return inet_ntop(AF_INET, addr, addrbuf[++addrbuf_i % 2], INET6_ADDRSTRLEN);
}

const char *str_in6(const struct in6_addr *addr)
{
    static char addrbuf[2][INET6_ADDRSTRLEN];
    static unsigned addrbuf_i = 0;
    return inet_ntop(AF_INET6, addr, addrbuf[++addrbuf_i % 2], INET6_ADDRSTRLEN);
}

static int common_bits(const void *p1, const void* p2, int bits_n)
{
    const uint8_t *a1 = (const uint8_t*) p1;
    const uint8_t *a2 = (const uint8_t*) p2;

    for (int i = 0; i < bits_n; i += 1) {
        uint8_t m = (1 << (7 - (i & 0x0F)));
        if ((a1[i / 8] & m) != (a2[i / 8] & m)) {
            return i + 1;
        }
    }

    return bits_n;
}

int addr_cmp_subnet(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2, int subnet_len)
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

int addr_is_localhost(const struct sockaddr_storage *addr)
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
        return 0;
    }
}

int addr_is_multicast(const struct sockaddr_storage *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return IN_MULTICAST(ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr));
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6*) addr)->sin6_addr);
    default:
        return 0;
    }
}

int addr_is_link_local(const struct sockaddr_storage *addr)
{
    switch (addr->ss_family) {
    case AF_INET: {
        const struct in_addr *a = &((const struct sockaddr_in *) addr)->sin_addr;
        return ((a->s_addr & 0x0000ffff) == 0x0000fea9);
    }
    case AF_INET6: {
        const struct in6_addr *a = &((const struct sockaddr_in6 *) addr)->sin6_addr;
        return (a->s6_addr[0] == 0xfe) && ((a->s6_addr[1] & 0xC0) == 0x80);
    }
    default:
        log_error("add_is_link_local not implemented for protocol");
        return 0;
    }
}

int addr_port(const struct sockaddr_in6 *addr)
{
    return ntohs(addr->sin6_port);
    /*
    switch (addr->ss_family) {
    case AF_INET:
        return ntohs(((struct sockaddr_in *)addr)->sin_port);
    case AF_INET6:
        return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    default:
        return 0;
    }*/
}

int addr_len(const struct sockaddr_storage *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}

static int addr_parse_internal(struct sockaddr_storage *ret, const char addr_str[], const char port_str[], int af)
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
* A port can also be a service	(e.g. 'www').
*
* "<address>"
* "<ipv4_address>:<port>"
* "[<address>]"
* "[<address>]:<port>"
*/
int addr_parse(struct sockaddr_storage *addr_ret, const char full_addr_str[], const char default_port[], int af)
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

// Compare two ip addresses and port
int addr_equal(const struct sockaddr_storage *addr1, const struct sockaddr_storage *addr2)
{
    if (addr1->ss_family != addr2->ss_family) {
        return 0;
    } else if (addr1->ss_family == AF_INET) {
        const struct sockaddr_in *a1 = (const struct sockaddr_in *) addr1;
        const struct sockaddr_in *a2 = (const struct sockaddr_in *) addr2;
        return (a1->sin_port == a2->sin_port) && (0 == memcmp(&a1->sin_addr, &a2->sin_addr, 4));
    } else if (addr1->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a1 = (const struct sockaddr_in6 *) addr1;
        const struct sockaddr_in6 *a2 = (const struct sockaddr_in6 *) addr2;
        return (a1->sin6_port == a2->sin6_port) && (0 == memcmp(&a1->sin6_addr, &a2->sin6_addr, 16));
    } else {
        return 0;
    }
}

int addr_equal6(const struct in6_addr *addr1, const struct in6_addr *addr2)
{
    return memcmp(addr1, addr2, sizeof(struct in6_addr));
}

const char *format_mac(char buf[18], const struct mac *addr)
{
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
        addr->data[0], addr->data[1], addr->data[2],
        addr->data[3], addr->data[4], addr->data[5]);
    return buf;
}

const char *format_duration(char buf[64], time_t from, time_t to)
{
    int days, hours, minutes, seconds;
    long long int secs;
    const char *neg = "";

    if (from <= to) {
        secs = to - from;
    } else {
        secs = from - to;
        // Prepend minus sign
        neg = "-";
    }

    days = secs / (24 * 60 * 60);
    secs -= days * (24 * 60 * 60);
    hours = secs / (60 * 60);
    secs -= hours * (60 * 60);
    minutes = secs / 60;
    secs -= minutes * 60;
    seconds = secs;

    if (days > 0) {
        snprintf(buf, 64, "%s%dd %dh", neg, days, hours);
    } else if (hours > 0) {
        snprintf(buf, 64, "%s%dh %dm", neg, hours, minutes);
    } else if (minutes > 0) {
        snprintf(buf, 64, "%s%dm %ds", neg, minutes, seconds);
    } else {
        snprintf(buf, 64, "%s%ds", neg, seconds);
    }

    return buf;
}

const char *format_size(char buf[64], unsigned bytes)
{
    if (bytes < 1000) {
        sprintf(buf, "%u B", bytes);
    } else if (bytes < 1000000) {
        sprintf(buf, "%.0f K", bytes / 1000.0);
    } else if (bytes < 1000000000) {
        sprintf(buf, "%.1f M", bytes / 1000000.0);
    } else if (bytes < 1000000000000) {
        sprintf(buf, "%.2f G", bytes / 1000000000.0);
    } else {
        sprintf(buf, "%.2f T", bytes / 1000000000000.0);
    }

    return buf;
}

const char *str_addr2(const Address *addr)
{
    static char addrbuf[2][INET6_ADDRSTRLEN + 8];
    static unsigned addrbuf_i = 0;
    char *buf = addrbuf[++addrbuf_i % 2];

    switch (addr->family) {
    case AF_INET6:
    case AF_INET:
        return str_addr_buf(buf, (struct sockaddr_storage*) addr);
    case AF_MAC:
        return format_mac(buf, &addr->mac.addr);
    default:
        return NULL;
    }
}

