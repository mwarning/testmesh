
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


uint8_t highest_bit(uint64_t value)
{
    uint8_t pos = 0;
    while (value >>= 1) {
        ++pos;
    }
    return pos;
}

int decrease_ip_ttl(const void *data, size_t length)
{
    uint8_t *buf = (uint8_t*) data;

    if (buf && length > 0) {
        uint8_t ip_version = (buf[0] >> 4) & 0x0f;

        if (ip_version == 4 && length >= 20) {
            uint8_t ttl = buf[8];
            if (ttl > 0) {
                ttl -= 1;
            }
            buf[8] = ttl;
            return ttl;
        } else if (ip_version == 6 && length >= 44) {
            uint8_t hop_limit = buf[7];
            if (hop_limit > 0) {
                hop_limit -= 1;
            }
            buf[7] = hop_limit;
            return hop_limit;
        }
    }

    return -1;
}

char *bytes_to_base16(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize)
{
    static const char hexchars[16] = "0123456789abcdef";

    // + 1 for the '\0'
    if (dstsize != (2 * srcsize + 1)) {
        return NULL;
    }

    for (size_t i = 0; i < srcsize; ++i) {
        dst[2 * i] = hexchars[src[i] / 16];
        dst[2 * i + 1] = hexchars[src[i] % 16];
    }

    dst[2 * srcsize] = '\0';

    return dst;
}

bool addr_set_port(struct sockaddr *addr, uint16_t port)
{
    switch (addr->sa_family) {
    case AF_INET:
        ((struct sockaddr_in *)addr)->sin_port = htons(port);
        return true;
    case AF_INET6:
        ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
        return true;
    default:
        return false;
    }
}

uint16_t addr_port_get(const struct sockaddr *addr)
{
    switch (addr->sa_family) {
    case AF_INET:
        return ntohs(((const struct sockaddr_in *)addr)->sin_port);
    case AF_INET6:
        return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    default:
        return 0;
    }
}

socklen_t addr_length(const struct sockaddr *addr)
{
    switch (addr->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}

const char *str_af(int af) {
    switch (af) {
    case AF_INET:
        return "IPv4";
    case AF_INET6:
        return "IPv6";
    case AF_UNSPEC:
        return "IPv4+IPv6";
    case AF_MAC:
        return "MAC";
    default:
        return "<invalid>";
    }
}

static uint32_t min3(uint32_t a, uint32_t b, uint32_t c)
{
    if (a <= b && a <= c) {
        return a;
    } else if (b <= a && b <= c) {
        return b;
    } else {
        return c;
    }
}

int levenshtein(const uint8_t *s1, size_t s1len, const uint8_t *s2, size_t s2len)
{
    uint32_t lastdiag, olddiag;
    uint32_t column[s1len + 1];
    for (size_t y = 1; y <= s1len; ++y)
        column[y] = y;
    for (size_t x = 1; x <= s2len; ++x) {
        column[0] = x;
        for (size_t y = 1, lastdiag = x - 1; y <= s1len; ++y) {
            olddiag = column[y];
            column[y] = min3(column[y] + 1, column[y - 1] + 1, lastdiag + (s1[y-1] == s2[x - 1] ? 0 : 1));
            lastdiag = olddiag;
        }
    }
    return column[s1len];
}

bool is_newer_seqnum(uint16_t cur, uint16_t new)
{
    if (cur >= new) {
        return (cur - new) > 0x7fff;
    } else {
        return (new - cur) < 0x7fff;
    }
}

// Separate a string into a list of arguments (int argc, char **argv).
// Modifies args!
int setargs(const char **argv, int argv_size, char *args)
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

const option_t *find_option(const option_t options[], const char name[])
{
    const option_t *option = options;
    while (option->name && name) {
        if (0 == strcmp(name, option->name)) {
            return option;
        }
        option++;
    }

    return NULL;
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

bool hex_dump(char *dst, size_t dstlen, const void *buf, size_t buflen)
{
    const uint8_t *pc = (const uint8_t*) buf;
    size_t written = 0;
    uint8_t buff[17];
    size_t i;

    // Length checks.
    if (buflen == 0) {
        written += snprintf(&dst[written], dstlen - written, "  ZERO LENGTH\n");
        return true;
    }

    // Process every byte in the data.
    for (i = 0; i < buflen; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.
            if (i != 0) {
                written += snprintf(&dst[written], dstlen - written, "  %s\n", buff);
            }

            // Output the offset.
            written += snprintf(&dst[written], dstlen - written, "  %04lx ", i);
        }

        // Now the hex code for the specific character.
        written += snprintf(&dst[written], dstlen - written, " %02x", pc[i]);

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
        written += snprintf(&dst[written], dstlen - written, "   ");
        i++;
    }

    // And print the final ASCII buffer.
    written += snprintf(&dst[written], dstlen - written, "  %s\n", buff);

    return written == dstlen;
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
            // create hash
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
            // create hash
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

static const char *str_addr_storage_buf(char *addrbuf, const struct sockaddr *addr)
{
    char buf[INET6_ADDRSTRLEN];
    int port;

    switch (addr->sa_family) {
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

uint64_t time_millis_now()
{
    struct timespec now;
    // exact by probably < 10ms
    if (-1 == clock_gettime(CLOCK_MONOTONIC_COARSE, &now)) {
        log_error("clock_gettime() %s", strerror(errno));
        exit(1);
    }
    return now.tv_sec * 1000U + now.tv_nsec / 1000000U;
}

uint32_t time_millis_resolution()
{
	struct timespec res;
	if (-1 == clock_getres(CLOCK_MONOTONIC_COARSE, &res)) {
		log_error("clock_getres() %s", strerror(errno));
        exit(1);
	}
    if (res.tv_sec >= 1) {
        log_error("clock_getres() bad resolution");
        exit(1);
    }
	return res.tv_sec * 1000U + res.tv_nsec / 1000000U;
}

static const char *_str_time(uint64_t ms, bool is_negative)
{
    static char strdurationbuf[4][64];
    static size_t strdurationbuf_i = 0;
    char *buf = strdurationbuf[++strdurationbuf_i % 4];
    const char *prefix = is_negative ? "-" : "";

    size_t years, days, hours, minutes, seconds, milliseconds;

    years = ms / (365 * 24 * 60 * 60 * 1000ULL);
    ms -= years * (365 * 24 * 60 * 60 * 1000ULL);
    days = ms / (24 * 60 * 60 * 1000ULL);
    ms -= days * (24 * 60 * 60 * 1000ULL);
    hours = ms / (60 * 60 * 1000ULL);
    ms -= hours * (60 * 60 * 1000ULL);
    minutes = ms / (60 * 1000ULL);
    ms -= minutes * (60 * 1000ULL);
    seconds = ms / (1000ULL);
    ms -= seconds * (1000ULL);
    milliseconds = ms;

    if (years > 0) {
        snprintf(buf, 64, "%s%zuy%02zud", prefix, years, days);
    } else if (days > 0) {
        snprintf(buf, 64, "%s%zud%02zuh", prefix, days, hours);
    } else if (hours > 0) {
        snprintf(buf, 64, "%s%zuh%02zum", prefix, hours, minutes);
    } else if (minutes > 0) {
        snprintf(buf, 64, "%s%zum%02zus", prefix, minutes, seconds);
    } else if (seconds > 0) {
        snprintf(buf, 64, "%s%zus%03zums", prefix, seconds, milliseconds);
    } else {
        snprintf(buf, 64, "%s%03zums", prefix, milliseconds);
    }

    return buf;
}

const char *str_time(uint64_t ms)
{
    return _str_time(ms, false);
}

const char *str_duration(uint64_t from_ms, uint64_t to_ms)
{
    if (from_ms == 0 || to_ms == 0) {
        return "?";
    }

    if (from_ms <= to_ms) {
        return _str_time(to_ms - from_ms, false);
    } else {
        return _str_time(from_ms - to_ms, true);
    }
}

const char *str_since(uint64_t ms)
{
    return str_duration(ms, gstate.time_now);
}

const char *str_until(uint64_t ms)
{
    return str_duration(gstate.time_now, ms);
}

const char *str_bytes(uint64_t bytes)
{
    static char strbytesbuf[4][10];
    static size_t strbytesbuf_i = 0;
    char *buf = strbytesbuf[++strbytesbuf_i % 4];

    if (bytes < 1000) {
        snprintf(buf, 8, "%u B", (unsigned) bytes);
    } else if (bytes < 1000000) {
        snprintf(buf, 8, "%.1f KB", bytes / 1000.0);
    } else if (bytes < 1000000000) {
        snprintf(buf, 8, "%.1f MB", bytes / 1000000.0);
    } else if (bytes < 1000000000000) {
        snprintf(buf, 8, "%.1f GB", bytes / 1000000000.0);
    } else if (bytes < 1000000000000000) {
        snprintf(buf, 8, "%.1f TB", bytes / 1000000000000.0);
    } else if (bytes < 1000000000000000000) {
        snprintf(buf, 8, "%.1f PB", bytes / 1000000000000000.0);
    } else {
        snprintf(buf, 8, "%.1f EB", bytes / 1000000000000000000.0);
    }

    return buf;
}

bool addr_is_linklocal_ipv4(const struct in_addr *addr)
{
    return ((addr->s_addr & 0x0000ffff) == 0x0000fea9);
}

bool addr_is_linklocal_ipv6(const struct in6_addr *addr)
{
    return (addr->s6_addr[0] == 0xfe) && ((addr->s6_addr[1] & 0xC0) == 0x80);
}

const char *str_addr6(const struct sockaddr_in6 *addr)
{
    static char straddr6buf[4][INET6_ADDRSTRLEN + 8];
    static size_t straddr6buf_i = 0;
    char *buf = straddr6buf[++straddr6buf_i % 4];
    return str_addr_storage_buf(buf, (struct sockaddr*) addr);
}

const char *str_addr4(const struct sockaddr_in *addr)
{
    static char straddr4buf[4][INET_ADDRSTRLEN + 8];
    static size_t straddr4buf_i = 0;
    char *buf = straddr4buf[++straddr4buf_i % 4];
    return str_addr_storage_buf(buf, (struct sockaddr*) addr);
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

uint32_t addr_cmp_subnet(const struct sockaddr *addr1, const struct sockaddr *addr2, uint32_t subnet_len)
{
    const void *p1;
    const void* p2;

    if (addr1->sa_family != addr2->sa_family) {
        return 0;
    }

    switch (addr1->sa_family) {
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

bool addr_is_localhost(const struct sockaddr *addr)
{
    //return (memcmp(addr, &in6addr_loopback, 16) == 0);
    // 127.0.0.1
    const uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

    switch (addr->sa_family) {
    case AF_INET:
        return (memcmp(&((struct sockaddr_in *)addr)->sin_addr, &inaddr_loopback, 4) == 0);
    case AF_INET6:
        return (memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr, &in6addr_loopback, 16) == 0);
    default:
        return false;
    }
}

bool addr_is_multicast(const struct sockaddr *addr)
{
    switch (addr->sa_family) {
    case AF_INET:
        return IN_MULTICAST(ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr));
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6*) addr)->sin6_addr);
    default:
        return false;
    }
}

bool addr_is_linklocal(const struct sockaddr *addr)
{
    switch (addr->sa_family) {
    case AF_INET: {
        const struct in_addr *a = &((const struct sockaddr_in *) addr)->sin_addr;
        return addr_is_linklocal_ipv4(a);
    }
    case AF_INET6: {
        const struct in6_addr *a = &((const struct sockaddr_in6 *) addr)->sin6_addr;
        return addr_is_linklocal_ipv6(a);
    }
    default:
        return false;
    }
}

static int addr_parse_internal(struct sockaddr *ret, const char addr_str[], const char port_str[], uint32_t af)
{
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct addrinfo *p = NULL;
    bool rc = false;

    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = af;

    if (getaddrinfo(addr_str, port_str, &hints, &info) != 0) {
        return false;
    }

    p = info;
    while (p != NULL) {
        if ((af == AF_UNSPEC || af == AF_INET6) && p->ai_family == AF_INET6) {
            memcpy(ret, p->ai_addr, sizeof(struct sockaddr_in6));
            rc = true;
            break;
        }

        if ((af == AF_UNSPEC || af == AF_INET) && p->ai_family == AF_INET) {
            memcpy(ret, p->ai_addr, sizeof(struct sockaddr_in));
            rc = true;
            break;
        }
        p = p->ai_next;
    }

    freeaddrinfo(info);

    return rc;
}

bool parse_hex(uint64_t *ret, const char *val, int bytes)
{
    size_t len = strlen(val);
    if (len < 3 || len > (2 + 2 * bytes) || (len % 2) != 0 || val[0] != '0' || val[1] != 'x') {
       return false;
    }

    char *end = NULL;
    *ret = strtoul(val + 2, &end, 16);
    return (val + len) == end;
}

/*
bool parse_number(uint64_t *ret, const char *val, int bytes)
{
    char *end = NULL;
    *ret = strtoul(val, &end, 10);
    return (val + len) == end && ;
}
*/

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
bool addr_parse(struct sockaddr *addr_ret, const char full_addr_str[], const char default_port[], uint32_t af)
{
    char addr_buf[256];
    char *addr_beg;
    char *addr_tmp;
    char *last_colon;
    const char *addr_str = NULL;
    const char *port_str = NULL;

    size_t len = strlen(full_addr_str);
    if (len >= (sizeof(addr_buf) - 1)) {
        // address too long
        return false;
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
            return false;
        }

        *addr_tmp = '\0';
        addr_str = addr_beg + 1;

        if (*(addr_tmp + 1) == '\0') {
            port_str = default_port;
        } else if (*(addr_tmp + 1) == ':') {
            port_str = addr_tmp + 2;
        } else {
            // port expected
            return false;
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

// match a single string in argv
bool match(const char *argv[], const char *pattern)
{
    return argv[0] && !argv[1] && 0 == strcmp(argv[0], pattern);
}
