#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include "main.h"
#include "log.h"
#include "utils.h"


uint32_t adler32(const void *buf, size_t buflength) {
    const uint8_t *buffer = (const uint8_t*)buf;

    uint32_t s1 = 1;
    uint32_t s2 = 0;

    for (size_t n = 0; n < buflength; n++) {
        s1 = (s1 + buffer[n]) % 65521;
        s2 = (s2 + s1) % 65521;
    }     
    return (s2 << 16) | s1;
}

void hexDump(const char * desc, const void * addr, const int len)
{
    const unsigned char * pc = (const unsigned char *)addr;
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

void extract_mac_from_eui64(uint8_t *mac, const struct in6_addr *addr)
{
	// fe80::604f:4ff:fe33:af43
	mac[0] = addr->s6_addr[8];
	mac[1] = addr->s6_addr[9] ^ 2;
	mac[2] = addr->s6_addr[10];
	mac[3] = addr->s6_addr[13];
	mac[4] = addr->s6_addr[14];
	mac[5] = addr->s6_addr[15];
}

// Create a random port != 0
int port_random(void)
{
	uint16_t port;

	do {
		bytes_random(&port, sizeof(port));
	} while (port == 0);

	return port;
}

struct in6_ifreq {
    struct in6_addr addr;
    uint32_t        prefixlen;
    unsigned int    ifindex;
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

// Parse a port - treats 0 as valid port
int port_parse(const char pstr[], int err)
{
	int port;
	char c;

	if (pstr && sscanf(pstr, "%d%c", &port, &c) == 1 && port >= 0 && port <= 65535) {
		return port;
	} else {
		return err;
	}
}

int port_set6(struct sockaddr_in6 *addr, uint16_t port)
{
    return port_set((struct sockaddr_storage *) addr, port);
}

int port_set(struct sockaddr_storage *addr, uint16_t port)
{
	switch (addr->ss_family) {
	case AF_INET:
		((struct sockaddr_in *)addr)->sin_port = htons(port);
		return EXIT_SUCCESS;
	case AF_INET6:
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
		return EXIT_SUCCESS;
	default:
		return EXIT_FAILURE;
	}
}

// Fill buffer with random bytes
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

/*
const char *str_addr(const struct in6_addr *sin6_addr)
{
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, sin6_addr, buf, sizeof(buf));
    return buf;
}
*/
const char *str_addr6(const struct sockaddr_in6 *addr)
{
    return str_addr((struct sockaddr_storage*) addr);
}

const char *str_in6(const struct in6_addr *addr)
{
    static char addrbuf[INET6_ADDRSTRLEN];
    return inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf));
}

static const char *str_addr_buf(char *addrbuf, const struct sockaddr_storage *addr)
{
	//static char addrbuf[INET6_ADDRSTRLEN + 8];
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

const char *str_addr(const struct sockaddr_storage *addr)
{
    static char addrbuf[INET6_ADDRSTRLEN + 8][2];
    static unsigned addrbuf_i = 0;
    return str_addr_buf(addrbuf[addrbuf_i++ % 2], addr);
}

const char *str_ifindex(int ifindex)
{
    static char ifnamebuf[IF_NAMESIZE][2];
    static unsigned ifname_i = 0;
    return if_indextoname(ifindex, ifnamebuf[ifname_i++ % 2]);
}

int addr_is_localhost(const struct in6_addr *addr)
{
    return (memcmp(addr, &in6addr_loopback, 16) == 0);
    /*
	// 127.0.0.1
	const uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

	switch (addr->ss_family) {
	case AF_INET:
		return (memcmp(&((struct sockaddr_in *)addr)->sin_addr, &inaddr_loopback, 4) == 0);
	case AF_INET6:
		return (memcmp(&((struct sockaddr_in6 *)addr)->sin6_addr, &in6addr_loopback, 16) == 0);
	default:
		return 0;
	}*/
}

int addr_is_multicast(const struct in6_addr *addr)
{
    return IN6_IS_ADDR_MULTICAST(addr);
    /*
	switch (addr->ss_family) {
	case AF_INET:
		return IN_MULTICAST(ntohl(((struct sockaddr_in*) addr)->sin_addr.s_addr));
	case AF_INET6:
		return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6*) addr)->sin6_addr);
	default:
		return 0;
	}*/
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

int addr_equal66(const struct sockaddr_in6 *addr1, const struct sockaddr_in6 *addr2)
{
    return addr_equal66(addr1, addr2);
}

int addr_equal6(const struct in6_addr *addr1, const struct in6_addr *addr2)
{
    return memcmp(addr1, addr2, sizeof(struct in6_addr));
}

// configure interface
int interface_set_mtu(int fd, const char *ifname, int mtu)
{
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
    ifr.ifr_mtu = mtu;

    if (ioctl(fd, SIOCSIFMTU, &ifr) == -1) {
      log_error("ioctl(SIOCSIFMTU) %s", strerror(errno));
      return 1;
    }

    return 0;
}

int interface_get_ifindex(int* ifindex, int fd, const char *ifname)
{
    struct ifreq if_idx;

    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
        log_error("ioctl(SIOCGIFINDEX) %s", strerror(errno));
        return 1;
    }

    *ifindex = if_idx.ifr_ifindex;

    return 0;
}

int interface_get_mac(uint8_t *mac, int fd, const char *ifname)
{
    struct ifreq if_mac;

    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0) {
        log_error("ioctl(SIOCGIFHWADDR) %s", strerror(errno));
        return 1;
    }

    memcpy(mac, (uint8_t*) &if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}

int tun_alloc(const char *dev)
{
    const char *clonedev = "/dev/net/tun";
    struct ifreq ifr = {0};
    int fd;

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        log_error("open %s: %s", clonedev, strerror(errno));
        return -1;
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strcpy(ifr.ifr_name, dev);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        log_error("ioctl(TUNSETIFF) %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (0 != strcmp(ifr.ifr_name, dev)) {
        return -1;
    }

    return fd;
}

int interface_get_addr6(struct in6_addr *addr, const char *ifname)
{
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
       if (ifa->ifa_addr == NULL) {
           continue;
       }

       if (ifa->ifa_addr->sa_family != AF_INET6) {
           continue;
       }

       if (strcmp(ifa->ifa_name, ifname) != 0) {
           continue;
       }

       //memcpy(addr, ifa->ifa_addr, sizeof(struct sockaddr_in6));
       memcpy(addr, &((struct sockaddr_in6*) ifa->ifa_addr)->sin6_addr, sizeof(struct in6_addr));
       //char buf[100];
       //printf("%s: %s\n", ifa->ifa_name, inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, buf, sizeof(buf)));
       freeifaddrs(ifaddr);
       return 0;
    }

    freeifaddrs(ifaddr);
    return -1;
}

int interface_set_up(int fd, const char* ifname) {
    struct ifreq ifr = {0};
    int oldflags;

    strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        log_error("ioctl(SIOCGIFFLAGS) for %s: %s", ifname, strerror(errno));
        return -1;
    }

    oldflags = ifr.ifr_flags;
    ifr.ifr_flags |= IFF_UP;

    if (oldflags == ifr.ifr_flags) {
        // interface is already up/down
        return 0;
    }

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        log_error("ioctl(SIOCSIFFLAGS) for %s: %s", ifname, strerror(errno));
        return -1;
    }

    return 0;
}

int interface_is_up(int fd, const char *ifname)
{
    struct ifreq ifr = {0};

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		log_error("SIOCGIFFLAGS for %s: %s", ifname, strerror(errno));
		return 0;
    }

    return !!(ifr.ifr_flags & IFF_UP);
}

int _ip_cmd(const char *cmd, const char *ifname, const struct in6_addr *addr)
{
    char addr_str[INET6_ADDRSTRLEN];
    char command[INET6_ADDRSTRLEN + 64];
    int prefixlen = 16;

    inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));

    sprintf(command, "ip a %s %s/%u dev %s", cmd, addr_str, prefixlen, ifname);
    //log_debug("command: %s", command);
    return system(command);
}

int addr_set(const char *ifname, const struct in6_addr *addr)
{
    return _ip_cmd("add", ifname, addr);
}

int addr_del(const char *ifname, const struct in6_addr *addr)
{
    return _ip_cmd("del", ifname, addr);
}

int addr_flush(const char *ifname)
{
    char command[64];

    sprintf(command, "ip a flush dev %s", ifname);
    return system(command);
}

static const uint8_t zeroes[20] = {0};
static const uint8_t v4prefix[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

int is_martian(const struct sockaddr *sa)
{
    switch(sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in*) sa;
        const uint8_t *addr = (const uint8_t*) &sin->sin_addr;
        return sin->sin_port == 0 ||
            (addr[0] == 0) ||
            (addr[0] == 127) ||
            ((addr[0] & 0xE0) == 0xE0);
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*) sa;
        const uint8_t *addr = (const uint8_t*) &sin6->sin6_addr;
        return sin6->sin6_port == 0 ||
            (addr[0] == 0xFF) ||
            (addr[0] == 0xFE && (addr[1] & 0xC0) == 0x80) ||
            (memcmp(addr, zeroes, 15) == 0 &&
             (addr[15] == 0 || addr[15] == 1)) ||
            (memcmp(addr, v4prefix, 12) == 0);
    }

    default:
        return 0;
    }
}

static void reverse_bytes(uint8_t *data, int len)
{
    for (int i = 0; i < (len / 2); i++) {
        uint8_t tmp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = tmp;
    }
}

int is_eui64_sockaddr(struct sockaddr *addr)
{
    if (addr->sa_family != AF_INET6) {
        return 0;
    }

    uint8_t *b = ((struct sockaddr_in6 *) addr)->sin6_addr.s6_addr;
    return (b[0] == 0xfe) && (b[1] == 0x80) && (b[11] == 0xff) && (b[12] == 0xfe);
}

int is_eui64(const struct in6_addr *addr)
{
    return (addr->s6_addr[11] == 0xff && addr->s6_addr[12] == 0xFE);
}

void id_get4(uint32_t *id, const struct in_addr *addr)
{
    const uint8_t* s = (const uint8_t*) &addr->s_addr;
    uint8_t* d = (uint8_t*) id;

    d[3] = s[0];
    d[2] = s[1];
    d[1] = s[2];
    d[0] = s[3];
}

void id_set4(struct in_addr *addr, const uint32_t *id)
{
    const uint8_t* s = (const uint8_t*) id;
    uint8_t* d = (uint8_t*) &addr->s_addr;

    d[3] = s[0];
    d[2] = s[1];
    d[1] = s[2];
    d[0] = s[3];
}

void id_get6(uint32_t *id, const struct in6_addr *addr)
{
    const uint8_t* s = (const uint8_t*) &addr->s6_addr;
    uint8_t* d = (uint8_t*) id;

    // hm, not consisten with id_set6
    /*if (is_eui64(addr)) {
        d[3] = s[10];
        d[2] = s[13];
        d[1] = s[14];
        d[0] = s[15];
    } else {*/
        d[3] = s[12];
        d[2] = s[13];
        d[1] = s[14];
        d[0] = s[15];
    //}
    //memcpy(id, &addr->s6_addr[16 - sizeof(*id)], sizeof(*id));
    //reverse_bytes((uint8_t*) id, sizeof(*id));
}

void id_set6(struct in6_addr *addr, const uint32_t *id)
{
    memcpy(&addr->s6_addr[16 - sizeof(*id)], id, sizeof(*id));
    reverse_bytes((uint8_t*) &addr->s6_addr[16 - sizeof(*id)], sizeof(*id));
}

char *format_duration(char buf[64], time_t from, time_t to)
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

char *format_size(char buf[64], unsigned bytes)
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
