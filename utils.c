
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

#include "main.h"
#include "log.h"
#include "utils.h"


void hexDump(const char * desc, const void * addr, const int len) {
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
	//fe80::604f:4ff:fe33:af43
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

int port_set(struct address *addr, uint16_t port)
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

const char *str_addr(const struct address *addr)
{
	static char addrbuf[INET6_ADDRSTRLEN + 8];
	char buf[INET6_ADDRSTRLEN];
	const char *fmt;
	int port;

	switch (addr->ss_family) {
	case AF_INET6:
		port = ((struct sockaddr_in6 *)addr)->sin6_port;
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buf, sizeof(buf));
		fmt = "[%s]:%d";
		break;
	case AF_INET:
		port = ((struct sockaddr_in *)addr)->sin_port;
		inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, buf, sizeof(buf));
		fmt = "%s:%d";
		break;
	default:
		return "<invalid address>";
	}

	sprintf(addrbuf, fmt, buf, ntohs(port));

	return addrbuf;
}

int addr_is_localhost(const struct address *addr)
{
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

int addr_is_multicast(const struct address *addr)
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

int addr_port(const struct address *addr)
{
	switch (addr->ss_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)addr)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
	default:
		return 0;
	}
}

int addr_len(const struct address *addr)
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

static int addr_parse_internal(struct address *ret, const char addr_str[], const char port_str[], int af)
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
int addr_parse(struct address *addr_ret, const char full_addr_str[], const char default_port[], int af)
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

// Compare two ip addresses, ignore port
int addr_equal(const struct address *addr1, const struct address *addr2)
{
	if (addr1->ss_family != addr2->ss_family) {
		return 0;
	} else if (addr1->ss_family == AF_INET) {
		return 0 == memcmp(&((struct sockaddr_in *)addr1)->sin_addr, &((struct sockaddr_in *)addr2)->sin_addr, 4);
	} else if (addr1->ss_family == AF_INET6) {
		return 0 == memcmp(&((struct sockaddr_in6 *)addr1)->sin6_addr, &((struct sockaddr_in6 *)addr2)->sin6_addr, 16);
	} else {
		return 0;
	}
}

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

int interface_get_addr6(struct address *addr, const char *ifname)
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

       memcpy(addr, (struct sockaddr_in6 *)ifa->ifa_addr, sizeof(struct sockaddr_in6));
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
