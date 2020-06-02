
#ifndef _UTILS_H_
#define _UTILS_H_

// Number of elements in an array
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Size of a struct element
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

struct address {
	union {
		short ss_family;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	};
};

void hexDump(const char * desc, const void * addr, const int len);

void extract_mac_from_eui64(uint8_t *mac, const struct in6_addr *addr);
int interface_get_addr6(struct address *addr, const char *ifname);

int port_random(void);
int port_parse(const char pstr[], int err);
int port_set(struct address *addr, uint16_t port);

int bytes_random(void *buffer, size_t size);

const char *str_addr(const struct address *addr);

int addr_is_localhost(const struct address *addr);
int addr_is_multicast(const struct address *addr);
int addr_parse(struct address *addr, const char full_addr_str[], const char default_port[], int af);
int addr_port(const struct address *addr);
int addr_len(const struct address *addr);
int addr_equal(const struct address *addr1, const struct address *addr2);

int interface_set_mtu(int fd, const char *ifname, int mtu);
int interface_set_up(int fd, const char* ifname);
int interface_get_ifindex(int* ifindex, int fd, const char *ifname);
int interface_get_mac(uint8_t *mac, int fd, const char *ifname);
int tun_alloc(const char *dev);

int interface_is_up(int fd, const char *interface);

#endif // _UTILS_H_
